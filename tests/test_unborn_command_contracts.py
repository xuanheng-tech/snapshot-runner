from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import snapshot_runner
from snapshot_runner import artifact, collect, git, security
from snapshot_runner import cli as runner

GIT = "/usr/bin/git"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SUBCOMMANDS = ("repo-status", "diff-audit", "branch-review", "test-triage")
# 2.0.0 removed the provider-named aliases and their entrypoint functions.
REMOVED_ALIAS_ENTRYPOINTS = (
    "repo_status_main",
    "diff_audit_main",
    "branch_review_main",
    "test_triage_main",
    "_public_command_main",
)


def _run_git(
    repo: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments],
        cwd="/",
        input=input_bytes,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result


def _initialize_unborn(repo: Path) -> None:
    repo.mkdir()
    _run_git(repo, "init", "--quiet", "--initial-branch=main")


def _private_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


def _prepare(
    repo: Path,
    task: str,
    task_argument: str | None = None,
) -> artifact.SnapshotArtifact:
    target_path, target_name, runner_path = runner._validate_target_repository_path(os.fspath(repo))
    target = git._validate_target_repository_context(
        target_path,
        target_name,
        runner_path,
        artifact._state_home(target_path),
        GIT,
        task,
    )
    return runner._prepare_snapshot(task, task_argument, target, GIT)


def _git_manifest(repo: Path) -> tuple[tuple[str, str, int, str], ...]:
    git_dir = Path(
        _run_git(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir")
        .stdout.decode("utf-8", errors="strict")
        .strip()
    )
    entries: list[tuple[str, str, int, str]] = []
    for path in sorted(git_dir.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(git_dir).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            entries.append((relative, "directory", mode, ""))
        elif stat.S_ISREG(metadata.st_mode):
            entries.append(
                (relative, "regular", mode, hashlib.sha256(path.read_bytes()).hexdigest())
            )
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            entries.append((relative, "symlink", mode, hashlib.sha256(target).hexdigest()))
    return tuple(entries)


def _readonly_state(repo: Path) -> tuple[bytes, tuple[tuple[str, str, int, str], ...]]:
    status = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout
    return status, _git_manifest(repo)


def _payload(result: artifact.SnapshotArtifact) -> dict[str, object]:
    return json.loads(result.snapshot_bytes)


def test_unborn_branch_review_uses_frozen_error_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "unborn-branch"
    _initialize_unborn(repo)
    state = _private_state(monkeypatch, tmp_path)

    def unexpected_collection(*_args: object, **_kwargs: object) -> collect.Snapshot:
        raise AssertionError("unborn branch-review entered commit-range collection")

    monkeypatch.setattr(collect, "collect_branch_review", unexpected_collection)
    before = _readonly_state(repo)

    result = runner.main(["prepare", "branch-review", "--repo", os.fspath(repo), "comparison-base"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: SNAPSHOT_COLLECTION_FAILED: {runner.BRANCH_REVIEW_UNBORN_ERROR}\n"
    )
    assert not (state / "snapshot-runner").exists()
    assert _readonly_state(repo) == before


def test_unborn_commands_combine_empty_tree_and_extensionless_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "unborn-combined"
    _initialize_unborn(repo)
    _private_state(monkeypatch, tmp_path)
    launcher = repo / "launcher"
    launcher.write_text("index version\n", encoding="utf-8")
    launcher.chmod(0o755)
    _run_git(repo, "add", "--", "launcher")
    launcher.write_text("worktree version\n", encoding="utf-8")
    launcher.chmod(0o644)
    (repo / "NOTES").write_text("untracked UTF-8 说明\n", encoding="utf-8")
    (repo / "binary").write_bytes(b"synthetic\0binary\n")
    before = _readonly_state(repo)

    status = _payload(_prepare(repo, "repo-status"))
    first = _prepare(repo, "diff-audit")
    second = _prepare(repo, "diff-audit")
    payload = _payload(first)
    data = payload["data"]
    assert isinstance(data, dict)
    expected_empty_tree = (
        _run_git(
            repo,
            "hash-object",
            "-t",
            "tree",
            "--stdin",
            "--no-filters",
            input_bytes=b"",
        )
        .stdout.decode("ascii", errors="strict")
        .strip()
    )

    assert status["data"]["head"] == "unborn"  # type: ignore[index]
    assert status["data"]["current_branch"] == "main"  # type: ignore[index]
    assert data["baseline_kind"] == "empty_tree"
    assert data["baseline_oid"] == expected_empty_tree
    contexts = {
        (context["path"], context.get("source")): context for context in data["file_context"]
    }
    assert contexts[("launcher", "index")]["content"] == "index version\n"
    assert contexts[("launcher", "index")]["executable"] is True
    assert contexts[("launcher", "worktree")]["content"] == "worktree version\n"
    assert contexts[("launcher", "worktree")]["executable"] is False
    assert contexts[("NOTES", "untracked")]["content"] == "untracked UTF-8 说明\n"
    assert contexts[("NOTES", "untracked")]["executable"] is False
    assert all(context["path"] != "binary" for context in data["file_context"])
    assert any(
        gap["kind"] == "file_refused" and gap["subject"] == "binary"
        for gap in payload["evidence_gaps"]
    )
    assert "index version" in data["staged_diff"]
    assert "worktree version" not in data["staged_diff"]
    assert "worktree version" in data["unstaged_diff"]
    assert first.snapshot_bytes == second.snapshot_bytes
    assert hashlib.sha256(first.snapshot_bytes).hexdigest() == first.snapshot_id
    assert len(first.snapshot_bytes) <= collect.MAX_SNAPSHOT_BYTES
    assert stat.S_IMODE(first.directory.lstat().st_mode) == 0o700
    for name in artifact.SNAPSHOT_FILE_NAMES:
        assert stat.S_IMODE((first.directory / name).lstat().st_mode) == 0o600
    assert _readonly_state(repo) == before


def test_unborn_test_triage_is_deterministic_and_does_not_require_head(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "unborn-triage"
    _initialize_unborn(repo)
    _private_state(monkeypatch, tmp_path)
    (repo / "test.log").write_text("2 passed\n", encoding="utf-8")
    before = _readonly_state(repo)

    first = _prepare(repo, "test-triage", "test.log")
    second = _prepare(repo, "test-triage", "test.log")
    payload = _payload(first)

    assert payload["data"] == {"log": "2 passed\n", "log_display_name": "test-output.log"}
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    assert first.snapshot_bytes == second.snapshot_bytes
    assert first.snapshot_id == second.snapshot_id
    assert hashlib.sha256(first.snapshot_bytes).hexdigest() == first.snapshot_id
    assert _readonly_state(repo) == before


def test_installed_runner_boundary_keeps_target_validation_and_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "installed-runner-target"
    installed_root = tmp_path / "installed-site-packages"
    _initialize_unborn(repo)
    installed_root.mkdir()
    _private_state(monkeypatch, tmp_path)
    target = git._validate_target_repository_context(
        repo,
        repo.name,
        installed_root,
        artifact._state_home(repo),
        GIT,
        "repo-status",
        allow_installed_runner=True,
    )

    result = runner._prepare_snapshot("repo-status", None, target, GIT)
    payload = _payload(result)

    assert target.runner_root == installed_root
    assert target.runner_identity is None
    assert target.shared_common_dir is False
    assert payload["data"]["head"] == "unborn"  # type: ignore[index]
    assert payload["evidence_gaps"] == []


@pytest.mark.parametrize("case", ["missing", "binary", "symlink", "outside"])
def test_unborn_test_triage_preserves_log_refusals(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
) -> None:
    repo = tmp_path / f"unborn-triage-{case}"
    _initialize_unborn(repo)
    state = _private_state(monkeypatch, tmp_path)
    argument = "missing.log"
    if case == "binary":
        argument = "binary.log"
        (repo / argument).write_bytes(b"synthetic\0binary\n")
    elif case == "symlink":
        outside = tmp_path / "outside.log"
        outside.write_text("outside\n", encoding="utf-8")
        argument = "linked.log"
        (repo / argument).symlink_to(outside)
    elif case == "outside":
        (tmp_path / "outside.log").write_text("outside\n", encoding="utf-8")
        argument = "../outside.log"
    before = _readonly_state(repo)

    with pytest.raises(security.RunnerError, match="test log refused"):
        _prepare(repo, "test-triage", argument)

    assert not (state / "snapshot-runner").exists()
    assert _readonly_state(repo) == before


@pytest.mark.parametrize("kind", ["bare", "non-git"])
@pytest.mark.parametrize(
    ("task", "task_argument"),
    [
        ("repo-status", None),
        ("diff-audit", None),
        ("branch-review", "main"),
        ("test-triage", "test.log"),
    ],
)
def test_all_public_commands_reject_invalid_repository_kinds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
    task: str,
    task_argument: str | None,
) -> None:
    repo = tmp_path / kind
    repo.mkdir()
    if kind == "bare":
        _run_git(repo, "init", "--bare", "--quiet")
    state = _private_state(monkeypatch, tmp_path)
    arguments = ["prepare", task, "--repo", os.fspath(repo)]
    if task_argument is not None:
        arguments.append(task_argument)

    result = runner.main(arguments)

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "workflow_failed: REPOSITORY_VALIDATION_FAILED: target repository validation failed\n"
    )
    assert not (state / "snapshot-runner").exists()


def test_release_version_and_console_script_metadata_are_consistent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert snapshot_runner.__version__ == "2.0.0"
    assert metadata["project"]["version"] == snapshot_runner.__version__
    # The single public console script is the provider-neutral primary command.
    assert metadata["project"]["scripts"] == {
        "snapshot-runner": "snapshot_runner.cli:snapshot_runner_main"
    }
    assert metadata["tool"]["uv"]["build-backend"]["module-name"] == "snapshot_runner"
    assert metadata["build-system"]["build-backend"] == "uv_build"
    assert runner.main(["--version"]) == 0
    assert capsys.readouterr().out == "snapshot-runner 2.0.0\n"
    assert runner.main(["--version"], neutral=True) == 0
    assert capsys.readouterr().out == "snapshot-runner 2.0.0\n"

    for task in PUBLIC_SUBCOMMANDS:
        with pytest.raises(SystemExit) as exit_info:
            runner.main([task, "--version"], neutral=True)
        assert exit_info.value.code == 0
        assert capsys.readouterr().out == "snapshot-runner 2.0.0\n"


def test_provider_named_alias_entrypoints_are_gone() -> None:
    """2.0.0 removed the four codex-* console scripts and their entrypoint functions."""
    for name in REMOVED_ALIAS_ENTRYPOINTS:
        assert not hasattr(runner, name), name
    source = (PROJECT_ROOT / "snapshot_runner" / "cli.py").read_text(encoding="utf-8")
    assert "codex" not in source.lower()


@pytest.mark.parametrize("task", PUBLIC_SUBCOMMANDS)
def test_primary_command_routes_each_subcommand(
    monkeypatch: pytest.MonkeyPatch,
    task: str,
) -> None:
    observed: list[str] | None = None

    def shared_main(arguments: list[str] | None = None, *, neutral: bool = False) -> int:
        nonlocal observed, captured_neutral
        observed = arguments
        captured_neutral = neutral
        return 17

    captured_neutral = False
    monkeypatch.setattr(runner, "main", shared_main)
    monkeypatch.setattr(sys, "argv", ["snapshot-runner", task, "--repo", "/synthetic/repo"])

    assert runner.snapshot_runner_main() == 17
    assert observed is None
    assert captured_neutral is True
