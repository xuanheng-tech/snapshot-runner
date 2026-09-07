from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import math
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESOLVED_TEST_PATHS = tuple(Path(raw or ".").resolve() for raw in sys.path)

import pytest  # noqa: E402 - isolation assertions must precede non-stdlib imports.

import codex_snapshot_runner as runner_namespace  # noqa: E402
from codex_snapshot_runner import (  # noqa: E402
    artifact as artifact_module,
)
from codex_snapshot_runner import (  # noqa: E402
    cli as runner,
)
from codex_snapshot_runner import (  # noqa: E402
    collect,
    git,
    security,
)


def _resolved_module_locations(module: object) -> tuple[Path, ...]:
    locations: list[Path] = []
    module_file = getattr(module, "__file__", None)
    if module_file is not None:
        locations.append(Path(module_file).resolve())
    namespace_path = getattr(module, "__path__", None)
    if namespace_path is not None:
        locations.extend(Path(raw).resolve() for raw in namespace_path)
    return tuple(dict.fromkeys(locations))


RUNNER_MODULES = (
    runner_namespace,
    artifact_module,
    runner,
    collect,
    git,
    security,
)
RUNNER_MODULE_LOCATIONS = {
    module.__name__: _resolved_module_locations(module) for module in RUNNER_MODULES
}
assert all(RUNNER_MODULE_LOCATIONS.values())
assert all(
    location.is_relative_to(PROJECT_ROOT)
    for locations in RUNNER_MODULE_LOCATIONS.values()
    for location in locations
)


def _synthetic_pem_boundary(kind: str) -> str:
    return "-" * 5 + kind + " PRIVATE KEY" + "-" * 5


def _synthetic_text(*parts: str) -> str:
    return "".join(parts)


def _safe_snapshot(
    task: str = "repo-status",
    repository: str = PROJECT_ROOT.name,
) -> collect.Snapshot:
    data: dict[str, object]
    if task == "repo-status":
        data = {
            "current_branch": "feature/snapshot",
            "head": "a" * 40,
            "upstream": "not configured",
            "ahead_behind": "not available",
            "status_short": " M safe.py\n",
            "recent_commits": "abc1234 safe commit\n",
            "local_branches": "feature/snapshot\tabc1234\n",
        }
    elif task == "diff-audit":
        data = {
            "status_short": " M safe.py\n",
            "staged_diff": "",
            "unstaged_diff": "",
            "file_context": [{"path": "safe.py", "content": "value = 1\n"}],
        }
    elif task == "branch-review":
        data = {
            "base": "refs/heads/main",
            "base_commit": "b" * 40,
            "target_ref": "refs/heads/feature/snapshot",
            "target_head": "c" * 40,
            "merge_base_commit": "b" * 40,
            "range_semantics": git.BRANCH_REVIEW_RANGE_SEMANTICS,
            "commits": "abc1234 safe commit\n",
            "diff": "",
            "deleted_files": [],
            "file_context": [{"path": "safe.py", "content": "value = 1\n"}],
        }
    else:
        data = {"log": "1 passed\n", "log_display_name": "test-output.log"}
    manifest = artifact_module._snapshot_data_scan_manifest({"task": task, "data": data})
    seal = (
        git.BranchReviewSeal(
            "refs/heads/main",
            "b" * 40,
            "refs/heads/feature/snapshot",
            "c" * 40,
            "b" * 40,
        )
        if task == "branch-review"
        else None
    )
    return collect.Snapshot(task, repository, data, manifest, branch_review_seal=seal)


def _snapshot_with_file_context(raw: str, relative_path: str) -> collect.Snapshot:
    data: dict[str, object] = {
        "status_short": " M synthetic\n",
        "staged_diff": "",
        "unstaged_diff": "",
        "file_context": [{"path": relative_path, "content": raw}],
    }
    manifest = artifact_module._snapshot_data_scan_manifest({"task": "diff-audit", "data": data})
    return collect.Snapshot("diff-audit", PROJECT_ROOT.name, data, manifest)


def _legacy_snapshot_with_yaml_context(raw: str, relative_path: str) -> collect.Snapshot:
    data: dict[str, object] = {
        "status_short": " M synthetic\n",
        "staged_diff": "",
        "unstaged_diff": "",
        "file_context": [{"path": relative_path, "content": raw}],
    }
    bindings = {
        ("status_short",): security.ScanMode.PLAIN_TEXT,
        ("staged_diff",): security.ScanMode.UNIFIED_DIFF,
        ("unstaged_diff",): security.ScanMode.UNIFIED_DIFF,
        ("file_context", 0, "path"): security.ScanMode.PLAIN_TEXT,
        ("file_context", 0, "content"): security.ScanMode.PLAIN_TEXT,
    }
    manifest = security.ScanModeManifest(
        security.SCAN_CLASSIFIER_VERSION,
        tuple(
            security.ScanModeBinding(path, mode)
            for path, mode in sorted(bindings.items(), key=lambda item: repr(item[0]))
        ),
    )
    return collect.Snapshot("diff-audit", PROJECT_ROOT.name, data, manifest)


def _snapshot_with_diff(raw: str) -> collect.Snapshot:
    data: dict[str, object] = {
        "status_short": " M synthetic\n",
        "staged_diff": raw,
        "unstaged_diff": "",
        "file_context": [],
    }
    manifest = artifact_module._snapshot_data_scan_manifest({"task": "diff-audit", "data": data})
    return collect.Snapshot("diff-audit", PROJECT_ROOT.name, data, manifest)


@pytest.fixture
def private_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


def _validated_test_repository(repo: Path) -> git.ValidatedTargetRepository:
    target_path, target_name, runner_path = runner._validate_target_repository_path(os.fspath(repo))
    return git._validate_target_repository_context(
        target_path,
        target_name,
        runner_path,
        artifact_module._state_home(target_path),
        "/usr/bin/git",
        "diff-audit",
    )


@pytest.fixture
def target_repository(private_state: Path) -> git.ValidatedTargetRepository:
    repo = private_state.parent / PROJECT_ROOT.name
    repo.mkdir()
    result = subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(repo), "init", "--quiet"],
        cwd="/",
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    (repo / "safe.py").write_text("value = 1\n", encoding="utf-8")
    for arguments in (
        ("add", "safe.py"),
        (
            "-c",
            "user.name=Codex Test",
            "-c",
            "user.email=codex-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "baseline",
        ),
    ):
        result = subprocess.run(
            ["/usr/bin/git", "-C", os.fspath(repo), *arguments],
            cwd="/",
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    return _validated_test_repository(repo)


@pytest.fixture
def prepared_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> artifact_module.SnapshotArtifact:
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())
    return runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")


def test_python_environment_and_project_modules_are_isolated() -> None:
    assert platform.python_version() == "3.12.13"
    assert PROJECT_ROOT in RESOLVED_TEST_PATHS
    assert all(RUNNER_MODULE_LOCATIONS.values())
    assert all(
        location.is_relative_to(PROJECT_ROOT)
        for locations in RUNNER_MODULE_LOCATIONS.values()
        for location in locations
    )


def test_public_just_interfaces_expose_all_prepares_and_disabled_analyze() -> None:
    justfile = (PROJECT_ROOT / "justfile").read_text(encoding="utf-8")
    mappings = {
        "codex-repo-status": "prepare repo-status",
        "codex-diff-audit": "prepare diff-audit",
        "codex-branch-review": "prepare branch-review",
        "codex-test-triage": "prepare test-triage",
    }
    for recipe, invocation in mappings.items():
        assert f"{recipe} *args:" in justfile
        assert invocation in justfile
    assert "codex-analyze-snapshot *args:" in justfile
    assert 'analyze "$@"' in justfile
    assert "{{snapshot_id}}" not in justfile

    just = shutil.which("just")
    assert just is not None
    result = subprocess.run(
        [just, "--list"],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    help_text = " ".join(result.stdout.split()).lower()
    assert "prepare-only fixed fail-closed sentinel" in help_text
    for stale_description in (
        "approve and analyze",
        "explicitly approve",
        "approve one reviewed snapshot",
    ):
        assert stale_description not in help_text


def test_prepare_resolves_only_git_and_prints_manual_workflow(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    capsys: pytest.CaptureFixture[str],
) -> None:
    resolved: list[str] = []

    def find(name: str) -> str:
        resolved.append(name)
        if name != "git":
            raise AssertionError("prepare attempted to resolve an unsupported executable")
        return "/usr/bin/git"

    monkeypatch.setattr(git, "_find_executable", find)
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())
    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repository.path)])
    output = capsys.readouterr().out
    assert result == 0
    assert resolved == ["git"]
    assert "preview:" in output
    assert "manual_workflow:" in output
    assert "manually upload preview.txt or snapshot.json to ChatGPT" in output
    assert "just codex-analyze-snapshot" not in output
    assert "Human review of preview.txt is required" in output


@pytest.mark.parametrize(
    "argv",
    [
        ["analyze"],
        ["analyze", "a" * 64],
        ["analyze", "../hostile-snapshot"],
        ["analyze", "a" * 64, "unexpected"],
        ["analyze", "--help"],
    ],
    ids=("missing", "valid", "hostile", "extra", "help"),
)
def test_prepare_only_analyze_refuses_before_prepare_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> None:
    calls: list[str] = []

    def fail(label: str) -> object:
        def unexpected(*_args: object, **_kwargs: object) -> object:
            calls.append(label)
            raise AssertionError(f"analyze crossed the {label} boundary")

        return unexpected

    for module, name in (
        (runner, "build_argument_parser"),
        (artifact_module, "_state_home"),
        (artifact_module, "_load_snapshot"),
        (git, "_find_executable"),
        (runner, "_prepare_snapshot"),
    ):
        monkeypatch.setattr(module, name, fail(name))
    monkeypatch.setattr(runner.os, "umask", fail("umask"))

    home = tmp_path / "home-must-not-be-read"
    codex_home = tmp_path / "codex-home-must-not-be-read"
    state = tmp_path / "state-must-not-be-read"
    monkeypatch.setenv("HOME", os.fspath(home))
    monkeypatch.setenv("CODEX_HOME", os.fspath(codex_home))
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    assert runner.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {runner.AUTOMATIC_ANALYSIS_DISABLED}: {runner.ANALYZE_DISABLED_ERROR}\n"
    )
    assert calls == []
    assert not home.exists()
    assert not codex_home.exists()
    assert not state.exists()


def test_automatic_analysis_production_implementation_is_absent() -> None:
    source = (PROJECT_ROOT / "codex_snapshot_runner/cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    definitions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    removed_symbols = {
        "_check_login",
        "_create_analysis_staging",
        "_run_analysis",
        "_run_model",
        "AppServerSession",
        "ModelResult",
        "SystemdController",
        "isolated_codex_home",
        "state_output_root",
        "validate_preflight",
    }
    assert definitions.isdisjoint(removed_symbols)
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imported_roots.isdisjoint(
        {"http", "pwd", "queue", "select", "selectors", "socket", "threading"}
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["prepare", "repo-status"],
        ["prepare", "diff-audit"],
        ["prepare", "branch-review", "main"],
        ["prepare", "test-triage", "safe.log"],
    ],
)
def test_every_prepare_requires_explicit_repo_before_executable_resolution(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> None:
    monkeypatch.setattr(
        git,
        "_find_executable",
        lambda _name: pytest.fail("prepare resolved Git before rejecting missing --repo"),
    )
    assert runner.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {runner.ARGUMENT_ERROR}: {runner.TARGET_REPOSITORY_REQUIRED_ERROR}\n"
    )


def test_snapshot_directory_must_be_inside_validated_store_before_meta_read(
    tmp_path: Path,
    private_state: Path,
) -> None:
    controlled = private_state / "codex-exec"
    store = controlled / "snapshots"
    for path in (controlled, store):
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    outside = tmp_path / ("c" * 64)
    outside.mkdir(mode=0o700)
    outside.chmod(0o700)
    with pytest.raises(runner.RunnerError, match="outside the validated snapshot store"):
        artifact_module._load_snapshot_directory("c" * 64, outside)


def test_current_meta_epoch_does_not_bypass_noncurrent_snapshot_envelope(
    private_state: Path,
) -> None:
    envelope = _safe_snapshot().as_envelope()
    envelope["producer_security_epoch"] = collect.PRODUCER_SECURITY_EPOCH - 1
    snapshot_bytes = (
        json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
    )
    snapshot_id = hashlib.sha256(snapshot_bytes).hexdigest()
    preview = b"legacy preview\n"
    meta = artifact_module._snapshot_meta(
        snapshot_id,
        "repo-status",
        PROJECT_ROOT.name,
        snapshot_bytes,
        preview,
    )
    meta_bytes = artifact_module._serialize_snapshot_meta(meta)
    controlled = private_state / "codex-exec"
    store = controlled / "snapshots"
    directory = store / snapshot_id
    for path in (controlled, store, directory):
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
    for name, payload in {
        "meta.json": meta_bytes,
        "snapshot.json": snapshot_bytes,
        "preview.txt": preview,
    }.items():
        path = directory / name
        path.write_bytes(payload)
        path.chmod(0o600)
    with pytest.raises(runner.RunnerError, match="snapshot envelope schema is invalid"):
        artifact_module._load_snapshot(snapshot_id)


CLI_MARKER = "SYNTHETIC_CLI_MARKER"


@pytest.mark.parametrize(
    ("argv", "expected_code", "expected_error"),
    [
        (["prepare", CLI_MARKER], runner.ARGUMENT_ERROR, runner.CLI_ARGUMENT_ERROR),
        (
            ["analyze", "a" * 64, "--timeout-seconds", CLI_MARKER],
            runner.AUTOMATIC_ANALYSIS_DISABLED,
            runner.ANALYZE_DISABLED_ERROR,
        ),
        (
            ["prepare", "repo-status", f"--{CLI_MARKER}"],
            runner.ARGUMENT_ERROR,
            runner.CLI_ARGUMENT_ERROR,
        ),
        (["analyze"], runner.AUTOMATIC_ANALYSIS_DISABLED, runner.ANALYZE_DISABLED_ERROR),
        (
            ["prepare", "branch-review", "--repo", "/synthetic/repo"],
            runner.ARGUMENT_ERROR,
            runner.CLI_ARGUMENT_ERROR,
        ),
    ],
    ids=("choice", "type", "unknown", "missing-positional", "missing-task-argument"),
)
def test_cli_argument_errors_are_fixed_and_never_echo_input(
    argv: list[str],
    expected_code: str,
    expected_error: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert runner.main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"workflow_failed: {expected_code}: {expected_error}\n"
    assert CLI_MARKER not in captured.err


def test_cli_help_describes_prepare_only_fail_closed_analyze() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "codex_snapshot_runner.cli", "--help"],
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""
    help_text = " ".join(result.stdout.split()).lower()
    assert "prepare" in help_text
    assert "analyze" in help_text
    assert "prepare-only mode does not support automatic analyze" in help_text
    assert "fixed fail-closed sentinel" in help_text
    assert "review preview.txt" in help_text
    assert "manually upload preview.txt or snapshot.json" in help_text
    for stale_description in (
        "approve and analyze",
        "explicitly approve",
        "approve one reviewed snapshot",
    ):
        assert stale_description not in help_text


def test_runner_error_requires_explicit_code_and_message() -> None:
    error = runner.RunnerError(runner.ARGUMENT_ERROR, runner.CLI_ARGUMENT_ERROR)
    signature = inspect.signature(runner.RunnerError)

    assert error.code == runner.ARGUMENT_ERROR
    assert error.message == runner.CLI_ARGUMENT_ERROR
    assert tuple(signature.parameters) == ("code", "message")
    assert all(
        parameter.default is inspect.Parameter.empty for parameter in signature.parameters.values()
    )
    assert not hasattr(collect, "SnapshotError")


def test_top_level_unexpected_exception_reports_code_and_type_without_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target_repository: git.ValidatedTargetRepository,
) -> None:
    def fail(_arguments: argparse.Namespace) -> int:
        raise OSError(CLI_MARKER)

    monkeypatch.setattr(runner, "_run_prepare", fail)
    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repository.path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {runner.RUNNER_UNEXPECTED_ERROR}: "
        "unexpected OSError during prepare workflow\n"
    )
    assert CLI_MARKER not in captured.err
    assert "unsafe diagnostic suppressed" not in captured.err


def test_git_failure_reports_operation_exit_code_without_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target_repository: git.ValidatedTargetRepository,
) -> None:
    secret = "SYNTHETIC_GIT_STDERR_SECRET"
    original_run = git.GitRunner.run

    def fail_diff(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        if arguments[:1] == ("diff",):
            return git.GitResult(b"", secret.encode(), 128, False, "diff")
        return original_run(self, arguments, maximum=maximum)

    monkeypatch.setattr(git.GitRunner, "run", fail_diff)

    assert runner.main(["prepare", "diff-audit", "--repo", os.fspath(target_repository.path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {git.GIT_COMMAND_FAILED}: git diff collection failed (exit=128)\n"
    )
    assert secret not in captured.err
    assert "unsafe diagnostic suppressed" not in captured.err


def test_top_level_keyboard_interrupt_semantics_are_not_suppressed(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target_repository: git.ValidatedTargetRepository,
) -> None:
    def fail(_arguments: argparse.Namespace) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "_run_prepare", fail)
    assert (
        runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repository.path)])
        == 128 + signal.SIGINT
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_prepare_publishes_content_addressed_private_snapshot(
    prepared_snapshot: artifact_module.SnapshotArtifact,
) -> None:
    artifact = prepared_snapshot
    assert artifact.snapshot_id == hashlib.sha256(artifact.snapshot_bytes).hexdigest()
    assert {
        path.name for path in artifact.directory.iterdir()
    } == artifact_module.SNAPSHOT_FILE_NAMES
    assert not list(artifact.directory.parent.glob(".staging-*"))
    for path in (artifact.directory, artifact.directory.parent):
        assert stat.S_IMODE(path.lstat().st_mode) == 0o700
    for name in artifact_module.SNAPSHOT_FILE_NAMES:
        assert stat.S_IMODE((artifact.directory / name).lstat().st_mode) == 0o600
    assert (artifact.directory / "snapshot.json").read_bytes() == artifact.snapshot_bytes
    envelope = json.loads(artifact.snapshot_bytes)
    meta = json.loads((artifact.directory / "meta.json").read_bytes())
    assert envelope["schema_version"] == collect.SNAPSHOT_SCHEMA_VERSION == 2
    assert meta["schema_version"] == artifact_module.SNAPSHOT_META_SCHEMA_VERSION == 2
    assert envelope["producer_security_epoch"] == collect.PRODUCER_SECURITY_EPOCH == 4
    assert meta["producer_security_epoch"] == collect.PRODUCER_SECURITY_EPOCH
    preview = (artifact.directory / "preview.txt").read_text(encoding="utf-8")
    assert preview.startswith("MANUAL REVIEW REQUIRED BEFORE UPLOAD\n")
    assert f"git: branch=feature/snapshot head={'a' * 40}\n" in preview
    assert "tracked_modified=1 untracked=0 staged=0 unstaged=1 changed_files=1" in preview
    assert "completeness: evidence_gaps=0 truncated=no incomplete=no" in preview
    assert "complete_evidence: snapshot.json" in preview
    assert '"schema_version"' not in preview and "safe commit" not in preview


def test_prepare_reuses_identical_existing_snapshot(
    prepared_snapshot: artifact_module.SnapshotArtifact,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    repeated = runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")
    assert repeated.snapshot_id == prepared_snapshot.snapshot_id
    assert repeated.snapshot_bytes == prepared_snapshot.snapshot_bytes
    assert repeated.directory == prepared_snapshot.directory
    assert not list(repeated.directory.parent.glob(".staging-*"))


def test_prepare_revalidates_complete_staging_before_publish(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())
    original_atomic_write = artifact_module._atomic_write

    def corrupt_preview_after_write(path: Path, content: bytes, maximum: int) -> None:
        original_atomic_write(path, content, maximum)
        if path.name == "preview.txt":
            path.write_bytes(path.read_bytes() + b"corrupted-after-validation\n")

    monkeypatch.setattr(artifact_module, "_atomic_write", corrupt_preview_after_write)
    with pytest.raises(runner.RunnerError, match="hash, identity, or size validation failed"):
        runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")

    root = artifact_module.snapshot_output_root()
    assert root.is_dir()
    assert list(root.iterdir()) == []


def test_prepare_validates_before_rename_and_does_not_reload_after_publish(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())
    events: list[tuple[str, Path]] = []
    original_validate = artifact_module._load_snapshot_directory
    original_rename = runner.os.rename

    def record_validation(snapshot_id: str, directory: Path) -> artifact_module.SnapshotArtifact:
        events.append(("validate", directory))
        return original_validate(snapshot_id, directory)

    def record_rename(source: Path, destination: Path) -> None:
        events.append(("rename", source))
        original_rename(source, destination)

    monkeypatch.setattr(artifact_module, "_load_snapshot_directory", record_validation)
    monkeypatch.setattr(runner.os, "rename", record_rename)
    monkeypatch.setattr(
        artifact_module,
        "_load_snapshot",
        lambda _snapshot_id: pytest.fail("published snapshot was reloaded after rename"),
    )

    artifact = runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")

    assert [event for event, _path in events] == ["validate", "rename"]
    assert events[0][1].name.startswith(".staging-snapshot-")
    assert events[1][1] == events[0][1]
    assert artifact.directory == artifact_module.snapshot_output_root() / artifact.snapshot_id


def test_prepare_rename_failure_leaves_no_final_directory(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())
    secret = "SYNTHETIC_PUBLISH_SECRET"

    def fail_rename(_source: Path, _destination: Path) -> None:
        raise OSError(secret)

    monkeypatch.setattr(runner.os, "rename", fail_rename)
    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repository.path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {security.ARTIFACT_PUBLISH_FAILED}: "
        "unable to atomically publish snapshot\n"
    )
    assert secret not in captured.err
    assert "unsafe diagnostic suppressed" not in captured.err

    assert list(artifact_module.snapshot_output_root().iterdir()) == []


def test_prepare_staging_fsync_failure_before_rename_leaves_no_final_directory(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())
    original_fsync = artifact_module._fsync_directory

    def fail_staging_fsync(path: Path) -> None:
        if path.name.startswith(".staging-snapshot-"):
            raise OSError("synthetic staging fsync failure")
        original_fsync(path)

    monkeypatch.setattr(artifact_module, "_fsync_directory", fail_staging_fsync)
    with pytest.raises(runner.RunnerError, match="snapshot publication failed") as raised:
        runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")
    assert raised.value.code == security.ARTIFACT_PUBLISH_FAILED

    assert list(artifact_module.snapshot_output_root().iterdir()) == []


def test_prepare_parent_fsync_failure_returns_fixed_error_and_preserves_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    capsys: pytest.CaptureFixture[str],
) -> None:
    snapshot = _safe_snapshot()
    expected_envelope = artifact_module._sanitize_validate_snapshot(
        snapshot.as_envelope(),
        target_repository.path,
        expected_scan_manifest=snapshot.scan_manifest,
    )
    expected_bytes = artifact_module._serialize_snapshot(expected_envelope)
    expected_id = hashlib.sha256(expected_bytes).hexdigest()
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: snapshot)
    monkeypatch.setattr(git, "_find_executable", lambda _name: "/usr/bin/git")
    root = artifact_module.snapshot_output_root()
    synced: list[Path] = []
    original_fsync = artifact_module._fsync_directory

    def fail_store_fsync(path: Path) -> None:
        synced.append(path)
        if path == root:
            raise OSError("synthetic parent fsync failure")
        original_fsync(path)

    monkeypatch.setattr(artifact_module, "_fsync_directory", fail_store_fsync)

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repository.path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {security.ARTIFACT_PUBLISH_FAILED}: "
        f"{artifact_module.SNAPSHOT_PUBLISH_DURABILITY_ERROR}\n"
    )
    destination = root / expected_id
    assert synced[-1] == root
    assert destination.is_dir()
    assert not list(root.glob(".staging-*"))
    assert artifact_module._load_snapshot(expected_id).directory == destination


def test_prepare_redacts_identified_secret_from_snapshot_and_preview(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    builder = collect.SnapshotBuilder("repo-status", PROJECT_ROOT.name, PROJECT_ROOT)
    builder.add_text(
        "current_branch",
        "Authorization: Bearer abcdefghijklmnop",
        source="branch",
        scan_mode=security.ScanMode.PLAIN_TEXT,
    )
    for key in ("head", "status_short", "recent_commits", "local_branches"):
        builder.add_text(key, "safe", source=key, scan_mode=security.ScanMode.PLAIN_TEXT)
    builder.add_text(
        "upstream", "not configured", source="upstream", scan_mode=security.ScanMode.PLAIN_TEXT
    )
    builder.add_text(
        "ahead_behind",
        "not available",
        source="ahead-behind",
        scan_mode=security.ScanMode.PLAIN_TEXT,
    )
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: builder.finish())
    artifact = runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")
    combined = artifact.snapshot_bytes + (artifact.directory / "preview.txt").read_bytes()
    assert b"abcdefghijklmnop" not in combined
    assert b"REDACTED_AUTH" in combined


def test_prepare_fails_closed_for_complete_private_key_block() -> None:
    builder = collect.SnapshotBuilder("repo-status", PROJECT_ROOT.name, PROJECT_ROOT)
    with pytest.raises(security.RunnerError, match="prepare refused"):
        builder.add_text(
            "current_branch",
            _synthetic_pem_boundary("BEGIN")
            + "\nSYNTHETIC PRIVATE KEY BODY\n"
            + _synthetic_pem_boundary("END"),
            source="branch",
            scan_mode=security.ScanMode.PLAIN_TEXT,
        )


@pytest.mark.parametrize(
    ("raw", "marker", "scan_mode"),
    [
        (
            "Authorization: Bearer abcdefghijklmnop",
            "REDACTED_AUTH",
            security.ScanMode.PLAIN_TEXT,
        ),
        ("AKIAABCDEFGHIJKLMNOP", "REDACTED_AWS_ACCESS_KEY", security.ScanMode.PLAIN_TEXT),
        ("ghp_" + "A" * 24, "REDACTED_GITHUB_TOKEN", security.ScanMode.PLAIN_TEXT),
        ("sk-proj-" + "A" * 24, "REDACTED_OPENAI_TOKEN", security.ScanMode.PLAIN_TEXT),
    ],
)
def test_secret_formats_are_deterministically_redacted(
    raw: str,
    marker: str,
    scan_mode: security.ScanMode,
) -> None:
    sanitized = security.sanitize_text(raw, scan_mode=scan_mode, repository_root=PROJECT_ROOT)
    assert marker in sanitized.text
    assert raw not in sanitized.text


@pytest.mark.parametrize(
    ("field", "mutation"),
    [
        ("snapshot.json", "append"),
        ("preview.txt", "unlink"),
        ("meta.json", "symlink"),
    ],
)
def test_snapshot_reload_revalidates_hash_missing_and_regular_files(
    prepared_snapshot: artifact_module.SnapshotArtifact,
    tmp_path: Path,
    field: str,
    mutation: str,
) -> None:
    path = prepared_snapshot.directory / field
    if mutation == "append":
        path.write_bytes(path.read_bytes() + b" ")
    elif mutation == "unlink":
        path.unlink()
    else:
        path.unlink()
        target = tmp_path / "replacement"
        target.write_text("{}", encoding="utf-8")
        path.symlink_to(target)
    with pytest.raises(runner.RunnerError):
        artifact_module._load_snapshot(prepared_snapshot.snapshot_id)


def test_snapshot_reload_revalidates_owner_and_size(
    monkeypatch: pytest.MonkeyPatch,
    prepared_snapshot: artifact_module.SnapshotArtifact,
) -> None:
    actual_uid = os.getuid()
    monkeypatch.setattr(runner.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(runner.RunnerError, match="owned by the current user"):
        artifact_module._load_snapshot(prepared_snapshot.snapshot_id)
    monkeypatch.undo()
    with pytest.raises(runner.RunnerError, match="size bound"):
        artifact_module._read_private_regular(
            prepared_snapshot.directory / "snapshot.json",
            1,
            "snapshot JSON",
        )


def test_snapshot_reload_revalidates_schema() -> None:
    envelope = _safe_snapshot().as_envelope()
    envelope["schema_version"] = 999
    with pytest.raises(runner.RunnerError, match="schema"):
        artifact_module._validate_snapshot_envelope(envelope)


def test_conversion_safety_is_strictly_optional_and_schema_checked() -> None:
    envelope = _safe_snapshot("diff-audit").as_envelope()
    data = envelope["data"]
    assert isinstance(data, dict)
    data["conversion_safety"] = {
        "external_commands_executed": False,
        "content_diff_complete": True,
        "disabled_config_types": ["external_attributes_file"],
        "files": [],
    }

    assert artifact_module._validate_snapshot_envelope(envelope) is envelope

    conversion_safety = data["conversion_safety"]
    assert isinstance(conversion_safety, dict)
    conversion_safety["external_commands_executed"] = True
    with pytest.raises(runner.RunnerError, match="conversion-safety"):
        artifact_module._validate_snapshot_envelope(envelope)


def test_snapshot_reload_verifies_hash_before_rebuilding_scan_manifest(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    snapshot = _snapshot_with_file_context("token: str\n", "safe.py")
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    artifact = runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    snapshot_path = artifact.directory / "snapshot.json"
    snapshot_path.write_bytes(snapshot_path.read_bytes() + b" ")

    def unexpected_classifier(_path: str) -> security.ScanMode:
        raise AssertionError("classifier ran before hash validation")

    monkeypatch.setattr(artifact_module, "classify_scan_mode", unexpected_classifier)
    with pytest.raises(runner.RunnerError, match="hash"):
        artifact_module._load_snapshot(artifact.snapshot_id)
    assert artifact.directory.is_relative_to(private_state)


def test_snapshot_reload_rebuilds_manifest_with_same_fixed_classifier_after_validation(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    snapshot = _snapshot_with_file_context("token: str\n", "safe.py")
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    artifact = runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    original = artifact_module.classify_scan_mode
    observed: list[str] = []

    def recording_classifier(path: str) -> security.ScanMode:
        observed.append(path)
        return original(path)

    monkeypatch.setattr(artifact_module, "classify_scan_mode", recording_classifier)
    loaded = artifact_module._load_snapshot(artifact.snapshot_id)
    assert loaded.snapshot_id == artifact.snapshot_id
    assert observed and set(observed) == {"safe.py"}
    assert loaded.directory.is_relative_to(private_state)


def test_snapshot_reload_rejects_scan_classifier_version_drift(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    snapshot = _snapshot_with_file_context("token: str\n", "safe.py")
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    artifact = runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    monkeypatch.setattr(
        artifact_module, "SCAN_CLASSIFIER_VERSION", security.SCAN_CLASSIFIER_VERSION + 1
    )
    with pytest.raises(runner.RunnerError, match="classifier"):
        artifact_module._load_snapshot(artifact.snapshot_id)
    assert artifact.directory.is_relative_to(private_state)


def test_snapshot_ancestor_symlink_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    linked_state = tmp_path / "linked-state"
    linked_state.symlink_to(PROJECT_ROOT, target_is_directory=True)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(linked_state))
    with pytest.raises(runner.RunnerError, match="symlink ancestor"):
        artifact_module._ensure_private_state_directory(
            artifact_module.snapshot_output_root(),
            "snapshot store",
        )


def test_state_home_must_be_separate_from_runner_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(PROJECT_ROOT))
    with pytest.raises(runner.RunnerError, match="outside and separate"):
        artifact_module._state_home()


def test_state_home_refuses_parent_traversal_into_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = PROJECT_ROOT / ".." / PROJECT_ROOT.name
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(raw))
    with pytest.raises(runner.RunnerError, match="canonical"):
        artifact_module._state_home()


def test_default_local_state_path_is_accepted_when_private(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    state = home / ".local" / "state"
    state.mkdir(mode=0o700, parents=True)
    state.chmod(0o700)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", os.fspath(home))
    assert artifact_module._state_home() == state


def test_existing_state_home_requires_directory_owner_and_private_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o755)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    with pytest.raises(runner.RunnerError, match="mode 0700"):
        artifact_module._state_home()
    state.chmod(0o700)
    actual_uid = os.getuid()
    monkeypatch.setattr(runner.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(runner.RunnerError, match="owned by the current user"):
        artifact_module._state_home()


def test_state_home_requires_an_absolute_existing_real_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("XDG_STATE_HOME", "relative/state")
    with pytest.raises(runner.RunnerError, match="must be absolute"):
        artifact_module._state_home()

    missing = tmp_path / "missing-state"
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(missing))
    with pytest.raises(runner.RunnerError, match=f"^{artifact_module.STATE_HOME_MISSING_ERROR}$"):
        artifact_module._state_home()

    state_file = tmp_path / "state-file"
    state_file.write_text("not a directory", encoding="utf-8")
    state_file.chmod(0o600)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state_file))
    with pytest.raises(runner.RunnerError, match="non-directory|real directory"):
        artifact_module._state_home()


def test_every_subprocess_is_shell_free() -> None:
    source = "\n".join(
        (PROJECT_ROOT / "codex_snapshot_runner" / name).read_text(encoding="utf-8")
        for name in ("artifact.py", "cli.py", "collect.py", "git.py", "security.py")
    )
    assert "shell=True" not in source
    assert "subprocess.run(" not in source
    assert "os.system(" not in source


def test_just_prepare_recipe_selects_prepare_without_executing_runner(tmp_path: Path) -> None:
    captured = _capture_just_argv(
        tmp_path,
        "codex-repo-status",
        ["--repo", "/absolute/target/repo"],
    )
    assert captured[-4:] == [
        "prepare",
        "repo-status",
        "--repo",
        "/absolute/target/repo",
    ]
    assert "analyze" not in captured


def _capture_just_argv(tmp_path: Path, recipe: str, arguments: list[str]) -> list[str]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    capture = tmp_path / "argv.json"
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, sys\n"
        "with open(os.environ['CODEX_EXEC_ARGV_CAPTURE'], 'w', encoding='utf-8') as stream:\n"
        "    json.dump(sys.argv[1:], stream, ensure_ascii=False)\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o700)
    just = shutil.which("just")
    assert just is not None
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    environment["CODEX_EXEC_ARGV_CAPTURE"] = os.fspath(capture)
    result = subprocess.run(
        [just, recipe, *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(capture.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("recipe", "arguments", "action"),
    [
        (
            "codex-repo-status",
            ["--repo", "/absolute/target/repo"],
            ["prepare", "repo-status", "--repo", "/absolute/target/repo"],
        ),
        (
            "codex-diff-audit",
            ["--repo", "/absolute/target/repo"],
            ["prepare", "diff-audit", "--repo", "/absolute/target/repo"],
        ),
        (
            "codex-branch-review",
            ["--repo", "/absolute/target/repo", "main"],
            ["prepare", "branch-review", "--repo", "/absolute/target/repo", "main"],
        ),
        (
            "codex-test-triage",
            ["--repo", "/absolute/target/repo", "safe log.txt"],
            [
                "prepare",
                "test-triage",
                "--repo",
                "/absolute/target/repo",
                "safe log.txt",
            ],
        ),
        ("codex-analyze-snapshot", ["a" * 64], ["analyze", "a" * 64]),
    ],
)
def test_all_just_recipes_forward_only_positional_argv(
    tmp_path: Path,
    recipe: str,
    arguments: list[str],
    action: list[str],
) -> None:
    captured = _capture_just_argv(tmp_path, recipe, arguments)
    assert captured == [
        "run",
        "--no-cache",
        "--frozen",
        "--no-sync",
        "python",
        "-m",
        "codex_snapshot_runner.cli",
        *action,
    ]


@pytest.mark.parametrize(
    "snapshot_argument",
    [
        "snapshot id with spaces",
        "quote'\"value",
        "; touch SHOULD_NOT_EXIST",
        "$(touch SHOULD_NOT_EXIST)",
        "line one\nline two",
        "control\x01value",
    ],
    ids=("space", "quotes", "semicolon", "substitution", "newline", "control"),
)
def test_analyze_sentinel_recipe_treats_hostile_arguments_only_as_argv_data(
    tmp_path: Path,
    snapshot_argument: str,
) -> None:
    captured = _capture_just_argv(tmp_path, "codex-analyze-snapshot", [snapshot_argument])
    assert captured[-2:] == ["analyze", snapshot_argument]
    assert not (PROJECT_ROOT / "SHOULD_NOT_EXIST").exists()


def test_analyze_sentinel_recipe_missing_and_extra_arguments_remain_argv_data(
    tmp_path: Path,
) -> None:
    missing = _capture_just_argv(tmp_path / "missing", "codex-analyze-snapshot", [])
    extra = _capture_just_argv(
        tmp_path / "extra",
        "codex-analyze-snapshot",
        ["a" * 64, "unexpected"],
    )
    assert missing[-1:] == ["analyze"]
    assert extra[-3:] == ["analyze", "a" * 64, "unexpected"]


def test_all_just_recipes_have_safe_dry_run_scripts() -> None:
    just = shutil.which("just")
    assert just is not None
    recipes = {
        "codex-repo-status": ["--repo", "/absolute/target/repo"],
        "codex-diff-audit": ["--repo", "/absolute/target/repo"],
        "codex-branch-review": ["--repo", "/absolute/target/repo", "main"],
        "codex-test-triage": ["--repo", "/absolute/target/repo", "safe.log"],
        "codex-analyze-snapshot": ["a" * 64],
    }
    for recipe, arguments in recipes.items():
        result = subprocess.run(
            [just, "--dry-run", recipe, *arguments],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        dry_run = result.stdout + result.stderr
        assert '"$@"' in dry_run
        assert "{{" not in dry_run


def _repo_status_snapshot_with_text(raw: str) -> collect.Snapshot:
    builder = collect.SnapshotBuilder("repo-status", PROJECT_ROOT.name, PROJECT_ROOT)
    builder.add_text(
        "current_branch",
        raw,
        source="synthetic-evidence",
        scan_mode=security.ScanMode.PLAIN_TEXT,
    )
    for key in ("head", "status_short", "recent_commits", "local_branches"):
        builder.add_text(key, "safe", source=key, scan_mode=security.ScanMode.PLAIN_TEXT)
    return builder.finish()


@pytest.mark.parametrize(
    "raw",
    [
        "password: | # comment\n  SYNTHETIC_SECRET",
        "password: |2-\n  SYNTHETIC_SECRET",
    ],
)
def test_yaml_reproductions_fail_closed_through_prepare(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    raw: str,
) -> None:
    with pytest.raises(runner.RunnerError):
        snapshot = _legacy_snapshot_with_yaml_context(raw, "synthetic.yaml")
        monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
        runner._prepare_snapshot(
            "diff-audit",
            None,
            target_repository,
            "/usr/bin/git",
        )
    for path in private_state.rglob("*"):
        if path.is_file():
            assert b"SYNTHETIC_SECRET" not in path.read_bytes()


C01_MARKER = "SYNTHETIC_C01_MARKER"


@pytest.mark.parametrize(
    "raw",
    [
        f"!!str password: {C01_MARKER}",
        f"!synthetic password: {C01_MARKER}",
        f"&synthetic password: {C01_MARKER}",
        f"password: *{C01_MARKER}",
        f"? password\n: {C01_MARKER}",
        f"?\n  password\n: {C01_MARKER}",
        f"? !!str\n  password\n: {C01_MARKER}",
        f"?\n  !synthetic\n  &key\n  password\n: {C01_MARKER}",
        f"? password\n:\n  {C01_MARKER}",
        f"- password: {C01_MARKER}",
        f"?\n  - password\n: {C01_MARKER}",
        f"{{password: {C01_MARKER}}}",
        f"[password: {C01_MARKER}]",
        f"? {{password: {C01_MARKER}}}\n: safe",
        f"?\n  password: {C01_MARKER}\n: safe",
        f"? pass\n  word\n: {C01_MARKER}",
        f"key_name: &key password\n*key: {C01_MARKER}",
        f"<<: *{C01_MARKER}",
        f"password: |2-\n  {C01_MARKER}",
        f"? safe\n: password: {C01_MARKER}",
        f"? safe\n: - password: {C01_MARKER}",
        f"outer:\n  ? safe\n  : password: {C01_MARKER}",
        f"? safe\n: {{password: {C01_MARKER}}}",
        f"{{safe: ok,\n password: {C01_MARKER}}}",
        f"safe: [\n {{password: {C01_MARKER}}}\n]",
        f"safe: {{outer: [\n {{password: {C01_MARKER}}}\n]}}",
        f'safe: {{note: "x,#}}", # comment\n password: {C01_MARKER}}}',
        f"- safe: ok\n  password: {C01_MARKER}",
        f"- ? safe\n  : password: {C01_MARKER}",
        f"outer:\n  - password: {C01_MARKER}",
        f"safe: &ref {C01_MARKER}",
        f"safe: *ref\npassword: {C01_MARKER}",
        f"*ref: {C01_MARKER}",
        f"{{<<: *ref, password: {C01_MARKER}}}",
        f"outer:\n  <<: *ref\n  password: {C01_MARKER}",
        f"password: first\n  {C01_MARKER}",
        f'password: "{C01_MARKER}',
        f"\ufeff\ufeffpassword: {C01_MARKER}",
        f"pass\ufeffword: {C01_MARKER}",
    ],
    ids=(
        "standard-tag",
        "custom-tag",
        "anchor",
        "alias",
        "explicit-key",
        "explicit-key-indicator-line",
        "explicit-key-split-tag",
        "explicit-key-split-properties",
        "explicit-key-split-value",
        "sequence-key",
        "explicit-sequence-key",
        "flow-key",
        "flow-sequence-key",
        "nested-key",
        "block-nested-key",
        "multiline-plain-key",
        "alias-derived-key",
        "merge-key",
        "block-scalar",
        "explicit-inline-mapping-value",
        "explicit-inline-sequence-value",
        "nested-explicit-value",
        "explicit-flow-value",
        "multiline-flow-mapping",
        "flow-sequence-mapping",
        "nested-flow-collection",
        "flow-quote-comment-delimiter",
        "sequence-item-mapping",
        "sequence-explicit-mapping",
        "nested-sequence-credential",
        "anchor-value",
        "alias-value",
        "alias-key-direct",
        "flow-merge",
        "nested-merge",
        "multiline-plain-scalar",
        "unclosed-double-quote",
        "duplicate-bom",
        "internal-bom",
    ),
)
def test_c01_yaml_semantics_fail_closed_at_every_boundary(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    raw: str,
) -> None:
    with pytest.raises(
        security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"
    ) as sanitize_error:
        security.classify_scan_mode("synthetic.yaml")
    assert C01_MARKER not in str(sanitize_error.value)

    unsafe_snapshot = _legacy_snapshot_with_yaml_context(raw, "synthetic.yaml")
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: unsafe_snapshot)
    with pytest.raises(runner.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$") as raised:
        runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    assert C01_MARKER not in str(raised.value)
    assert raised.value.code == security.ARTIFACT_VALIDATION_FAILED
    assert not list(private_state.rglob(".staging-*"))
    assert not list(private_state.rglob("snapshot.json"))
    assert not list(private_state.rglob("preview.txt"))
    for path in private_state.rglob("*"):
        if path.is_file():
            assert C01_MARKER.encode() not in path.read_bytes()


def test_single_leading_bom_is_normalized_before_all_snapshot_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    token = "sk-proj-" + "B" * 24
    raw = "\ufeff" + token
    sanitized = security.sanitize_text(raw, scan_mode=security.ScanMode.PLAIN_TEXT)
    assert "\ufeff" not in sanitized.text
    assert token not in sanitized.text

    builder = collect.SnapshotBuilder("repo-status", PROJECT_ROOT.name, PROJECT_ROOT)
    builder.add_text(
        "current_branch",
        raw,
        source="synthetic-c01-bom",
        scan_mode=security.ScanMode.PLAIN_TEXT,
    )
    assert token not in str(builder.data["current_branch"])
    snapshot = _snapshot_with_file_context(raw, "synthetic.txt")
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    artifact = runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    combined = b"".join(path.read_bytes() for path in artifact.directory.iterdir())
    assert token.encode() not in combined
    assert "\ufeff".encode() not in combined
    assert not list(artifact.directory.parent.glob(".staging-*"))


def test_normalized_mapping_keys_preserve_values_and_reject_collisions() -> None:
    normalized = security.sanitize_json_value(
        {"\ufeffsafe": C01_MARKER},
        scan_mode=security.ScanMode.PLAIN_TEXT,
    )
    assert normalized == {"safe": C01_MARKER}
    with pytest.raises(security.SecurityError, match="collide"):
        security.sanitize_json_value(
            {"\ufeffsafe": 1, "safe": 2}, scan_mode=security.ScanMode.PLAIN_TEXT
        )


@pytest.mark.parametrize(
    "raw",
    [
        "safe: value\n",
        "'safe-key': value\n",
        '"safe_key": value\n',
        "outer:\n  nested:\n    name: value\n",
        "outer:\n  - name: value\n",
        "safe: {outer: [one, two]}\n",
        "safe: {\n  outer: [\n    one,\n    two\n  ] # bounded comment\n}\n",
        "# comment mentioning password: value\nsafe: value\n",
    ],
)
def test_yaml_subset_entrypoint_is_removed_for_every_structure(raw: str) -> None:
    assert raw
    assert not hasattr(security, "scan_yaml_subset")
    with pytest.raises(security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        security.classify_scan_mode("synthetic.yaml")


def test_yaml_recognizer_and_compatibility_path_are_not_production_boundaries() -> None:
    source = (PROJECT_ROOT / "codex_snapshot_runner/security.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "scan_yaml_subset" not in function_names
    assert "_is_complete_json_collection" not in function_names
    class_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
    assert not class_names & {
        "SafeYamlScanResult",
        "_SafeYamlSubsetScanner",
        "_YamlContainer",
        "_YamlCredentialSpan",
        "_YamlEvidenceGap",
        "_YamlFlowFrame",
        "_YamlReject",
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "scan_yaml_subset" not in calls
    assert "_SafeYamlSubsetScanner" not in calls
    scan_mode = next(
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ScanMode"
    )
    assert all(
        not isinstance(node, ast.Assign)
        or all(not isinstance(target, ast.Name) or target.id != "YAML" for target in node.targets)
        for node in scan_mode.body
    )
    assert "REDACTED_YAML_CREDENTIAL" not in source
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
    assert "yaml" not in imported_roots


def test_yaml_rejection_is_independent_of_depth_token_and_scalar_shape() -> None:
    samples = (
        "".join(f"{'  ' * depth}level_{depth}:\n" for depth in range(64)),
        "one: 1\ntwo: 2\nthree: 3\n",
        "safe: " + "x" * (64 * 1024 + 1),
    )
    for raw in samples:
        with pytest.raises(
            security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"
        ) as raised:
            security.classify_scan_mode("synthetic.yaml")
        assert raw not in str(raised.value)


@pytest.mark.parametrize(
    "raw",
    [
        "".join(f"{'  ' * depth}level_{depth}:\n" for depth in range(64)),
        "safe: " + "x" * (64 * 1024 + 1),
    ],
)
def test_yaml_depth_and_scalar_limits_reject_builder_and_artifact(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    raw: str,
) -> None:
    snapshot = _legacy_snapshot_with_yaml_context(raw, "synthetic.yaml")
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    with pytest.raises(runner.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    assert not list(private_state.rglob(".staging-*"))


def test_yaml_token_limit_rejects_builder_and_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_attempted = False

    def unexpected_read(*_args: object, **_kwargs: object) -> tuple[str, int, None]:
        nonlocal read_attempted
        read_attempted = True
        raise AssertionError("YAML file content was read")

    monkeypatch.setattr(collect, "_read_regular_file", unexpected_read)
    builder = collect.SnapshotBuilder("repo-status", PROJECT_ROOT.name, PROJECT_ROOT)
    with pytest.raises(security.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        collect._add_context(builder, ["synthetic.yml"])
    assert read_attempted is False


def test_yaml_test_log_is_rejected_before_safe_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened = False

    def unexpected_open(*_args: object, **_kwargs: object) -> tuple[None, None, str]:
        nonlocal opened
        opened = True
        raise AssertionError("YAML test log was opened")

    monkeypatch.setattr(collect, "_open_repo_regular", unexpected_open)
    with pytest.raises(security.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        collect._read_test_log(PROJECT_ROOT, "synthetic.yaml")
    assert opened is False


def test_test_triage_refuses_unsafe_log_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    safe_log = repo / "safe.log"
    safe_log.write_text("1 passed\n", encoding="utf-8")
    (tmp_path / "outside.log").write_text("outside\n", encoding="utf-8")
    (repo / "linked.log").symlink_to(safe_log)
    (repo / "log-directory").mkdir()

    for supplied in (os.fspath(safe_log), "../outside.log", "linked.log", "log-directory"):
        with pytest.raises(security.RunnerError, match="test log refused"):
            collect.collect_test_triage(repo, supplied)


def test_test_triage_log_limit_preserves_bounded_head_and_tail(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "large.log").write_bytes(b"H" + b"x" * collect.MAX_TEST_LOG_BYTES + b"T")

    log, omitted, display_name = collect._read_test_log(repo, "large.log")
    assert len(log.encode()) <= collect.MAX_TEST_LOG_BYTES
    assert log.startswith("H") and log.endswith("T")
    assert "[...TEST_LOG_MIDDLE_OMITTED...]" in log
    assert omitted == 36
    assert display_name == "test-output.log"


@pytest.mark.parametrize(
    ("relative_path", "expected"),
    [
        ("module.py", security.ScanMode.PLAIN_TEXT),
        ("web.tsx", security.ScanMode.PLAIN_TEXT),
        ("Justfile", security.ScanMode.PLAIN_TEXT),
        ("Dockerfile", security.ScanMode.PLAIN_TEXT),
        ("notes.md", security.ScanMode.PLAIN_TEXT),
        ("config.toml", security.ScanMode.PLAIN_TEXT),
        (".gitattributes", security.ScanMode.PLAIN_TEXT),
    ],
)
def test_scan_mode_does_not_infer_source_languages(
    relative_path: str,
    expected: security.ScanMode,
) -> None:
    assert security.classify_scan_mode(relative_path) is expected


@pytest.mark.parametrize(
    "relative_path",
    ["config.yaml", "config.YML", "../config.yaml", "/tmp/config.yaml", "secrets.yaml"],
)
def test_yaml_suffix_classifier_uses_one_fixed_safe_error(relative_path: str) -> None:
    with pytest.raises(security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        security.classify_scan_mode(relative_path)


@pytest.mark.parametrize(
    "relative_path",
    ["unknown.bin", ".unknown-dotfile", "bad\nname.py"],
)
def test_scan_mode_classifier_rejects_unknown_or_unsafe_paths(relative_path: str) -> None:
    with pytest.raises(security.SecurityError):
        security.classify_scan_mode(relative_path)


def test_missing_unknown_and_version_mismatched_scan_modes_fail_closed() -> None:
    with pytest.raises(security.SecurityError, match="scan mode"):
        security.sanitize_text("safe")
    with pytest.raises(security.SecurityError, match="scan mode"):
        security.sanitize_text("safe", scan_mode="yaml")  # type: ignore[arg-type]
    with pytest.raises(security.SecurityError, match="scan mode"):
        security.sanitize_json_value("safe")
    with pytest.raises(security.SecurityError, match="version"):
        security.ScanModeManifest(999, ())


@pytest.mark.parametrize(
    ("relative_path", "raw"),
    [
        ("safe.py", "# token: str is an annotation example\n"),
        ("safe.py", 'message = "password: function argument"\n'),
        ("safe.py", "def f(token: str) -> None:\n    return None\n"),
        ("safe.py", "result = value if flag else fallback  # ordinary: colon\n"),
        ("safe.txt", "Prose discusses password and token without assigning either.\n"),
        ("safe.txt", "https://example.invalid?q=value\n"),
        ("safe.txt", "Label: an ordinary colon in prose.\n"),
    ],
)
def test_source_and_plain_text_do_not_gain_yaml_semantics_at_any_boundary(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    relative_path: str,
    raw: str,
) -> None:
    mode = security.classify_scan_mode(relative_path)
    assert security.sanitize_text(raw, scan_mode=mode).text == raw

    builder = collect.SnapshotBuilder("repo-status", PROJECT_ROOT.name, PROJECT_ROOT)
    builder.add_text("current_branch", raw, source="synthetic-source", scan_mode=mode)
    assert builder.data["current_branch"] == raw

    snapshot = _snapshot_with_file_context(raw, relative_path)
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    artifact = runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    contexts = artifact.envelope["data"]["file_context"]  # type: ignore[index]
    assert contexts[0]["content"] == raw  # type: ignore[index]
    assert not list(artifact.directory.parent.glob(".staging-*"))


def _synthetic_diff(path: str, old: str, new: str) -> str:
    return (
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-{old}\n+{new}\n"
    )


def test_mixed_yaml_and_source_diff_rejects_the_entire_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    raw = _synthetic_diff("config.yaml", "password: old", "password: new") + _synthetic_diff(
        "module.py", "token: str", "token: str"
    )
    with pytest.raises(security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        security.sanitize_text(raw, scan_mode=security.ScanMode.UNIFIED_DIFF)
    monkeypatch.setattr(
        collect, "collect_diff_audit", lambda *_args, **_kwargs: _snapshot_with_diff(raw)
    )
    with pytest.raises(runner.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    assert not (private_state / "codex-exec").exists()


@pytest.mark.parametrize(
    "raw",
    [
        (
            "diff --git a/config.yaml b/config.yaml\n"
            "--- a/config.yaml\n"
            "+++ b/config.yaml\n"
            "@@ -1 +1 @@\n"
            "-password: old\n"
            "+password: new\n"
            "@@ -10 +10 @@\n"
            "-safe: before\n"
            "+safe: after\n"
        ),
        (
            "diff --git a/old.yaml b/new.py\n"
            "similarity index 100%\n"
            "rename from old.yaml\n"
            "rename to new.py\n"
        ),
        (
            "diff --git a/source.py b/copy.yml\n"
            "similarity index 100%\n"
            "copy from source.py\n"
            "copy to copy.yml\n"
        ),
    ],
    ids=("multiple-hunks", "rename", "copy"),
)
def test_unified_diff_rejects_every_yaml_file_section_before_hunk_scanning(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    raw: str,
) -> None:
    with pytest.raises(security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        security.sanitize_text(raw, scan_mode=security.ScanMode.UNIFIED_DIFF)
    monkeypatch.setattr(
        collect, "collect_diff_audit", lambda *_args, **_kwargs: _snapshot_with_diff(raw)
    )
    with pytest.raises(runner.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    assert not (private_state / "codex-exec").exists()


def _run_test_git(repo: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _test_git_output(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=repo,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _collector_deps(
    repo: Path,
) -> tuple[git.TargetGitEvidence, git.GitConversionPolicy]:
    builder = collect.SnapshotBuilder("repo-status", repo.name, repo)
    evidence = collect._current_target_evidence(git.GitRunner(repo), builder)
    return evidence, git.GitConversionPolicy()


def _initialize_isolation_repo(repo: Path, branch: str, committed_marker: str) -> str:
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet", f"--initial-branch={branch}")
    (repo / "safe.py").write_text(f'MARKER = "{committed_marker}"\n', encoding="utf-8")
    _run_test_git(repo, "add", "safe.py")
    _run_test_git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        committed_marker,
    )
    return _test_git_output(repo, "rev-parse", "HEAD")


def _commit_worktree_marker(repo: Path, name: str, marker: str) -> str:
    (repo / name).write_text(f'MARKER = "{marker}"\n', encoding="utf-8")
    _run_test_git(repo, "add", name)
    _run_test_git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        marker,
    )
    return _test_git_output(repo, "rev-parse", "HEAD")


def _initialize_shared_worktrees(
    root: Path,
) -> tuple[Path, Path, Path, str, str]:
    source = root / "shared-source"
    runner_repo = root / "runner-linked"
    target_repo = root / "target-linked"
    _initialize_isolation_repo(source, "shared-base", "SHARED_BASE_COMMIT")
    _run_test_git(source, "branch", "runner-only-branch")
    _run_test_git(source, "branch", "target-only-branch")
    _run_test_git(
        source, "worktree", "add", "--quiet", os.fspath(runner_repo), "runner-only-branch"
    )
    _run_test_git(
        source, "worktree", "add", "--quiet", os.fspath(target_repo), "target-only-branch"
    )
    runner_head = _commit_worktree_marker(
        runner_repo,
        "runner_committed.py",
        "RUNNER_ONLY_COMMIT_CANARY",
    )
    target_head = _commit_worktree_marker(
        target_repo,
        "target_committed.py",
        "TARGET_ONLY_COMMIT_CANARY",
    )
    (runner_repo / "RUNNER_STATUS_CANARY.txt").write_text(
        "RUNNER_ONLY_STATUS_CANARY\n", encoding="utf-8"
    )
    (target_repo / "TARGET_STATUS_CANARY.txt").write_text(
        "TARGET_ONLY_STATUS_CANARY\n", encoding="utf-8"
    )
    return source, runner_repo, target_repo, runner_head, target_head


def test_test_triage_target_repository_rejections_happen_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    valid_repo = tmp_path / "valid-repo"
    _initialize_isolation_repo(valid_repo, "target-valid", "TARGET_VALID_COMMIT")
    non_git = tmp_path / "non-git"
    non_git.mkdir()
    direct_link = tmp_path / "direct-link"
    direct_link.symlink_to(valid_repo, target_is_directory=True)
    real_parent = tmp_path / "real-parent"
    nested_repo = real_parent / "nested-repo"
    real_parent.mkdir()
    _initialize_isolation_repo(nested_repo, "target-nested", "TARGET_NESTED_COMMIT")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    subdirectory = valid_repo / "subdirectory"
    subdirectory.mkdir()
    traversal = valid_repo.parent / ".." / valid_repo.parent.name / valid_repo.name
    candidates = (
        "relative-repo",
        os.fspath(tmp_path / "missing-repo"),
        os.fspath(non_git),
        os.fspath(direct_link),
        os.fspath(linked_parent / nested_repo.name),
        os.fspath(traversal),
        os.fspath(subdirectory),
    )
    collected = False

    def unexpected_collection(*_args: object, **_kwargs: object) -> collect.Snapshot:
        nonlocal collected
        collected = True
        raise AssertionError("collector ran for an invalid target repository")

    monkeypatch.setattr(collect, "collect_test_triage", unexpected_collection)
    monkeypatch.setattr(git, "_find_executable", lambda _name: "/usr/bin/git")
    for candidate in candidates:
        arguments = argparse.Namespace(
            action="prepare",
            task="test-triage",
            repo=candidate,
            task_argument="safe.log",
        )
        with pytest.raises(runner.RunnerError, match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$"):
            runner._run_prepare(arguments)
    assert collected is False


def test_target_repository_wrong_owner_is_rejected_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "wrong-owner-repo"
    _initialize_isolation_repo(repo, "target-owner", "TARGET_OWNER_COMMIT")
    collected = False

    def unexpected_collection(*_args: object, **_kwargs: object) -> collect.Snapshot:
        nonlocal collected
        collected = True
        raise AssertionError("collector ran for a wrong-owner target repository")

    actual_uid = os.getuid()
    monkeypatch.setattr(runner.os, "getuid", lambda: actual_uid + 1)
    monkeypatch.setattr(collect, "collect_repo_status", unexpected_collection)
    arguments = argparse.Namespace(
        action="prepare",
        task="repo-status",
        repo=os.fspath(repo),
        task_argument=None,
    )
    with pytest.raises(runner.RunnerError, match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$"):
        runner._run_prepare(arguments)
    assert collected is False


@pytest.mark.parametrize(
    ("task", "task_argument"),
    [
        ("repo-status", None),
        ("diff-audit", None),
        ("branch-review", "target-main"),
        ("test-triage", "safe.log"),
    ],
)
def test_prepare_only_public_entry_completes_all_four_prepare_workflows(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    task: str,
    task_argument: str | None,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    repo = tmp_path / "target-repo"
    _initialize_isolation_repo(repo, "target-main", "BASELINE_COMMIT")
    (repo / "safe.py").write_text('MARKER = "WORKTREE_CHANGE"\n', encoding="utf-8")
    (repo / "safe.log").write_text("1 passed\n", encoding="utf-8")
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    preflight_calls = 0
    conversion_policy_calls = 0
    original_preflight = git.preflight_git_capabilities
    original_conversion_policy = git.GitConversionPolicy

    def count_preflight(*args: object, **kwargs: object) -> git.GitCapabilityFingerprint:
        nonlocal preflight_calls
        preflight_calls += 1
        return original_preflight(*args, **kwargs)  # type: ignore[arg-type]

    def count_conversion_policy(*args: object, **kwargs: object) -> git.GitConversionPolicy:
        nonlocal conversion_policy_calls
        conversion_policy_calls += 1
        return original_conversion_policy(*args, **kwargs)  # type: ignore[arg-type]

    resolved: list[str] = []

    def find(name: str) -> str:
        resolved.append(name)
        if name != "git":
            raise AssertionError("prepare resolved an automatic-analysis executable")
        return "/usr/bin/git"

    monkeypatch.setattr(git, "_find_executable", find)
    monkeypatch.setattr(git, "preflight_git_capabilities", count_preflight)
    monkeypatch.setattr(git, "GitConversionPolicy", count_conversion_policy)
    argv = ["prepare", task, "--repo", os.fspath(repo)]
    if task_argument is not None:
        argv.append(task_argument)

    assert runner.main(argv) == 0
    output = capsys.readouterr().out
    assert resolved == ["git"]
    expected_capability_calls = 0 if task == "test-triage" else 2
    assert preflight_calls == expected_capability_calls
    assert conversion_policy_calls == expected_capability_calls
    assert "manual_workflow:" in output
    assert "manually upload preview.txt or snapshot.json to ChatGPT" in output
    assert "just codex-analyze-snapshot" not in output

    snapshot_root = state / "codex-exec" / "snapshots"
    directories = list(snapshot_root.iterdir())
    assert len(directories) == 1
    directory = directories[0]
    assert {path.name for path in directory.iterdir()} == artifact_module.SNAPSHOT_FILE_NAMES
    assert stat.S_IMODE(snapshot_root.lstat().st_mode) == 0o700
    assert stat.S_IMODE(directory.lstat().st_mode) == 0o700
    for name in artifact_module.SNAPSHOT_FILE_NAMES:
        assert stat.S_IMODE((directory / name).lstat().st_mode) == 0o600

    snapshot_bytes = (directory / "snapshot.json").read_bytes()
    preview_bytes = (directory / "preview.txt").read_bytes()
    envelope = json.loads(snapshot_bytes)
    meta = json.loads((directory / "meta.json").read_bytes())
    assert envelope["task"] == task
    assert envelope["schema_version"] == collect.SNAPSHOT_SCHEMA_VERSION == 2
    assert envelope["producer_security_epoch"] == collect.PRODUCER_SECURITY_EPOCH == 4
    assert meta["schema_version"] == artifact_module.SNAPSHOT_META_SCHEMA_VERSION == 2
    assert meta["producer_security_epoch"] == collect.PRODUCER_SECURITY_EPOCH
    assert meta["snapshot_sha256"] == hashlib.sha256(snapshot_bytes).hexdigest()
    assert meta["preview_sha256"] == hashlib.sha256(preview_bytes).hexdigest()
    assert meta["preview_bytes"] == len(preview_bytes)
    preview = preview_bytes.decode("utf-8")
    assert f"snapshot_id: {directory.name}\ntask: {task}\n" in preview
    assert "completeness: evidence_gaps=" in preview
    assert not (state / "codex-exec" / "runs").exists()
    assert not (state / "codex-exec" / "codex-home").exists()


def test_git_runner_uses_validated_repo_only_as_dash_c_argv(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    shallow_marker = tmp_path / "SYNTHETIC_HOST_SHALLOW_MARKER"
    shallow_marker.write_text("HOST_SHALLOW_BODY_MUST_NOT_ESCAPE\n", encoding="utf-8")
    hostile_git_environment = {
        "GIT_DIR": "/synthetic/host/git-dir",
        "GIT_WORK_TREE": "/synthetic/host/worktree",
        "GIT_COMMON_DIR": "/synthetic/host/common-dir",
        "GIT_INDEX_FILE": "/synthetic/host/index",
        "GIT_SHALLOW_FILE": os.fspath(shallow_marker),
        "GIT_OBJECT_DIRECTORY": "/synthetic/host/objects",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/synthetic/host/alternate-objects",
        "GIT_NAMESPACE": "synthetic-host-namespace",
        "GIT_ATTR_SOURCE": "synthetic-host-attributes",
        "GIT_EXTERNAL_DIFF": "/synthetic/host/external-diff",
        "GIT_DIFF_OPTS": "--synthetic-host-option",
        "GIT_SSH": "/synthetic/host/ssh",
        "GIT_SSH_COMMAND": "/synthetic/host/ssh-command",
        "GIT_ASKPASS": "/synthetic/host/askpass",
        "GIT_CONFIG_PARAMETERS": "'color.ui'='always'",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "color.ui",
        "GIT_CONFIG_VALUE_0": "always",
    }
    for name, value in hostile_git_environment.items():
        monkeypatch.setenv(name, value)
    observed: list[tuple[list[str], object, object, object]] = []
    original_popen = git.subprocess.Popen

    def recording_popen(argv: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
        observed.append((argv, kwargs.get("cwd"), kwargs.get("shell"), kwargs.get("env")))
        return original_popen(argv, **kwargs)

    monkeypatch.setattr(git.subprocess, "Popen", recording_popen)
    snapshot = collect.collect_repo_status(
        target_repository.path, *_collector_deps(target_repository.path)
    )
    assert snapshot.repository == target_repository.name
    serialized = json.dumps(snapshot.as_envelope())
    assert os.fspath(shallow_marker) not in serialized
    assert "HOST_SHALLOW_BODY_MUST_NOT_ESCAPE" not in serialized
    assert observed
    for argv, cwd, shell, environment in observed:
        assert argv[:3] == ["/usr/bin/git", "-C", os.fspath(target_repository.path)]
        assert cwd == "/"
        assert shell is False
        assert isinstance(environment, dict)
        assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
        assert environment["GIT_CONFIG_GLOBAL"] == "/dev/null"
        assert environment["GIT_CONFIG_SYSTEM"] == "/dev/null"
        assert environment["GIT_CONFIG_COUNT"] == "0"
        assert environment["GIT_ATTR_NOSYSTEM"] == "1"
        assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert environment["GIT_NO_LAZY_FETCH"] == "1"
        assert environment["GIT_OPTIONAL_LOCKS"] == "0"
        assert environment["GIT_TERMINAL_PROMPT"] == "0"
        assert environment["GIT_PAGER"] == "cat"
        assert environment["XDG_CONFIG_HOME"] == "/nonexistent"
        assert not (set(hostile_git_environment) - {"GIT_CONFIG_COUNT"}) & set(environment)
        assert not any(
            name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")) for name in environment
        )
        assert "core.hooksPath=/dev/null" in argv
        assert "core.fsmonitor=false" in argv
        assert "diff.external=" in argv
        assert not any(argument.startswith("filter.lfs.") for argument in argv)


def test_host_git_shallow_file_cannot_affect_prepare_evidence_or_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    marker = tmp_path / "SYNTHETIC_GIT_SHALLOW_FILE"
    marker_body = "HOST_SHALLOW_MARKER_MUST_NOT_ENTER_ARTIFACT"
    marker.write_text(f"{marker_body}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_SHALLOW_FILE", os.fspath(marker))

    artifact = runner._prepare_snapshot(
        "repo-status",
        None,
        target_repository,
        "/usr/bin/git",
    )

    assert artifact.envelope["data"]["head"] == target_repository.target_identity.head  # type: ignore[index]
    combined = b"".join(
        (artifact.directory / name).read_bytes() for name in artifact_module.SNAPSHOT_FILE_NAMES
    )
    assert os.fspath(marker).encode() not in combined
    assert marker_body.encode() not in combined
    assert not (private_state / "codex-exec" / "runs").exists()


def test_target_and_runner_worktrees_must_not_contain_each_other(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    container = tmp_path / "container-repo"
    runner_repo = container / "runner-repo"
    child = runner_repo / "target-repo"
    container.mkdir()
    runner_repo.mkdir()
    child.mkdir()
    monkeypatch.setattr(runner, "REPOSITORY_ROOT", runner_repo)
    for candidate in (container, runner_repo, child):
        with pytest.raises(runner.RunnerError, match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$"):
            runner._validate_target_repository_path(os.fspath(candidate))


@pytest.mark.parametrize("relation", ["target", "target-child", "target-parent"])
def test_state_home_is_separate_from_target_and_runner(
    monkeypatch: pytest.MonkeyPatch,
    target_repository: git.ValidatedTargetRepository,
    relation: str,
) -> None:
    candidates = {
        "target": target_repository.path,
        "target-child": target_repository.path / "state",
        "target-parent": target_repository.path.parent,
    }
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(candidates[relation]))
    with pytest.raises(runner.RunnerError, match="outside and separate"):
        artifact_module._state_home(target_repository.path)


def test_path_level_state_failure_runs_zero_git_commands_and_creates_no_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target_repo = tmp_path / "target-repo"
    _initialize_isolation_repo(target_repo, "target-branch", "TARGET_BASELINE")
    state = target_repo / ".git"
    state.chmod(0o700)
    git_calls: list[tuple[Path, tuple[str, ...]]] = []
    resolved_executables: list[str] = []

    def unexpected_git(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        del maximum
        git_calls.append((self.repo_root, arguments))
        raise AssertionError("Git ran before path-level state validation")

    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.setattr(git.GitRunner, "run", unexpected_git)

    def unexpected_resolution(name: str) -> str:
        resolved_executables.append(name)
        raise AssertionError("executable resolution ran before path-level state validation")

    monkeypatch.setattr(git, "_find_executable", unexpected_resolution)
    monkeypatch.setattr(
        collect,
        "collect_test_triage",
        lambda *_args, **_kwargs: pytest.fail("collector ran after invalid state path"),
    )
    arguments = argparse.Namespace(
        action="prepare",
        task="test-triage",
        repo=os.fspath(target_repo),
        task_argument="safe.log",
    )

    with pytest.raises(runner.RunnerError, match="outside and separate"):
        runner._run_prepare(arguments)

    assert git_calls == []
    assert resolved_executables == []
    assert not (state / "codex-exec").exists()
    assert not list(tmp_path.rglob("snapshot.json"))


@pytest.mark.parametrize(
    "state_relation",
    ("target-git-dir", "runner-git-dir", "shared-common-dir", "contains-common-dir"),
)
def test_state_git_admin_overlap_stops_after_only_fixed_path_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state_relation: str,
) -> None:
    source, runner_repo, target_repo, _runner_head, _target_head = _initialize_shared_worktrees(
        tmp_path
    )
    target_git_dir = Path(_test_git_output(target_repo, "rev-parse", "--absolute-git-dir")).resolve(
        strict=True
    )
    runner_git_dir = Path(_test_git_output(runner_repo, "rev-parse", "--absolute-git-dir")).resolve(
        strict=True
    )
    common_dir = Path(
        _test_git_output(
            target_repo,
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        )
    ).resolve(strict=True)
    candidates = {
        "target-git-dir": target_git_dir,
        "runner-git-dir": runner_git_dir,
        "shared-common-dir": common_dir,
        "contains-common-dir": source,
    }
    state = candidates[state_relation]
    state.chmod(0o700)
    observed: list[tuple[Path, tuple[str, ...]]] = []
    original_run = git.GitRunner.run

    def recording_run(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        observed.append((self.repo_root, arguments))
        return original_run(self, arguments, maximum=maximum)

    monkeypatch.setattr(runner, "REPOSITORY_ROOT", runner_repo)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.setattr(git.GitRunner, "run", recording_run)
    monkeypatch.setattr(git, "_find_executable", lambda _name: "/usr/bin/git")
    monkeypatch.setattr(
        collect,
        "collect_repo_status",
        lambda *_args, **_kwargs: pytest.fail("collector ran after Git-admin overlap"),
    )
    arguments = argparse.Namespace(
        action="prepare",
        task="repo-status",
        repo=os.fspath(target_repo),
        task_argument=None,
    )
    path_validation = (
        "rev-parse",
        "--is-inside-work-tree",
        "--path-format=absolute",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
    )

    with pytest.raises(runner.RunnerError, match=f"^{git.STATE_GIT_BOUNDARY_ERROR}$"):
        runner._run_prepare(arguments)

    assert observed == [(target_repo, path_validation), (runner_repo, path_validation)]
    assert not (state / "codex-exec").exists()
    assert not list(tmp_path.rglob("snapshot.json"))


def test_repo_status_snapshot_is_isolated_from_runner_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner_repo = tmp_path / "runner-repo"
    target_repo = tmp_path / "target-repo"
    state = tmp_path / "isolated-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    runner_head = _initialize_isolation_repo(
        runner_repo, "runner-only-branch", "RUNNER_ONLY_COMMIT"
    )
    target_head = _initialize_isolation_repo(
        target_repo, "target-only-branch", "TARGET_ONLY_COMMIT"
    )
    (runner_repo / "RUNNER_ONLY_CANARY.txt").write_text("runner only\n", encoding="utf-8")
    (target_repo / "TARGET_ONLY_CANARY.txt").write_text("target only\n", encoding="utf-8")
    monkeypatch.setattr(runner, "REPOSITORY_ROOT", runner_repo)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.chdir(runner_repo)

    validated = _validated_test_repository(target_repo)
    assert validated.shared_common_dir is False
    assert validated.target_identity.current_ref == "refs/heads/target-only-branch"
    assert validated.runner_identity.current_ref == "refs/heads/runner-only-branch"
    assert validated.target_identity.head == target_head
    assert validated.runner_identity.head == runner_head
    assert (
        validated.target_identity.paths.git_common_dir
        != validated.runner_identity.paths.git_common_dir
    )

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repo)]) == 0
    assert "manual_workflow:" in capsys.readouterr().out
    directories = list((state / "codex-exec" / "snapshots").iterdir())
    assert len(directories) == 1
    directory = directories[0]
    snapshot_payload = json.loads((directory / "snapshot.json").read_bytes())
    meta_payload = json.loads((directory / "meta.json").read_bytes())
    combined = b"".join(
        (directory / name).read_bytes() for name in artifact_module.SNAPSHOT_FILE_NAMES
    )

    assert snapshot_payload["repository"] == target_repo.name
    assert meta_payload["repository"] == target_repo.name
    assert snapshot_payload["data"]["current_branch"] == "target-only-branch"
    assert snapshot_payload["data"]["head"] == target_head
    assert "TARGET_ONLY_CANARY.txt" in snapshot_payload["data"]["status_short"]
    for forbidden in (
        "runner-only-branch",
        runner_head,
        "RUNNER_ONLY_COMMIT",
        "RUNNER_ONLY_CANARY.txt",
        os.fspath(runner_repo),
        os.fspath(target_repo),
    ):
        assert forbidden.encode() not in combined


def test_shared_common_dir_repo_status_contains_only_target_worktree_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, runner_repo, target_repo, runner_head, target_head = _initialize_shared_worktrees(
        tmp_path
    )
    state = tmp_path / "isolated-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setattr(runner, "REPOSITORY_ROOT", runner_repo)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    validated = _validated_test_repository(target_repo)
    assert validated.shared_common_dir is True
    assert validated.target_identity.paths.worktree_root == target_repo
    assert validated.runner_identity.paths.worktree_root == runner_repo
    assert validated.target_identity.paths.git_common_dir == source / ".git"
    assert validated.runner_identity.paths.git_common_dir == source / ".git"
    assert validated.target_identity.current_ref == "refs/heads/target-only-branch"
    assert validated.runner_identity.current_ref == "refs/heads/runner-only-branch"
    assert validated.target_identity.head == target_head
    assert validated.runner_identity.head == runner_head
    for path in (
        validated.target_identity.paths.worktree_root,
        validated.target_identity.paths.git_dir,
        validated.target_identity.paths.git_common_dir,
        validated.runner_identity.paths.worktree_root,
        validated.runner_identity.paths.git_dir,
        validated.runner_identity.paths.git_common_dir,
    ):
        assert path.is_absolute()
        assert path.resolve(strict=True) == path

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(target_repo)]) == 0
    assert "manual_workflow:" in capsys.readouterr().out
    directories = list((state / "codex-exec" / "snapshots").iterdir())
    assert len(directories) == 1
    directory = directories[0]
    snapshot_payload = json.loads((directory / "snapshot.json").read_bytes())
    combined = b"".join(
        (directory / name).read_bytes() for name in artifact_module.SNAPSHOT_FILE_NAMES
    )
    data = snapshot_payload["data"]

    assert data["current_branch"] == "target-only-branch"
    assert data["head"] == target_head
    assert data["local_branches"] == f"target-only-branch\t{target_head}\n"
    assert "TARGET_STATUS_CANARY.txt" in data["status_short"]
    assert "TARGET_ONLY_COMMIT_CANARY" in data["recent_commits"]
    for forbidden in (
        "runner-only-branch",
        "refs/heads/runner-only-branch",
        runner_head,
        "RUNNER_ONLY_COMMIT_CANARY",
        "runner_committed.py",
        "RUNNER_STATUS_CANARY.txt",
        "RUNNER_ONLY_STATUS_CANARY",
        os.fspath(runner_repo),
        os.fspath(validated.runner_identity.paths.git_dir),
        os.fspath(validated.runner_identity.paths.git_common_dir),
        os.fspath(target_repo),
        os.fspath(validated.target_identity.paths.git_dir),
    ):
        assert forbidden.encode() not in combined


def test_shared_common_dir_branch_review_rejects_runner_current_ref(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _source, runner_repo, target_repo, _runner_head, _target_head = _initialize_shared_worktrees(
        tmp_path
    )
    state = tmp_path / "isolated-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setattr(runner, "REPOSITORY_ROOT", runner_repo)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    result = runner.main(
        [
            "prepare",
            "branch-review",
            "--repo",
            os.fspath(target_repo),
            "refs/heads/runner-only-branch",
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "base ref belongs to the Runner worktree" in captured.err
    assert "runner-only-branch" not in captured.err
    assert not (state / "codex-exec").exists()


def test_extra_git_like_arguments_are_rejected_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    target_repository: git.ValidatedTargetRepository,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        runner,
        "_run_prepare",
        lambda _arguments: pytest.fail("prepare ran with an extra Git-like argument"),
    )
    assert (
        runner.main(
            [
                "prepare",
                "repo-status",
                "--repo",
                os.fspath(target_repository.path),
                "--git-dir=/tmp/hostile",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        f"workflow_failed: {runner.ARGUMENT_ERROR}: {runner.CLI_ARGUMENT_ERROR}\n"
    )


def _initialize_branch_review_test_repo(repo: Path) -> tuple[str, str]:
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet")
    (repo / "safe.py").write_text("value = 1\n", encoding="utf-8")
    _run_test_git(repo, "add", "safe.py")
    _run_test_git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )
    base_commit = _test_git_output(repo, "rev-parse", "HEAD")
    _run_test_git(repo, "branch", "feature/example", base_commit)
    _run_test_git(repo, "tag", "release/v1", base_commit)
    _run_test_git(repo, "branch", "shared/name", base_commit)
    (repo / "safe.py").write_text("value = 2\n", encoding="utf-8")
    _run_test_git(repo, "add", "safe.py")
    _run_test_git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "non-empty branch review",
    )
    tag_commit = _test_git_output(repo, "rev-parse", "HEAD")
    _run_test_git(repo, "tag", "shared/name", tag_commit)
    return base_commit, tag_commit


def test_branch_review_preserves_slash_branch_ref_commit_and_non_yaml_evidence(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    base_commit, _tag_commit = _initialize_branch_review_test_repo(repo)

    snapshot = collect.collect_branch_review(repo, "feature/example", *_collector_deps(repo))
    target_ref = _test_git_output(repo, "symbolic-ref", "HEAD")
    target_head = _test_git_output(repo, "rev-parse", "HEAD")

    assert snapshot.data["base"] == "refs/heads/feature/example"
    assert snapshot.data["base_commit"] == base_commit
    assert snapshot.data["target_ref"] == target_ref
    assert snapshot.data["target_head"] == target_head
    assert snapshot.data["merge_base_commit"] == base_commit
    assert snapshot.data["range_semantics"] == "merge-base-to-target-head"
    assert snapshot.data["deleted_files"] == []
    assert "+value = 2" in str(snapshot.data["diff"])
    assert snapshot.data["file_context"] == [{"path": "safe.py", "content": "value = 2\n"}]
    assert snapshot.branch_review_seal == git.BranchReviewSeal(
        "refs/heads/feature/example",
        base_commit,
        target_ref,
        target_head,
        base_commit,
    )


def test_branch_review_preserves_slash_tag_ref_and_commit(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    base_commit, _tag_commit = _initialize_branch_review_test_repo(repo)

    snapshot = collect.collect_branch_review(repo, "release/v1", *_collector_deps(repo))

    assert snapshot.data["base"] == "refs/tags/release/v1"
    assert snapshot.data["base_commit"] == base_commit


def test_branch_review_same_basename_requires_canonical_ref(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    branch_commit, tag_commit = _initialize_branch_review_test_repo(repo)

    with pytest.raises(security.RunnerError, match="base is ambiguous"):
        collect.collect_branch_review(repo, "shared/name", *_collector_deps(repo))

    branch_snapshot = collect.collect_branch_review(
        repo, "refs/heads/shared/name", *_collector_deps(repo)
    )
    tag_snapshot = collect.collect_branch_review(
        repo, "refs/tags/shared/name", *_collector_deps(repo)
    )
    assert branch_snapshot.data["base"] == "refs/heads/shared/name"
    assert branch_snapshot.data["base_commit"] == branch_commit
    assert tag_snapshot.data["base"] == "refs/tags/shared/name"
    assert tag_snapshot.data["base_commit"] == tag_commit


def _commit_test_changes(repo: Path, message: str) -> str:
    _run_test_git(repo, "add", "-A")
    _run_test_git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        message,
    )
    return _test_git_output(repo, "rev-parse", "HEAD")


def test_branch_review_dirty_worktree_never_changes_sealed_blob_context(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _base_commit, target_head = _initialize_branch_review_test_repo(repo)
    (repo / "safe.py").write_text("DIRTY_WORKTREE_CANARY = True\n", encoding="utf-8")

    snapshot = collect.collect_branch_review(repo, "feature/example", *_collector_deps(repo))

    assert snapshot.data["target_head"] == target_head
    assert snapshot.data["file_context"] == [{"path": "safe.py", "content": "value = 2\n"}]
    assert "DIRTY_WORKTREE_CANARY" not in json.dumps(snapshot.as_envelope())


def test_branch_review_uses_merge_base_when_base_and_target_diverge(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet")
    current_branch = _test_git_output(repo, "symbolic-ref", "--short", "HEAD")
    (repo / "safe.py").write_text("value = 'common'\n", encoding="utf-8")
    common = _commit_test_changes(repo, "common")
    _run_test_git(repo, "branch", "diverged-base", common)
    _run_test_git(repo, "switch", "--quiet", "diverged-base")
    (repo / "base_only.py").write_text("BASE_ONLY_CANARY = True\n", encoding="utf-8")
    base_tip = _commit_test_changes(repo, "base-only commit")
    _run_test_git(repo, "switch", "--quiet", current_branch)
    (repo / "safe.py").write_text("value = 'target'\n", encoding="utf-8")
    target_head = _commit_test_changes(repo, "target-only commit")

    snapshot = collect.collect_branch_review(repo, "diverged-base", *_collector_deps(repo))
    serialized = json.dumps(snapshot.as_envelope())

    assert snapshot.data["base_commit"] == base_tip
    assert snapshot.data["target_head"] == target_head
    assert snapshot.data["merge_base_commit"] == common
    assert "target-only commit" in str(snapshot.data["commits"])
    assert "base-only commit" not in str(snapshot.data["commits"])
    assert "BASE_ONLY_CANARY" not in serialized
    assert snapshot.data["file_context"] == [{"path": "safe.py", "content": "value = 'target'\n"}]


def test_branch_review_deletion_rename_and_binary_use_sealed_metadata(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet")
    (repo / "removed.py").write_text("REMOVED = True\n", encoding="utf-8")
    (repo / "old_name.py").write_text("RENAMED = 'sealed'\n", encoding="utf-8")
    (repo / "asset.bin").write_bytes(b"\x00base\n")
    merge_base = _commit_test_changes(repo, "baseline files")
    _run_test_git(repo, "branch", "comparison-base", merge_base)
    (repo / "removed.py").unlink()
    _run_test_git(repo, "mv", "old_name.py", "new_name.py")
    (repo / "asset.bin").write_bytes(b"\x00target\n")
    target_head = _commit_test_changes(repo, "delete rename binary")
    (repo / "new_name.py").write_text("DIRTY_RENAME_CANARY = True\n", encoding="utf-8")

    snapshot = collect.collect_branch_review(repo, "comparison-base", *_collector_deps(repo))
    removed_oid = _test_git_output(repo, "rev-parse", f"{merge_base}:removed.py")

    assert snapshot.data["merge_base_commit"] == merge_base
    assert snapshot.data["target_head"] == target_head
    assert snapshot.data["deleted_files"] == [
        {
            "path": "removed.py",
            "status": "deleted",
            "blob_oid": removed_oid,
            "blob_size": len(b"REMOVED = True\n"),
            "blob_commit": merge_base,
        }
    ]
    assert snapshot.data["file_context"] == [
        {"path": "new_name.py", "content": "RENAMED = 'sealed'\n"}
    ]
    assert "REMOVED = True" not in str(snapshot.data["diff"])
    assert "REMOVED = True" not in json.dumps(snapshot.as_envelope())
    assert "REMOVED = True" not in json.dumps([gap.as_dict() for gap in snapshot.evidence_gaps])
    assert "DIRTY_RENAME_CANARY" not in json.dumps(snapshot.as_envelope())
    assert "rename from old_name.py" in str(snapshot.data["diff"])
    assert "rename to new_name.py" in str(snapshot.data["diff"])
    assert "asset.bin" not in str(snapshot.data["diff"])
    assert any(
        gap.subject == "asset.bin" and "unsupported file type" in gap.reason
        for gap in snapshot.evidence_gaps
    )


def test_deleted_body_marker_is_absent_from_every_published_artifact_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    _run_test_git(repo, "init", "--quiet", "--initial-branch=main")
    deleted_marker = "DELETED_OLD_BODY_MUST_NEVER_BE_SENT"
    (repo / "removed.py").write_text(f"{deleted_marker} = True\n", encoding="utf-8")
    (repo / "old_name.py").write_text("RENAMED_TARGET = 'sealed'\n", encoding="utf-8")
    merge_base = _commit_test_changes(repo, "baseline for deletion marker")
    _run_test_git(repo, "branch", "comparison-base", merge_base)
    (repo / "removed.py").unlink()
    _run_test_git(repo, "mv", "old_name.py", "new_name.py")
    _commit_test_changes(repo, "delete and rename")
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    target = _validated_test_repository(repo)

    artifact = runner._prepare_snapshot("branch-review", "comparison-base", target, "/usr/bin/git")
    data = artifact.envelope["data"]
    assert isinstance(data, dict)
    assert deleted_marker not in str(data["diff"])
    assert deleted_marker not in json.dumps(data["file_context"])
    assert deleted_marker not in json.dumps(artifact.envelope["evidence_gaps"])
    assert data["deleted_files"][0]["path"] == "removed.py"  # type: ignore[index]
    assert "rename from old_name.py" in str(data["diff"])
    assert "rename to new_name.py" in str(data["diff"])
    assert data["file_context"] == [
        {"path": "new_name.py", "content": "RENAMED_TARGET = 'sealed'\n"}
    ]
    for name in artifact_module.SNAPSHOT_FILE_NAMES:
        assert deleted_marker.encode() not in (artifact.directory / name).read_bytes()


def test_branch_review_rejects_detached_target_head(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _initialize_branch_review_test_repo(repo)
    _run_test_git(repo, "switch", "--quiet", "--detach")
    with pytest.raises(security.RunnerError, match="attached target branch"):
        collect.collect_branch_review(repo, "feature/example", *_collector_deps(repo))


def _branch_prepare_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path, git.ValidatedTargetRepository, str, str, str]:
    repo = tmp_path / "target-repo"
    base_commit, target_head = _initialize_branch_review_test_repo(repo)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    target = _validated_test_repository(repo)
    target_ref = _test_git_output(repo, "symbolic-ref", "HEAD")
    return repo, state, target, base_commit, target_head, target_ref


@pytest.mark.parametrize("mutation", ["base-ref", "target-ref-head"])
def test_branch_review_ref_change_during_collection_fails_without_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    repo, state, target, base_commit, target_head, target_ref = _branch_prepare_target(
        monkeypatch, tmp_path
    )
    original = collect._add_branch_blob_context

    def mutate_after_context(*args: object, **kwargs: object) -> None:
        original(*args, **kwargs)  # type: ignore[arg-type]
        if mutation == "base-ref":
            _run_test_git(repo, "update-ref", "refs/heads/feature/example", target_head)
        else:
            _run_test_git(repo, "update-ref", target_ref, base_commit)

    monkeypatch.setattr(collect, "_add_branch_blob_context", mutate_after_context)
    with pytest.raises(runner.RunnerError, match=f"^{git.BRANCH_REVIEW_STATE_CHANGED_ERROR}$"):
        runner._prepare_snapshot(
            "branch-review",
            "feature/example",
            target,
            "/usr/bin/git",
        )
    assert not (state / "codex-exec").exists()


@pytest.mark.parametrize("changed_path", ["worktree_root", "git_dir", "git_common_dir"])
def test_branch_review_git_identity_change_during_collection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changed_path: str,
) -> None:
    _repo, state, target, _base, _head, _ref = _branch_prepare_target(monkeypatch, tmp_path)
    original = git._validate_git_paths
    changed = False

    def changed_identity(*args: object, **kwargs: object) -> git.RepositoryGitPaths:
        nonlocal changed
        paths = original(*args, **kwargs)  # type: ignore[arg-type]
        if not changed and paths.worktree_root == target.path:
            changed = True
            values = {
                "worktree_root": paths.worktree_root,
                "git_dir": paths.git_dir,
                "git_common_dir": paths.git_common_dir,
            }
            values[changed_path] = tmp_path / f"changed-{changed_path}"
            return git.RepositoryGitPaths(**values)
        return paths

    monkeypatch.setattr(git, "_validate_git_paths", changed_identity)
    with pytest.raises(runner.RunnerError, match=f"^{git.BRANCH_REVIEW_STATE_CHANGED_ERROR}$"):
        runner._prepare_snapshot(
            "branch-review",
            "feature/example",
            target,
            "/usr/bin/git",
        )
    assert not (state / "codex-exec").exists()


def test_branch_review_state_change_after_staging_leaves_no_final_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, state, target, base_commit, _target_head, target_ref = _branch_prepare_target(
        monkeypatch, tmp_path
    )
    original = artifact_module._load_snapshot_directory

    def mutate_after_staging(
        snapshot_id: str,
        directory: Path,
    ) -> artifact_module.SnapshotArtifact:
        artifact = original(snapshot_id, directory)
        _run_test_git(repo, "update-ref", target_ref, base_commit)
        return artifact

    monkeypatch.setattr(artifact_module, "_load_snapshot_directory", mutate_after_staging)
    with pytest.raises(runner.RunnerError, match=f"^{git.BRANCH_REVIEW_STATE_CHANGED_ERROR}$"):
        runner._prepare_snapshot(
            "branch-review",
            "feature/example",
            target,
            "/usr/bin/git",
        )
    snapshot_root = state / "codex-exec" / "snapshots"
    assert snapshot_root.is_dir()
    assert list(snapshot_root.iterdir()) == []


def _replacement_blob(repo: Path, tmp_path: Path) -> tuple[str, str, str]:
    marker = "RACING_REPLACEMENT_BODY_MUST_NOT_PUBLISH"
    body = tmp_path / "replacement-body.py"
    body.write_text(f"{marker} = True\n", encoding="utf-8")
    replacement = _test_git_output(repo, "hash-object", "-w", os.fspath(body))
    target_head = _test_git_output(repo, "rev-parse", "HEAD")
    original = _test_git_output(repo, "rev-parse", f"{target_head}:safe.py")
    return original, replacement, marker


def _assert_state_has_no_marker_or_final_snapshot(state: Path, marker: str) -> None:
    snapshot_root = state / "codex-exec" / "snapshots"
    if snapshot_root.exists():
        assert list(snapshot_root.iterdir()) == []
    for path in state.rglob("*"):
        if path.is_file():
            assert marker.encode() not in path.read_bytes()


def test_replace_ref_created_during_collector_is_detected_without_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, state, target, _base, _head, _ref = _branch_prepare_target(monkeypatch, tmp_path)
    original_oid, replacement_oid, marker = _replacement_blob(repo, tmp_path)
    original_collector = collect._add_branch_blob_context

    def add_replace_after_content(*args: object, **kwargs: object) -> None:
        original_collector(*args, **kwargs)  # type: ignore[arg-type]
        _run_test_git(repo, "replace", original_oid, replacement_oid)

    monkeypatch.setattr(collect, "_add_branch_blob_context", add_replace_after_content)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_REPLACEMENT_REFUSED_ERROR}$",
    ):
        runner._prepare_snapshot("branch-review", "feature/example", target, "/usr/bin/git")
    _assert_state_has_no_marker_or_final_snapshot(state, marker)


def test_replace_ref_created_after_staging_validation_is_detected_before_rename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, state, target, _base, _head, _ref = _branch_prepare_target(monkeypatch, tmp_path)
    original_oid, replacement_oid, marker = _replacement_blob(repo, tmp_path)
    original_load = artifact_module._load_snapshot_directory

    def add_replace_after_staging(
        snapshot_id: str,
        directory: Path,
    ) -> artifact_module.SnapshotArtifact:
        artifact = original_load(snapshot_id, directory)
        _run_test_git(repo, "replace", original_oid, replacement_oid)
        return artifact

    monkeypatch.setattr(artifact_module, "_load_snapshot_directory", add_replace_after_staging)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_REPLACEMENT_REFUSED_ERROR}$",
    ):
        runner._prepare_snapshot("branch-review", "feature/example", target, "/usr/bin/git")
    _assert_state_has_no_marker_or_final_snapshot(state, marker)


def _initialize_git_capability_repo(repo: Path) -> None:
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet")
    (repo / "safe.canary-probe").write_text("safe\n", encoding="utf-8")
    _commit_test_changes(repo, "baseline")


def _clone_local_shallow(source: Path, destination: Path) -> None:
    result = subprocess.run(
        [
            "/usr/bin/git",
            "clone",
            "--quiet",
            "--no-local",
            "--depth=1",
            os.fspath(source),
            os.fspath(destination),
        ],
        cwd="/",
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "raw",
    [b"false", b"false \n", b" false\n", b"false\n\n", b"false\r\n", b"true\n", b"\xff\n"],
)
def test_shallow_state_requires_exact_utf8_false_with_one_terminal_newline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: bytes,
) -> None:
    monkeypatch.setattr(
        git.GitRunner,
        "run",
        lambda *_args, **_kwargs: git.GitResult(raw, b"", 0, False),
    )
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_SHALLOW_REFUSED_ERROR}$",
    ):
        git._shallow_repository_state(git.GitRunner(tmp_path))


def test_shallow_state_accepts_only_exact_false_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        git.GitRunner,
        "run",
        lambda *_args, **_kwargs: git.GitResult(b"false\n", b"", 0, False),
    )
    assert git._shallow_repository_state(git.GitRunner(tmp_path)) is False


def test_legal_local_shallow_clone_fails_before_object_identity_or_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    repo = tmp_path / "shallow-clone"
    _initialize_isolation_repo(source, "main", "SHALLOW_SOURCE_BASE")
    _commit_worktree_marker(source, "second.py", "SHALLOW_SOURCE_HEAD")
    _clone_local_shallow(source, repo)
    assert _test_git_output(repo, "rev-parse", "--is-shallow-repository") == "true"

    observed = _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_SHALLOW_REFUSED_ERROR,
        expect_config_check=False,
    )

    assert ("rev-parse", "--is-shallow-repository") in observed
    assert not list((tmp_path / "state").rglob("snapshot.json"))
    assert not list((tmp_path / "state").rglob("preview.txt"))
    assert not list((tmp_path / "state").rglob("meta.json"))
    assert not list((tmp_path / "state").rglob(".staging-*"))
    assert not (tmp_path / "state" / "codex-exec" / "runs").exists()


@pytest.mark.parametrize("location", ["git-dir", "common-dir", "actual"])
def test_shallow_candidates_in_all_git_locations_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    location: str,
) -> None:
    source = tmp_path / "source"
    repo = tmp_path / "linked"
    _initialize_isolation_repo(source, "base", "BASE")
    _run_test_git(source, "branch", "linked")
    _run_test_git(source, "worktree", "add", "--quiet", os.fspath(repo), "linked")
    git_dir = Path(_test_git_output(repo, "rev-parse", "--absolute-git-dir"))
    common_dir = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    )
    actual = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-path", "shallow")
    )
    shallow = {
        "git-dir": git_dir / "shallow",
        "common-dir": common_dir / "shallow",
        "actual": actual,
    }[location]
    shallow.write_bytes(b"")

    observed = _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_SHALLOW_REFUSED_ERROR,
        expect_config_check=False,
    )
    assert (
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "shallow",
    ) in observed or location != "git-dir"


@pytest.mark.parametrize("kind", ["empty", "symlink", "directory"])
def test_empty_symlink_and_nonregular_shallow_candidates_are_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    shallow = repo / ".git" / "shallow"
    secret = "SHALLOW_CANDIDATE_BODY_MUST_NOT_ESCAPE"
    if kind == "empty":
        shallow.write_bytes(b"")
    elif kind == "symlink":
        outside = tmp_path / "outside-shallow"
        outside.write_text(f"{secret}\n", encoding="utf-8")
        shallow.symlink_to(outside)
    else:
        shallow.mkdir()

    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_SHALLOW_REFUSED_ERROR,
        expect_config_check=False,
    )


def test_shallow_candidate_lstat_failure_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    shallow = repo / ".git" / "shallow"
    original_lstat = Path.lstat

    def denied_lstat(path: Path) -> os.stat_result:
        if path == shallow:
            raise PermissionError("synthetic shallow lstat denial")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", denied_lstat)
    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_SHALLOW_REFUSED_ERROR,
        expect_config_check=False,
    )


@pytest.mark.parametrize("mutation", ["outside", "symlink-parent", "wrong-basename"])
def test_git_resolved_shallow_path_must_have_provable_target_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    git_dir = repo / ".git"
    outside = tmp_path / "outside"
    outside.mkdir()
    if mutation == "outside":
        resolved = outside / "shallow"
    elif mutation == "symlink-parent":
        link = git_dir / "linked-parent"
        link.symlink_to(outside, target_is_directory=True)
        resolved = link / "shallow"
    else:
        resolved = git_dir / "not-shallow"
    original_run = git.GitRunner.run

    def changed_git_path(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        if arguments == ("rev-parse", "--path-format=absolute", "--git-path", "shallow"):
            return git.GitResult(f"{resolved}\n".encode(), b"", 0, False)
        return original_run(self, arguments, maximum=maximum)

    monkeypatch.setattr(git.GitRunner, "run", changed_git_path)
    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_SHALLOW_REFUSED_ERROR,
        expect_config_check=False,
    )


def test_runner_shallow_repository_refuses_every_target_prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner_repo = tmp_path / "runner-repo"
    target_repo = tmp_path / "target-repo"
    _initialize_isolation_repo(runner_repo, "runner", "RUNNER")
    _initialize_isolation_repo(target_repo, "target", "TARGET")
    (runner_repo / ".git" / "shallow").write_bytes(b"")
    monkeypatch.setattr(runner, "REPOSITORY_ROOT", runner_repo)

    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        target_repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_SHALLOW_REFUSED_ERROR,
        expect_config_check=False,
    )


def test_nonshallow_complete_history_capability_control_passes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    _initialize_git_capability_repo(repo)
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    target = _validated_test_repository(repo)

    assert target.capability_fingerprint.shallow.is_shallow_repository is False
    assert target.capability_fingerprint.shallow.actual_path.endswith("/shallow")
    assert target.capability_fingerprint.shallow.candidate_paths
    assert all(
        candidate.state == "absent"
        for candidate in target.capability_fingerprint.shallow.candidate_paths
    )
    assert not (state / "codex-exec").exists()


def _write_external_canary(tmp_path: Path) -> tuple[Path, Path]:
    marker = tmp_path / "EXTERNAL_GIT_PROGRAM_EXECUTED"
    canary = tmp_path / "git-external-canary"
    canary.write_text(
        f"#!/usr/bin/python3\nfrom pathlib import Path\nPath({os.fspath(marker)!r}).touch()\n",
        encoding="utf-8",
    )
    canary.chmod(0o700)
    return canary, marker


def _assert_capability_prepare_rejected_before_content(
    monkeypatch: pytest.MonkeyPatch,
    repo: Path,
    state: Path,
    marker: Path,
    *,
    expected_error: str = git.GIT_CAPABILITY_REFUSED_ERROR,
    expect_config_check: bool = True,
) -> list[tuple[str, ...]]:
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    observed: list[tuple[str, ...]] = []
    content_calls: list[tuple[str, ...]] = []
    original = git.GitRunner.run

    def recording_run(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        observed.append(arguments)
        if (
            arguments[0] in {"status", "diff", "log", "ls-tree", "cat-file"}
            or arguments[0] == "rev-parse"
            and any(argument.endswith("^{commit}") for argument in arguments)
        ):
            content_calls.append(arguments)
        return original(self, arguments, maximum=maximum)

    monkeypatch.setattr(git.GitRunner, "run", recording_run)
    monkeypatch.setattr(
        collect,
        "collect_diff_audit",
        lambda *_args, **_kwargs: pytest.fail("collector ran after capability preflight failure"),
    )
    with pytest.raises(
        security.RunnerError,
        match=f"^{expected_error}$",
    ):
        target = _validated_test_repository(repo)
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")
    assert content_calls == []
    assert not marker.exists()
    assert not (state / "codex-exec").exists()
    config_checked = any(
        arguments[:2] == ("config", "--local") and "--no-includes" in arguments
        for arguments in observed
    )
    assert config_checked is expect_config_check
    return observed


def test_shallow_created_inside_collector_is_detected_without_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, state, target, base_commit, _head, _ref = _branch_prepare_target(monkeypatch, tmp_path)
    shallow = target.target_identity.paths.git_common_dir / "shallow"
    original_collector_step = collect._add_branch_blob_context

    def add_shallow_inside_collector(*args: object, **kwargs: object) -> None:
        original_collector_step(*args, **kwargs)  # type: ignore[arg-type]
        shallow.write_text(f"{base_commit}\n", encoding="ascii")

    monkeypatch.setattr(collect, "_add_branch_blob_context", add_shallow_inside_collector)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_SHALLOW_REFUSED_ERROR}$",
    ):
        runner._prepare_snapshot("branch-review", "feature/example", target, "/usr/bin/git")
    _assert_state_has_no_marker_or_final_snapshot(state, base_commit)
    assert not list(state.rglob(".staging-*"))
    assert not (state / "codex-exec" / "runs").exists()


def test_shallow_created_after_collector_is_detected_without_artifact(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    shallow = target_repository.target_identity.paths.git_common_dir / "shallow"
    marker = "POST_COLLECTOR_SHALLOW_BODY_MUST_NOT_PUBLISH"

    def collect_then_add_shallow(*_args: object, **_kwargs: object) -> collect.Snapshot:
        snapshot = _safe_snapshot()
        shallow.write_text(f"{marker}\n", encoding="utf-8")
        return snapshot

    monkeypatch.setattr(collect, "collect_repo_status", collect_then_add_shallow)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_SHALLOW_REFUSED_ERROR}$",
    ):
        runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")
    _assert_state_has_no_marker_or_final_snapshot(private_state, marker)
    assert not list(private_state.rglob(".staging-*"))
    assert not (private_state / "codex-exec" / "runs").exists()


def test_shallow_created_after_staging_validation_is_detected_before_rename(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    shallow = target_repository.target_identity.paths.git_common_dir / "shallow"
    marker = "STAGED_SHALLOW_BODY_MUST_NOT_PUBLISH"
    original_load = artifact_module._load_snapshot_directory
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: _safe_snapshot())

    def load_then_add_shallow(
        snapshot_id: str,
        directory: Path,
    ) -> artifact_module.SnapshotArtifact:
        artifact = original_load(snapshot_id, directory)
        shallow.write_text(f"{marker}\n", encoding="utf-8")
        return artifact

    monkeypatch.setattr(artifact_module, "_load_snapshot_directory", load_then_add_shallow)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_SHALLOW_REFUSED_ERROR}$",
    ):
        runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")
    _assert_state_has_no_marker_or_final_snapshot(private_state, marker)
    assert not list(private_state.rglob(".staging-*"))
    assert not (private_state / "codex-exec" / "runs").exists()


def _prepare_conversion_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    repo: Path,
    state: Path,
    *,
    task: str = "diff-audit",
    task_argument: str | None = None,
) -> tuple[artifact_module.SnapshotArtifact, dict[str, object]]:
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    target = _validated_test_repository(repo)
    artifact = runner._prepare_snapshot(task, task_argument, target, "/usr/bin/git")
    return artifact, json.loads(artifact.snapshot_bytes)


def test_harmless_git_attributes_preserve_existing_diff_audit_behavior(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    attributes = repo / ".gitattributes"
    attributes.write_text("*.canary-probe -text whitespace=cr-at-eol\n", encoding="utf-8")
    _commit_test_changes(repo, "tracked harmless attributes")

    artifact, payload = _prepare_conversion_snapshot(monkeypatch, repo, tmp_path / "state")

    assert artifact.directory.is_dir()
    assert "conversion_safety" not in payload["data"]  # type: ignore[operator]
    assert payload["truncated"] is False


def test_external_conversions_are_disabled_and_affected_file_is_degraded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    (repo / "ordinary.txt").write_text("ordinary baseline\n", encoding="utf-8")
    (repo / ".gitattributes").write_text(
        "*.canary-probe filter=canary diff=canary\n",
        encoding="utf-8",
    )
    _commit_test_changes(repo, "conversion fixture")
    canary, marker = _write_external_canary(tmp_path)
    for key in (
        "filter.canary.clean",
        "filter.canary.smudge",
        "filter.canary.process",
        "diff.canary.command",
        "diff.canary.textconv",
    ):
        _run_test_git(repo, "config", "--local", key, os.fspath(canary))
    _run_test_git(repo, "config", "--local", "filter.canary.required", "true")
    (repo / "safe.canary-probe").write_text("affected changed\n", encoding="utf-8")
    (repo / "ordinary.txt").write_text("ordinary changed\n", encoding="utf-8")

    artifact, payload = _prepare_conversion_snapshot(monkeypatch, repo, tmp_path / "state")

    assert not marker.exists()
    data = payload["data"]
    assert isinstance(data, dict)
    assert "+ordinary changed" in data["unstaged_diff"]
    assert "+affected changed" not in data["unstaged_diff"]
    safety = data["conversion_safety"]
    assert isinstance(safety, dict)
    assert safety["external_commands_executed"] is False
    assert safety["content_diff_complete"] is False
    files = safety["files"]
    assert isinstance(files, list) and len(files) == 1
    affected = files[0]
    assert affected["path"] == "safe.canary-probe"
    assert affected["tracked"] is True
    assert affected["untracked"] is False
    assert affected["staged_status"] == "unchanged"
    assert affected["unstaged_status"] == "raw_changed"
    assert affected["old_blob_oid"] == affected["new_blob_oid"]
    assert isinstance(affected["worktree_size"], int)
    assert affected["conversion_required"] is True
    assert affected["raw_content_captured"] is False
    assert {
        "clean_filter",
        "smudge_filter",
        "process_filter",
        "required_filter",
        "external_diff_driver",
        "textconv",
        "content_filter_attribute",
    } <= set(affected["disabled_types"])
    assert payload["truncated"] is True
    gaps = payload["evidence_gaps"]
    assert any(
        gap["kind"] == "external_conversion_disabled" and gap["subject"] == "safe.canary-probe"
        for gap in gaps
    )
    preview = (artifact.directory / "preview.txt").read_bytes()
    assert b"conversion_safety" not in preview
    assert b"ordinary changed" not in preview
    assert b"incomplete=yes" in preview


def test_global_external_diff_is_disabled_but_raw_diff_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    (repo / "ordinary.txt").write_text("ordinary baseline\n", encoding="utf-8")
    _commit_test_changes(repo, "ordinary baseline")
    canary, marker = _write_external_canary(tmp_path)
    _run_test_git(repo, "config", "--local", "diff.external", os.fspath(canary))
    (repo / "ordinary.txt").write_text("raw external diff change\n", encoding="utf-8")

    _artifact, payload = _prepare_conversion_snapshot(monkeypatch, repo, tmp_path / "state")

    assert not marker.exists()
    data = payload["data"]
    assert "+raw external diff change" in data["unstaged_diff"]  # type: ignore[index]
    files = data["conversion_safety"]["files"]  # type: ignore[index]
    assert files[0]["path"] == "ordinary.txt"
    assert "external_diff" in files[0]["disabled_types"]


def test_external_attributes_file_is_ignored_without_executing_filter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    (repo / "ordinary.txt").write_text("ordinary baseline\n", encoding="utf-8")
    _commit_test_changes(repo, "ordinary baseline")
    canary, marker = _write_external_canary(tmp_path)
    attributes = tmp_path / "external-attributes"
    attributes.write_text("*.txt filter=canary\n", encoding="utf-8")
    _run_test_git(repo, "config", "--local", "core.attributesFile", os.fspath(attributes))
    _run_test_git(repo, "config", "--local", "filter.canary.clean", os.fspath(canary))
    (repo / "ordinary.txt").write_text("raw attributes change\n", encoding="utf-8")

    _artifact, payload = _prepare_conversion_snapshot(monkeypatch, repo, tmp_path / "state")

    assert not marker.exists()
    safety = payload["data"]["conversion_safety"]  # type: ignore[index]
    assert safety["content_diff_complete"] is True
    assert safety["files"] == []
    assert "external_attributes_file" in safety["disabled_config_types"]


@pytest.mark.parametrize("source", ["info-attributes", "worktree-config"])
def test_repo_status_disables_indirect_content_filters(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source: str,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    canary, marker = _write_external_canary(tmp_path)
    if source == "info-attributes":
        (repo / ".git" / "info" / "attributes").write_text(
            "*.canary-probe filter=canary\n",
            encoding="utf-8",
        )
        _run_test_git(repo, "config", "--local", "filter.canary.process", os.fspath(canary))
    else:
        (repo / ".gitattributes").write_text(
            "*.canary-probe filter=canary\n",
            encoding="utf-8",
        )
        _commit_test_changes(repo, "worktree filter attributes")
        _run_test_git(repo, "config", "--local", "extensions.worktreeConfig", "true")
        _run_test_git(
            repo,
            "config",
            "--worktree",
            "filter.canary.process",
            os.fspath(canary),
        )
    (repo / "safe.canary-probe").write_text("repo status changed\n", encoding="utf-8")

    _artifact, payload = _prepare_conversion_snapshot(
        monkeypatch,
        repo,
        tmp_path / "state",
        task="repo-status",
    )

    assert not marker.exists()
    data = payload["data"]
    assert "safe.canary-probe" in data["status_short"]  # type: ignore[index]
    safety = data["conversion_safety"]  # type: ignore[index]
    assert safety["external_commands_executed"] is False
    assert safety["files"][0]["path"] == "safe.canary-probe"
    assert "process_filter" in safety["files"][0]["disabled_types"]


def test_branch_review_disables_external_diff_and_preserves_raw_patch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    base_commit, _target_head = _initialize_branch_review_test_repo(repo)
    canary, marker = _write_external_canary(tmp_path)
    _run_test_git(repo, "config", "--local", "diff.external", os.fspath(canary))

    _artifact, payload = _prepare_conversion_snapshot(
        monkeypatch,
        repo,
        tmp_path / "state",
        task="branch-review",
        task_argument="feature/example",
    )

    assert not marker.exists()
    data = payload["data"]
    assert data["merge_base_commit"] == base_commit  # type: ignore[index]
    assert "+value = 2" in data["diff"]  # type: ignore[index]
    safety = data["conversion_safety"]  # type: ignore[index]
    assert safety["external_commands_executed"] is False
    assert safety["content_diff_complete"] is False
    assert safety["files"][0]["path"] == "safe.py"
    assert safety["files"][0]["old_blob_oid"] != safety["files"][0]["new_blob_oid"]
    assert "external_diff" in safety["files"][0]["disabled_types"]


@pytest.mark.parametrize("capability", ["include", "include-if"])
def test_git_capability_config_includes_still_fail_closed_before_collectors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capability: str,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    canary, marker = _write_external_canary(tmp_path)
    included = tmp_path / "included.gitconfig"
    included.write_text(
        f'[filter "canary"]\n\tclean = {os.fspath(canary)}\n',
        encoding="utf-8",
    )
    key = "include.path" if capability == "include" else "includeIf.onbranch:main.path"
    _run_test_git(repo, "config", "--local", key, os.fspath(included))

    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        marker,
    )


def test_core_fsmonitor_still_fails_closed_before_collectors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    canary, marker = _write_external_canary(tmp_path)
    _run_test_git(repo, "config", "--local", "core.fsmonitor", os.fspath(canary))

    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        marker,
    )


def _object_store_manifest(repo: Path) -> tuple[tuple[str, str, int, str], ...]:
    object_directory = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-path", "objects")
    )
    entries: list[tuple[str, str, int, str]] = []
    for path in sorted(object_directory.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(object_directory).as_posix()
        if stat.S_ISREG(metadata.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append((relative, "regular", metadata.st_size, digest))
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            entries.append(
                (relative, "symlink", metadata.st_size, hashlib.sha256(target).hexdigest())
            )
    return tuple(entries)


def _loose_object_path(repo: Path, object_id: str) -> Path:
    object_directory = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-path", "objects")
    )
    return object_directory / object_id[:2] / object_id[2:]


def _write_git_program_canary(tmp_path: Path, name: str) -> tuple[Path, Path]:
    marker = tmp_path / f"{name}.executed"
    program = tmp_path / name
    program.write_text(
        "#!/usr/bin/python3\n"
        "from pathlib import Path\n"
        f"Path({os.fspath(marker)!r}).touch()\n"
        "raise SystemExit(91)\n",
        encoding="utf-8",
    )
    program.chmod(0o700)
    return program, marker


def _initialize_replace_test_repo(repo: Path) -> tuple[dict[str, str], str]:
    _base, target_head = _initialize_branch_review_test_repo(repo)
    target_branch = _test_git_output(repo, "symbolic-ref", "--short", "HEAD")
    original = {
        "commit": target_head,
        "tree": _test_git_output(repo, "rev-parse", f"{target_head}^{{tree}}"),
        "blob": _test_git_output(repo, "rev-parse", f"{target_head}:safe.py"),
    }
    _run_test_git(repo, "switch", "--quiet", "-c", "replacement-fixture")
    replacement_marker = "REPLACEMENT_OBJECT_BODY_MARKER"
    (repo / "safe.py").write_text(f"{replacement_marker} = True\n", encoding="utf-8")
    replacement_commit = _commit_test_changes(repo, "replacement object marker")
    replacement = {
        "commit": replacement_commit,
        "tree": _test_git_output(repo, "rev-parse", f"{replacement_commit}^{{tree}}"),
        "blob": _test_git_output(repo, "rev-parse", f"{replacement_commit}:safe.py"),
    }
    _run_test_git(repo, "switch", "--quiet", target_branch)
    return {f"original_{key}": value for key, value in original.items()} | {
        f"replacement_{key}": value for key, value in replacement.items()
    }, replacement_marker


def test_test_triage_skips_object_capabilities_without_running_converter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo = tmp_path / "repo"
    object_ids, replacement_marker = _initialize_replace_test_repo(repo)
    _run_test_git(
        repo,
        "replace",
        object_ids["original_commit"],
        object_ids["replacement_commit"],
    )
    converter, converter_marker = _write_external_canary(tmp_path)
    _run_test_git(repo, "config", "diff.canary.command", os.fspath(converter))
    (repo / ".gitattributes").write_text("*.log diff=canary\n", encoding="utf-8")
    (repo / "safe.log").write_text("FAILED synthetic test\n", encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))

    assert runner.main(["prepare", "test-triage", "--repo", os.fspath(repo), "safe.log"]) == 0
    triage_output = capsys.readouterr()
    assert triage_output.err == ""
    assert converter_marker.exists() is False
    directories = list((state / "codex-exec" / "snapshots").iterdir())
    assert len(directories) == 1
    artifact_bytes = (directories[0] / "snapshot.json").read_bytes()
    assert b"FAILED synthetic test" in artifact_bytes
    assert replacement_marker.encode() not in artifact_bytes

    assert runner.main(["prepare", "diff-audit", "--repo", os.fspath(repo)]) == 2
    refusal = capsys.readouterr()
    assert refusal.out == ""
    assert git.GIT_REPLACEMENT_REFUSED_ERROR in refusal.err
    assert converter_marker.exists() is False
    assert list((state / "codex-exec" / "snapshots").iterdir()) == directories


@pytest.mark.parametrize("object_type", ["commit", "tree", "blob"])
def test_replace_refs_are_disabled_and_refused_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    object_type: str,
) -> None:
    repo = tmp_path / "repo"
    object_ids, replacement_marker = _initialize_replace_test_repo(repo)
    original_id = object_ids[f"original_{object_type}"]
    replacement_id = object_ids[f"replacement_{object_type}"]
    git_runner = git.GitRunner(repo)
    original_body = git_runner.run(("cat-file", object_type, original_id))
    assert original_body.returncode == 0 and not original_body.truncated
    _run_test_git(repo, "replace", original_id, replacement_id)

    protected_body = git_runner.run(("cat-file", object_type, original_id))
    assert protected_body.returncode == 0
    assert protected_body.stdout == original_body.stdout
    assert replacement_marker.encode() not in protected_body.stdout

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    observed: list[tuple[str, ...]] = []
    original_run = git.GitRunner.run

    def recording_run(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        observed.append(arguments)
        return original_run(self, arguments, maximum=maximum)

    monkeypatch.setattr(git.GitRunner, "run", recording_run)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.GIT_REPLACEMENT_REFUSED_ERROR}$",
    ) as raised:
        _validated_test_repository(repo)
    assert replacement_marker not in str(raised.value)
    assert not (state / "codex-exec").exists()
    replace_queries = [arguments for arguments in observed if arguments[0] == "for-each-ref"]
    assert replace_queries
    assert all(arguments[-1] == "refs/replace/" for arguments in replace_queries)
    assert not any("refs/heads" in argument for arguments in observed for argument in arguments)


@pytest.mark.parametrize("graft_location", ["worktree", "common", "actual"])
def test_graft_files_in_all_git_locations_fail_closed_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    graft_location: str,
) -> None:
    source = tmp_path / "source"
    repo = tmp_path / "linked"
    _initialize_isolation_repo(source, "base", "BASE")
    _run_test_git(source, "branch", "linked")
    _run_test_git(source, "worktree", "add", "--quiet", os.fspath(repo), "linked")
    git_dir = Path(_test_git_output(repo, "rev-parse", "--absolute-git-dir"))
    common_dir = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    )
    actual = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
    )
    graft = {
        "worktree": git_dir / "info" / "grafts",
        "common": common_dir / "info" / "grafts",
        "actual": actual,
    }[graft_location]
    graft.parent.mkdir(parents=True, exist_ok=True)
    graft.write_text("GRAFT_BODY_MUST_NOT_READ\n", encoding="utf-8")
    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_REPLACEMENT_REFUSED_ERROR,
        expect_config_check=False,
    )


@pytest.mark.parametrize("alternate_name", ["alternates", "http-alternates"])
def test_repository_alternate_object_databases_fail_closed_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    alternate_name: str,
) -> None:
    repo = tmp_path / "repo"
    external = tmp_path / "external"
    _initialize_git_capability_repo(repo)
    _initialize_isolation_repo(external, "external", "EXTERNAL_ALTERNATE_BODY_CANARY")
    common_dir = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    )
    alternate = common_dir / "objects" / "info" / alternate_name
    alternate.parent.mkdir(parents=True, exist_ok=True)
    if alternate_name == "alternates":
        external_objects = _test_git_output(
            external, "rev-parse", "--path-format=absolute", "--git-path", "objects"
        )
        alternate.write_text(f"{external_objects}\n", encoding="utf-8")
    else:
        alternate.write_text("https://invalid.example/objects\n", encoding="utf-8")
    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_ALTERNATE_OBJECTS_REFUSED_ERROR,
        expect_config_check=False,
    )


def test_host_object_database_injection_cannot_supply_missing_external_objects(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    repo = tmp_path / "repo"
    external_head = _initialize_isolation_repo(
        external, "external", "EXTERNAL_OBJECT_BODY_MUST_NOT_ENTER_ARTIFACT"
    )
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet", "--initial-branch=main")
    reference = repo / ".git" / "refs" / "heads" / "main"
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text(f"{external_head}\n", encoding="ascii")
    external_objects = _test_git_output(
        external, "rev-parse", "--path-format=absolute", "--git-path", "objects"
    )
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", external_objects)
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", external_objects)
    with pytest.raises(runner.RunnerError, match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$"):
        _validated_test_repository(repo)
    assert not (state / "codex-exec").exists()


def _configure_promisor_canaries(
    repo: Path,
    tmp_path: Path,
    config_key: str,
) -> tuple[Path, ...]:
    remote_helper, remote_marker = _write_git_program_canary(tmp_path, "remote-helper-canary")
    credential_helper, credential_marker = _write_git_program_canary(
        tmp_path, "credential-helper-canary"
    )
    transport, transport_marker = _write_git_program_canary(tmp_path, "transport-canary")
    _run_test_git(repo, "config", "--local", "remote.canary.url", f"ext::{transport}")
    _run_test_git(repo, "config", "--local", "remote.canary.uploadpack", os.fspath(remote_helper))
    _run_test_git(repo, "config", "--local", "credential.helper", os.fspath(credential_helper))
    _run_test_git(repo, "config", "--local", "protocol.ext.allow", "always")
    values = {
        "extensions.partialClone": "canary",
        "remote.Canary.promisor": "true",
        "remote.Canary.partialCloneFilter": "blob:none",
    }
    _run_test_git(repo, "config", "--local", config_key, values[config_key])
    return remote_marker, credential_marker, transport_marker


@pytest.mark.parametrize("missing_kind", ["commit", "tree", "blob"])
@pytest.mark.parametrize(
    "config_key",
    ["extensions.partialClone", "remote.Canary.promisor", "remote.Canary.partialCloneFilter"],
)
def test_promisor_repositories_with_missing_objects_fail_before_object_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    missing_kind: str,
    config_key: str,
) -> None:
    repo = tmp_path / "repo"
    _base, target_head = _initialize_branch_review_test_repo(repo)
    object_ids = {
        "commit": target_head,
        "tree": _test_git_output(repo, "rev-parse", f"{target_head}^{{tree}}"),
        "blob": _test_git_output(repo, "rev-parse", f"{target_head}:safe.py"),
    }
    omitted = _loose_object_path(repo, object_ids[missing_kind])
    assert omitted.is_file()
    stash = tmp_path / "omitted-object"
    omitted.rename(stash)
    markers = _configure_promisor_canaries(repo, tmp_path, config_key)
    before = _object_store_manifest(repo)
    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        markers[-1],
        expected_error=git.GIT_PROMISOR_REFUSED_ERROR,
    )
    assert _object_store_manifest(repo) == before
    assert sum(marker.exists() for marker in markers) == 0
    assert not (tmp_path / "state" / "codex-exec" / "runs").exists()


def test_git_no_lazy_fetch_is_independent_of_promisor_preflight(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _base, target_head = _initialize_branch_review_test_repo(repo)
    blob_id = _test_git_output(repo, "rev-parse", f"{target_head}:safe.py")
    omitted = _loose_object_path(repo, blob_id)
    assert omitted.is_file()
    omitted.rename(tmp_path / "omitted-blob")
    markers = _configure_promisor_canaries(repo, tmp_path, "extensions.partialClone")
    before = _object_store_manifest(repo)

    result = git.GitRunner(repo).run(("cat-file", "blob", blob_id))

    assert result.returncode != 0
    assert _object_store_manifest(repo) == before
    assert sum(marker.exists() for marker in markers) == 0


def test_promisor_pack_marker_fails_closed_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    _initialize_git_capability_repo(repo)
    object_directory = Path(
        _test_git_output(repo, "rev-parse", "--path-format=absolute", "--git-path", "objects")
    )
    marker = object_directory / "pack" / "synthetic.promisor"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"")
    _assert_capability_prepare_rejected_before_content(
        monkeypatch,
        repo,
        tmp_path / "state",
        tmp_path / "MUST_NOT_EXIST",
        expected_error=git.GIT_PROMISOR_REFUSED_ERROR,
        expect_config_check=False,
    )


def _initialize_yaml_test_repo(repo: Path) -> None:
    repo.mkdir()
    _run_test_git(repo, "init", "--quiet")
    (repo / "config.yaml").write_text("safe: before\n", encoding="utf-8")
    (repo / "safe.py").write_text("value = 1\n", encoding="utf-8")
    _run_test_git(repo, "add", "config.yaml", "safe.py")
    _run_test_git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "baseline",
    )


@pytest.mark.parametrize("change_kind", ["staged", "unstaged", "untracked"])
@pytest.mark.parametrize("task", ["repo-status", "diff-audit"])
def test_prepare_refuses_yaml_workspace_changes_before_diff_or_file_content_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    change_kind: str,
    task: str,
) -> None:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    _initialize_yaml_test_repo(repo)
    marker = "SYNTHETIC_YAML_ARTIFACT_MARKER"
    if change_kind == "untracked":
        (repo / "untracked.yml").write_text(f"password: {marker}\n", encoding="utf-8")
    else:
        (repo / "config.yaml").write_text(f"password: {marker}\n", encoding="utf-8")
        if change_kind == "staged":
            _run_test_git(repo, "add", "config.yaml")

    observed_git_argv: list[tuple[str, ...]] = []
    original_run = git.GitRunner.run

    def recording_run(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        observed_git_argv.append(arguments)
        return original_run(self, arguments, maximum=maximum)

    monkeypatch.setattr(git.GitRunner, "run", recording_run)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    target = _validated_test_repository(repo)
    with pytest.raises(security.RunnerError, match=f"^{security.YAML_CONTENT_REFUSED}$"):
        runner._prepare_snapshot(task, None, target, "/usr/bin/git")
    assert observed_git_argv
    assert all(
        arguments[0] != "diff" or "--name-only" in arguments for arguments in observed_git_argv
    )
    assert not (state / "codex-exec").exists()
    assert marker.encode() not in b"".join(
        path.read_bytes() for path in state.rglob("*") if path.is_file()
    )


def test_truncated_git_diff_is_rejected_even_at_a_structural_boundary() -> None:
    builder = collect.SnapshotBuilder("diff-audit", PROJECT_ROOT.name, PROJECT_ROOT)
    result = git.GitResult(
        b"diff --git a/safe.py b/safe.py\n",
        b"",
        returncode=-9,
        truncated=True,
    )
    with pytest.raises(security.RunnerError, match="truncated unified diff"):
        collect._decode_unified_diff(result, "staged-diff", builder)


@pytest.mark.parametrize(
    "raw",
    [
        "diff --git a/config.yaml b/module.py\n",
        "diff --git a/file.bin b/file.bin\n",
        (
            "diff --git a/config.yaml b/config.yaml\n"
            "--- a/config.yaml\n"
            "+++ b/config.yaml\n"
            "@@ -1,2 +1,2 @@\n"
            "-safe: old\n"
            "+safe: new\n"
        ),
        (
            "diff --git a/config.yaml b/config.yaml\n"
            "--- a/config.yaml\n"
            "+++ b/config.yaml\n"
            "@@ -1 +1 @@\n"
            "-safe: old\n"
            f"+safe: {{password: {C01_MARKER}\n"
        ),
        "not a diff\n",
        'diff --git "a/space name.py" "b/space name.py\n',
    ],
)
def test_unified_diff_malformed_or_unprovable_inputs_fail_at_every_boundary(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
    raw: str,
) -> None:
    with pytest.raises(security.SecurityError):
        security.sanitize_text(raw, scan_mode=security.ScanMode.UNIFIED_DIFF)

    builder = collect.SnapshotBuilder("diff-audit", PROJECT_ROOT.name, PROJECT_ROOT)
    with pytest.raises(security.RunnerError):
        builder.add_text(
            "staged_diff",
            raw,
            source="synthetic-diff",
            scan_mode=security.ScanMode.UNIFIED_DIFF,
        )

    snapshot = _snapshot_with_diff(raw)
    monkeypatch.setattr(collect, "collect_diff_audit", lambda *_args, **_kwargs: snapshot)
    with pytest.raises(runner.RunnerError) as raised:
        runner._prepare_snapshot("diff-audit", None, target_repository, "/usr/bin/git")
    assert C01_MARKER not in str(raised.value)
    assert not list(private_state.rglob(".staging-*"))
    for path in private_state.rglob("*"):
        if path.is_file():
            assert C01_MARKER.encode() not in path.read_bytes()


def test_prepare_rejects_collector_and_schema_scan_manifest_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    private_state: Path,
    target_repository: git.ValidatedTargetRepository,
) -> None:
    snapshot = _safe_snapshot()
    bindings = list(snapshot.scan_manifest.bindings)
    first = bindings[0]
    bindings[0] = security.ScanModeBinding(first.path, security.ScanMode.UNIFIED_DIFF)
    snapshot.scan_manifest = security.ScanModeManifest(
        security.SCAN_CLASSIFIER_VERSION, tuple(bindings)
    )
    monkeypatch.setattr(collect, "collect_repo_status", lambda *_args, **_kwargs: snapshot)
    with pytest.raises(runner.RunnerError, match="manifest"):
        runner._prepare_snapshot("repo-status", None, target_repository, "/usr/bin/git")
    assert not list(private_state.rglob(".staging-*"))


@pytest.mark.parametrize(
    "raw",
    [
        "password: |\n  SYNTHETIC_SECRET",
        "password: >\n  SYNTHETIC_SECRET",
        "password: |-\n  SYNTHETIC_SECRET",
        "password: >+ # comment\n  SYNTHETIC_SECRET",
        "clientSecret: |2+\n    SYNTHETIC_SECRET",
        "refresh-token: >-2 # comment\n    SYNTHETIC_SECRET",
        "- password: |2-\n    SYNTHETIC_SECRET",
        "password: SYNTHETIC\n  SECRET",
        "- password: SYNTHETIC\n  SECRET",
        "{password: SYNTHETIC_SECRET}",
        "? password\n: SYNTHETIC_SECRET",
        "{? password: SYNTHETIC_SECRET}",
        "password: [REDACTED]\n  SYNTHETIC_SECRET",
    ],
)
def test_yaml_block_scalar_variants_fail_closed(raw: str) -> None:
    with pytest.raises(
        security.SecurityError, match=f"^{security.YAML_CONTENT_REFUSED}$"
    ) as raised:
        security.classify_scan_mode("synthetic.yaml")
    assert raw not in str(raised.value)


@pytest.mark.parametrize(
    "raw",
    [
        _synthetic_pem_boundary("BEGIN"),
        _synthetic_pem_boundary("END"),
        _synthetic_pem_boundary("BEGIN") + "\nSYNTHETIC PARTIAL BODY",
        "private_key_re='-----BEGIN ([A-Z0-9]+[[:space:]]+)*PRIVATE KEY-----'",
        r'PRIVATE_KEY_RE = r"-----BEGIN (?:RSA )?PRIVATE KEY-----"',
        "# Example: -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY-----",
        (_synthetic_pem_boundary("BEGIN") + "\nSYNTHETIC BODY\n" + "-----END RSA PRIVATE KEY-----"),
        '{"accessToken":\n"SYNTHETIC_SECRET"}',
        "tool --client-secret 'SYNTHETIC_SECRET",
        'ACCESS_TOKEN="SYNTHETIC_SECRET',
        '{"clientSecret":{"nested":"SYNTHETIC_SECRET"}}',
    ],
)
def test_isolated_pem_and_credential_like_examples_are_plain_text(raw: str) -> None:
    assert security.sanitize_text(raw, scan_mode=security.ScanMode.PLAIN_TEXT).text == raw


def test_pem_detection_literal_is_preserved_in_file_context_and_unified_diff() -> None:
    literal = "private_key_re='-----BEGIN ([A-Z0-9]+[[:space:]]+)*PRIVATE KEY-----'"
    snapshot = _snapshot_with_file_context(literal, "scanner.py")
    envelope = artifact_module._sanitize_validate_snapshot(
        snapshot.as_envelope(),
        PROJECT_ROOT,
        expected_scan_manifest=snapshot.scan_manifest,
    )
    assert envelope["data"]["file_context"] == [{"path": "scanner.py", "content": literal}]

    diff = _synthetic_diff("scanner", literal, literal + " # unchanged detector")
    sanitized = security.sanitize_text(diff, scan_mode=security.ScanMode.UNIFIED_DIFF)
    assert literal in sanitized.text
    assert "unchanged detector" in sanitized.text


@pytest.mark.parametrize("relative_path", ["private.pem", "private.key", ".env.local"])
def test_high_risk_repository_paths_remain_refused(relative_path: str) -> None:
    assert security.is_sensitive_repository_path(relative_path)
    assert not security.is_relevant_text_path(relative_path)


def test_recursive_sanitizer_handles_keys_values_and_tuples() -> None:
    token = "sk-proj-" + "C" * 24
    value = {
        "Authorization: Bearer abcdefghijklmnop": (
            token,
            {"note": "ordinary credential-like prose"},
        )
    }
    sanitized = security.sanitize_json_value(value, scan_mode=security.ScanMode.PLAIN_TEXT)
    encoded = json.dumps(sanitized)
    assert isinstance(next(iter(sanitized.values())), list)  # type: ignore[union-attr]
    assert "abcdefghijklmnop" not in encoded
    assert token not in encoded
    assert "ordinary credential-like prose" in encoded


@pytest.mark.parametrize(
    "value",
    [
        {1: "value"},
        b"bytes",
        Path("relative"),
        {"set"},
        object(),
        math.nan,
        math.inf,
    ],
)
def test_recursive_sanitizer_rejects_unsupported_values(value: object) -> None:
    with pytest.raises(security.SecurityError):
        security.sanitize_json_value(value, scan_mode=security.ScanMode.PLAIN_TEXT)


def test_recursive_sanitizer_enforces_depth_elements_and_key_collisions() -> None:
    nested: object = "leaf"
    for _index in range(34):
        nested = [nested]
    with pytest.raises(security.SecurityError, match="depth"):
        security.sanitize_json_value(nested, scan_mode=security.ScanMode.PLAIN_TEXT)
    at_limit = security.sanitize_json_value(
        list(range(9_999)), scan_mode=security.ScanMode.PLAIN_TEXT
    )
    assert isinstance(at_limit, list) and len(at_limit) == 9_999
    with pytest.raises(security.SecurityError, match="element"):
        security.sanitize_json_value(list(range(10_001)), scan_mode=security.ScanMode.PLAIN_TEXT)
    colliding = {
        "Authorization: Bearer abcdefghijklmnop": "first",
        "Authorization: Bearer zyxwvutsrqponmlk": "second",
    }
    with pytest.raises(security.SecurityError, match="collide"):
        security.sanitize_json_value(colliding, scan_mode=security.ScanMode.PLAIN_TEXT)


def _extensionless_diff_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path, git.ValidatedTargetRepository]:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    _initialize_git_capability_repo(repo)
    (repo / "CURRENT").write_text("generation-old\n", encoding="utf-8")
    (repo / "operations.py").write_text(
        'METADATA = {"signature": {"arity": 1}}\n', encoding="utf-8"
    )
    _commit_test_changes(repo, "extensionless baseline")
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return repo, state, _validated_test_repository(repo)


def _bounded_text_diff_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path, git.ValidatedTargetRepository]:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    _initialize_git_capability_repo(repo)
    (repo / ".gitattributes").write_text("*.md text\n", encoding="utf-8")
    (repo / "audit.csv").write_text("name,value\nold,1\n", encoding="utf-8")
    _commit_test_changes(repo, "bounded text baseline")
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return repo, state, _validated_test_repository(repo)


def test_diff_audit_accepts_safe_gitattributes_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    (repo / ".gitattributes").write_text("*.md text\n*.csv -text\n", encoding="utf-8")

    artifact = runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    payload = json.loads(artifact.snapshot_bytes)
    unstaged = payload["data"]["unstaged_diff"]
    assert "diff --git a/.gitattributes b/.gitattributes" in unstaged
    assert "+*.csv -text" in unstaged
    assert any(context["path"] == ".gitattributes" for context in payload["data"]["file_context"])


@pytest.mark.parametrize(
    "raw",
    [
        b"*.md text\0invalid\n",
        b"*.md text\n\xff\n",
        b"x" * (security.MAX_EXTENSIONLESS_TEXT_BYTES + 1),
    ],
    ids=("nul", "encoding", "size"),
)
def test_diff_audit_rejects_unsafe_gitattributes_content(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: bytes,
) -> None:
    repo, state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    (repo / ".gitattributes").write_bytes(raw)

    with pytest.raises(
        security.RunnerError,
        match="sanitize unstaged-diff|Git conversion attribute inspection failed closed",
    ):
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert not (state / "codex-exec").exists()


@pytest.mark.parametrize("staged", [False, True], ids=("unstaged", "staged"))
def test_diff_audit_accepts_safe_csv_text(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    staged: bool,
) -> None:
    repo, _state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    (repo / "audit.csv").write_text("name,value\nnew,2\n", encoding="utf-8")
    if staged:
        _run_test_git(repo, "add", "--", "audit.csv")

    artifact = runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    payload = json.loads(artifact.snapshot_bytes)
    diff_name = "staged_diff" if staged else "unstaged_diff"
    other_diff_name = "unstaged_diff" if staged else "staged_diff"
    diff = payload["data"][diff_name]
    assert "diff --git a/audit.csv b/audit.csv" in diff
    assert "+new,2" in diff
    assert payload["data"][other_diff_name] == ""


def test_csv_diff_redacts_credentials_and_paths_without_snapshot_leakage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    token = "sk-proj-" + "A" * 24
    absolute_path = "/srv/synthetic-factor/audit.csv"
    (repo / "audit.csv").write_text(
        f"name,value\ntoken,{token}\npath,{absolute_path}\n",
        encoding="utf-8",
    )
    _run_test_git(repo, "add", "--", "audit.csv")

    artifact = runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert token.encode() not in artifact.snapshot_bytes
    assert absolute_path.encode() not in artifact.snapshot_bytes
    payload = json.loads(artifact.snapshot_bytes)
    staged = payload["data"]["staged_diff"]
    assert "[REDACTED_OPENAI_TOKEN]" in staged
    assert "<ABS_PATH:" in staged


def test_csv_diff_private_key_fails_closed_without_snapshot_leakage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    marker = "SYNTHETIC CSV PRIVATE KEY BODY"
    private_key = (
        _synthetic_pem_boundary("BEGIN") + f"\n{marker}\n" + _synthetic_pem_boundary("END")
    )
    (repo / "audit.csv").write_text(
        f"kind,value\npem,{private_key}\n",
        encoding="utf-8",
    )
    _run_test_git(repo, "add", "--", "audit.csv")

    with pytest.raises(security.RunnerError, match="sanitize staged-diff"):
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert marker.encode() not in b"".join(
        path.read_bytes() for path in state.rglob("*") if path.is_file()
    )
    assert not (state / "codex-exec").exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"name,value\nnew,2\0invalid\n",
        b"name,value\nnew,\xff\n",
        b"x" * (security.MAX_EXTENSIONLESS_TEXT_BYTES + 1),
    ],
    ids=("nul", "encoding", "size"),
)
def test_diff_audit_rejects_unsafe_csv_content(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: bytes,
) -> None:
    repo, state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    (repo / "audit.csv").write_bytes(raw)

    with pytest.raises(security.RunnerError, match="sanitize unstaged-diff"):
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert not (state / "codex-exec").exists()


@pytest.mark.parametrize("relative_path", [".gitattributes", "audit.csv"])
def test_diff_audit_rejects_symlinks_for_new_bounded_text_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    relative_path: str,
) -> None:
    repo, state, target = _bounded_text_diff_target(monkeypatch, tmp_path)
    candidate = repo / relative_path
    candidate.unlink()
    candidate.symlink_to("safe.canary-probe")

    expected_error = (
        "Git conversion attribute inspection failed closed"
        if relative_path == ".gitattributes"
        else "sanitize unstaged-diff"
    )
    with pytest.raises(security.RunnerError, match=expected_error):
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert not (state / "codex-exec").exists()


def test_csv_diff_keeps_high_risk_path_refusal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    _initialize_git_capability_repo(repo)
    sensitive_csv = repo / ".env.audit.csv"
    sensitive_csv.write_text("name,value\nold,1\n", encoding="utf-8")
    _commit_test_changes(repo, "sensitive csv baseline")
    state.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    target = _validated_test_repository(repo)
    sensitive_csv.write_text("name,value\nnew,2\n", encoding="utf-8")

    with pytest.raises(security.RunnerError, match="sanitize unstaged-diff"):
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert not (state / "codex-exec").exists()


def test_diff_audit_accepts_safe_extensionless_text_and_structured_signature(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state, target = _extensionless_diff_target(monkeypatch, tmp_path)
    (repo / "CURRENT").write_text("generation-new\n", encoding="utf-8")
    (repo / "operations.py").write_text(
        'METADATA = {"signature": {"arity": 2, "parameters": ["left", "right"]}}\n',
        encoding="utf-8",
    )

    artifact = runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    payload = json.loads(artifact.snapshot_bytes)
    unstaged = payload["data"]["unstaged_diff"]
    assert "diff --git a/CURRENT b/CURRENT" in unstaged
    assert "diff --git a/operations.py b/operations.py" in unstaged
    assert '"signature": {"arity": 2' in unstaged
    assert payload["redactions"] == {}


@pytest.mark.parametrize(
    "raw",
    [
        b"generation\0invalid\n",
        b"generation-\xff\n",
        b"x" * (security.MAX_EXTENSIONLESS_TEXT_BYTES + 1),
    ],
    ids=("nul", "encoding", "size"),
)
def test_diff_audit_rejects_unsafe_extensionless_content(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    raw: bytes,
) -> None:
    repo, state, target = _extensionless_diff_target(monkeypatch, tmp_path)
    (repo / "CURRENT").write_bytes(raw)

    artifact = runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    payload = json.loads(artifact.snapshot_bytes)
    expected_gap = (
        "file_limit" if len(raw) > security.MAX_EXTENSIONLESS_TEXT_BYTES else "file_refused"
    )
    assert "CURRENT" in payload["data"]["status_short"]
    assert "CURRENT" not in payload["data"]["unstaged_diff"]
    assert all(context["path"] != "CURRENT" for context in payload["data"]["file_context"])
    assert any(
        gap["kind"] == expected_gap and gap["subject"] == "CURRENT"
        for gap in payload["evidence_gaps"]
    )
    assert payload["truncated"] is True
    assert artifact.directory.is_relative_to(state)


@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_diff_audit_rejects_non_regular_extensionless_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    replacement: str,
) -> None:
    repo, state, target = _extensionless_diff_target(monkeypatch, tmp_path)
    current = repo / "CURRENT"
    current.unlink()
    if replacement == "symlink":
        current.symlink_to("safe.canary-probe")
    else:
        current.mkdir()

    artifact = runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    payload = json.loads(artifact.snapshot_bytes)
    assert "CURRENT" in payload["data"]["status_short"]
    assert "CURRENT" not in payload["data"]["unstaged_diff"]
    assert all(context["path"] != "CURRENT" for context in payload["data"]["file_context"])
    assert any(
        gap["kind"] == "file_refused" and gap["subject"] == "CURRENT"
        for gap in payload["evidence_gaps"]
    )
    assert payload["truncated"] is True
    assert artifact.directory.is_relative_to(state)


def test_signature_keeps_value_based_secret_detection() -> None:
    token = "sk-proj-" + "A" * 24
    raw = f'METADATA = {{"signature": "{token}"}}\n'

    sanitized = security.sanitize_text(raw, scan_mode=security.ScanMode.PLAIN_TEXT)

    assert token not in sanitized.text
    assert "[REDACTED_OPENAI_TOKEN]" in sanitized.text


def test_signature_private_key_fails_closed_without_artifact_leakage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, state, target = _extensionless_diff_target(monkeypatch, tmp_path)
    marker = "SYNTHETIC SIGNATURE PRIVATE KEY BODY"
    private_key = (
        _synthetic_pem_boundary("BEGIN") + f"\n{marker}\n" + _synthetic_pem_boundary("END")
    )
    (repo / "operations.py").write_text(
        'PRIVATE_KEY_FIXTURE = """\n' + private_key + '\n"""\n', encoding="utf-8"
    )

    with pytest.raises(security.RunnerError, match="sanitize unstaged-diff"):
        runner._prepare_snapshot("diff-audit", None, target, "/usr/bin/git")

    assert marker.encode() not in b"".join(
        path.read_bytes() for path in state.rglob("*") if path.is_file()
    )
    assert not (state / "codex-exec").exists()
