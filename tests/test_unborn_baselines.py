from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from codex_snapshot_runner import artifact, collect, git, security
from codex_snapshot_runner import cli as runner

GIT = "/usr/bin/git"


def _run_git_command(
    *arguments: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        [GIT, *arguments],
        cwd="/",
        input=input_bytes,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if check:
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result


def _run_git(
    repo: Path,
    *arguments: str,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    return _run_git_command("-C", os.fspath(repo), *arguments, input_bytes=input_bytes, check=check)


def _git_text(repo: Path, *arguments: str) -> str:
    return _run_git(repo, *arguments).stdout.decode("utf-8", errors="strict").strip()


def _initialize_unborn(
    repo: Path,
    *,
    branch: str = "main",
    object_format: str | None = None,
) -> bool:
    repo.mkdir()
    arguments = ["init", "--quiet", f"--initial-branch={branch}"]
    if object_format is not None:
        arguments.append(f"--object-format={object_format}")
    result = _run_git(repo, *arguments, check=False)
    return result.returncode == 0


def _commit(repo: Path, message: str = "baseline") -> str:
    _run_git(repo, "add", "--", "safe.py")
    _run_git(
        repo,
        "-c",
        "core.hooksPath=/dev/null",
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
    return _git_text(repo, "rev-parse", "HEAD")


def _private_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


def _validated_repository(repo: Path, task: str) -> git.ValidatedTargetRepository:
    target_path, target_name, runner_path = runner._validate_target_repository_path(os.fspath(repo))
    return git._validate_target_repository_context(
        target_path,
        target_name,
        runner_path,
        artifact._state_home(target_path),
        GIT,
        task,
    )


def _prepare(
    repo: Path,
    task: str,
    task_argument: str | None = None,
) -> artifact.SnapshotArtifact:
    target = _validated_repository(repo, task)
    return runner._prepare_snapshot(task, task_argument, target, GIT)


def _admin_manifest(repo: Path) -> tuple[tuple[str, str, int, str], ...]:
    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    entries: list[tuple[str, str, int, str]] = []
    for path in sorted(git_dir.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(git_dir).as_posix()
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode):
            entries.append((relative, "directory", mode, ""))
        elif stat.S_ISREG(metadata.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            entries.append((relative, "regular", mode, digest))
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path).encode("utf-8", errors="surrogateescape")
            entries.append((relative, "symlink", mode, hashlib.sha256(target).hexdigest()))
    return tuple(entries)


def _readonly_state(repo: Path) -> tuple[bytes, tuple[tuple[str, str, int, str], ...]]:
    porcelain = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout
    return porcelain, _admin_manifest(repo)


def _payload(snapshot: artifact.SnapshotArtifact) -> dict[str, object]:
    return json.loads(snapshot.snapshot_bytes)


def _assert_unborn_repo_status(
    data: object,
    branch: str,
    status: str,
    *,
    upstream: str = "not configured",
) -> None:
    assert isinstance(data, dict)
    assert data["current_branch"] == branch
    assert data["head"] == "unborn"
    assert data["upstream"] == upstream
    assert data["ahead_behind"] == "not available"
    assert data["recent_commits"] == ""
    assert data["local_branches"] == f"{branch}\tunborn\n"
    assert data["status_short"] == status


def _repeated_repo_status(repo: Path) -> dict[str, object]:
    before = _readonly_state(repo)
    first = _prepare(repo, "repo-status")
    first_files = {
        name: (first.directory / name).read_bytes() for name in artifact.SNAPSHOT_FILE_NAMES
    }
    second = _prepare(repo, "repo-status")
    payload = _payload(first)

    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    assert first.snapshot_bytes == second.snapshot_bytes
    assert first.snapshot_id == second.snapshot_id
    assert first.directory == second.directory
    assert first_files == {
        name: (second.directory / name).read_bytes() for name in artifact.SNAPSHOT_FILE_NAMES
    }
    assert "evidence_gaps=0 truncated=no incomplete=no" in (
        first.directory / "preview.txt"
    ).read_text(encoding="utf-8")
    assert _readonly_state(repo) == before
    data = payload["data"]
    assert isinstance(data, dict)
    return data


def test_unborn_empty_repo_status_is_complete_deterministic_and_read_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "unborn-empty"
    assert _initialize_unborn(repo, branch="new-project")
    _private_state(monkeypatch, tmp_path)
    before = _readonly_state(repo)

    first = _prepare(repo, "repo-status")
    second = _prepare(repo, "repo-status")

    payload = _payload(first)
    _assert_unborn_repo_status(payload["data"], "new-project", "")
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    assert first.snapshot_bytes == second.snapshot_bytes
    assert first.snapshot_id == second.snapshot_id
    assert first.directory == second.directory
    assert hashlib.sha256(first.snapshot_bytes).hexdigest() == first.snapshot_id
    assert len(first.snapshot_bytes) <= collect.MAX_SNAPSHOT_BYTES
    assert stat.S_IMODE(first.directory.lstat().st_mode) == 0o700
    for name in artifact.SNAPSHOT_FILE_NAMES:
        assert stat.S_IMODE((first.directory / name).lstat().st_mode) == 0o600
    preview = (first.directory / "preview.txt").read_text(encoding="utf-8")
    assert "git: branch=new-project head=unborn" in preview
    assert "evidence_gaps=0 truncated=no incomplete=no" in preview
    assert _readonly_state(repo) == before


def test_init_unborn_with_remote_has_no_configured_upstream(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    remote = tmp_path / "init-remote.git"
    remote.mkdir()
    _run_git(remote, "init", "--bare", "--quiet", "--initial-branch=main")
    repo = tmp_path / "init-worktree"
    assert _initialize_unborn(repo)
    _run_git(repo, "remote", "add", "origin", os.fspath(remote))
    _private_state(monkeypatch, tmp_path)

    assert (
        _run_git(repo, "config", "--local", "--get", "branch.main.remote", check=False).returncode
        == 1
    )
    assert (
        _run_git(repo, "config", "--local", "--get", "branch.main.merge", check=False).returncode
        == 1
    )
    data = _repeated_repo_status(repo)

    _assert_unborn_repo_status(data, "main", "")


def test_clone_upstream_target_resolution_and_ahead_counts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    remote = tmp_path / "clone-remote.git"
    remote.mkdir()
    _run_git(remote, "init", "--bare", "--quiet", "--initial-branch=main")
    repo = tmp_path / "clone-worktree"
    _run_git_command("clone", "--quiet", os.fspath(remote), os.fspath(repo))
    _private_state(monkeypatch, tmp_path)

    assert _git_text(repo, "symbolic-ref", "--short", "HEAD") == "main"
    assert _run_git(repo, "rev-parse", "--verify", "HEAD", check=False).returncode != 0
    assert _git_text(repo, "config", "--local", "--get", "branch.main.remote") == "origin"
    assert _git_text(repo, "config", "--local", "--get", "branch.main.merge") == "refs/heads/main"
    assert _run_git(remote, "for-each-ref").stdout == b""
    assert (
        _run_git(repo, "rev-parse", "--verify", "@{upstream}^{commit}", check=False).returncode != 0
    )

    unresolved = _repeated_repo_status(repo)
    _assert_unborn_repo_status(unresolved, "main", "", upstream="origin/main")
    assert _run_git(remote, "for-each-ref").stdout == b""

    (repo / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    first_head = _commit(repo)
    _run_git(repo, "push", "--quiet", "--set-upstream", "origin", "main")
    resolved = _repeated_repo_status(repo)
    assert resolved["current_branch"] == "main"
    assert resolved["head"] == first_head
    assert resolved["upstream"] == "origin/main"
    assert resolved["ahead_behind"] == "0 / 0"

    (repo / "safe.py").write_text("VALUE = 2\n", encoding="utf-8")
    second_head = _commit(repo, "local ahead")
    local_ahead = _repeated_repo_status(repo)
    assert local_ahead["current_branch"] == "main"
    assert local_ahead["head"] == second_head
    assert local_ahead["upstream"] == "origin/main"
    assert local_ahead["ahead_behind"] == "1 / 0"


@pytest.mark.parametrize(
    "scenario",
    ["untracked", "staged", "staged-and-unstaged", "staged-and-untracked"],
)
def test_unborn_workspace_layers_remain_distinct(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario: str,
) -> None:
    repo = tmp_path / f"unborn-{scenario}"
    assert _initialize_unborn(repo)
    _private_state(monkeypatch, tmp_path)
    alpha = repo / "alpha.py"
    beta = repo / "beta.txt"
    alpha.write_text("VALUE = 'staged'\n", encoding="utf-8")
    if scenario != "untracked":
        _run_git(repo, "add", "--", "alpha.py")
    if scenario == "staged-and-unstaged":
        alpha.write_text("VALUE = 'worktree'\n", encoding="utf-8")
    if scenario == "staged-and-untracked":
        beta.write_text("untracked context\n", encoding="utf-8")
    before = _readonly_state(repo)
    expected_status = before[0].decode("utf-8", errors="strict")

    status_artifact = _prepare(repo, "repo-status")
    diff_artifact = _prepare(repo, "diff-audit")
    repeated = _prepare(repo, "diff-audit")

    status_payload = _payload(status_artifact)
    _assert_unborn_repo_status(status_payload["data"], "main", expected_status)
    assert status_payload["evidence_gaps"] == []
    assert status_payload["truncated"] is False

    payload = _payload(diff_artifact)
    data = payload["data"]
    assert isinstance(data, dict)
    expected_oid = (
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
    assert data["baseline_kind"] == "empty_tree"
    assert data["baseline_oid"] == expected_oid
    assert len(expected_oid) == 40
    assert data["status_short"] == expected_status
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    staged_diff = str(data["staged_diff"])
    unstaged_diff = str(data["unstaged_diff"])
    contexts = data["file_context"]
    assert isinstance(contexts, list)
    context_paths = [context["path"] for context in contexts]
    assert len(context_paths) == len(set(context_paths))

    if scenario == "untracked":
        assert staged_diff == ""
        assert unstaged_diff == ""
        assert context_paths == ["alpha.py"]
    else:
        assert "+VALUE = 'staged'" in staged_diff
        assert context_paths.count("alpha.py") == 1
    if scenario == "staged-and-unstaged":
        assert "+VALUE = 'worktree'" in unstaged_diff
        assert "VALUE = 'worktree'" in str(contexts)
    else:
        assert unstaged_diff == ""
    if scenario == "staged-and-untracked":
        assert context_paths == ["alpha.py", "beta.txt"]
        assert "beta.txt" not in staged_diff
    assert diff_artifact.snapshot_bytes == repeated.snapshot_bytes
    assert diff_artifact.snapshot_id == repeated.snapshot_id
    assert _readonly_state(repo) == before


def test_unborn_identity_uses_read_only_dynamic_empty_tree_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "unborn-command-boundary"
    assert _initialize_unborn(repo)
    _private_state(monkeypatch, tmp_path)
    before = _admin_manifest(repo)
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
    validated = _validated_repository(repo, "diff-audit")

    identity = validated.target_identity
    assert identity.head_state == git.HEAD_STATE_UNBORN
    assert identity.head is None
    assert identity.current_ref == "refs/heads/main"
    assert identity.empty_tree_oid is not None
    assert len(identity.empty_tree_oid) == 40
    assert ("rev-parse", "--show-object-format=storage") in observed
    assert ("hash-object", "-t", "tree", "--stdin", "--no-filters") in observed
    assert not any("-w" in arguments for arguments in observed)
    assert not any(arguments[:2] == ("cat-file", "-e") for arguments in observed)
    assert _admin_manifest(repo) == before


@pytest.mark.parametrize(
    ("object_format", "oid"),
    [
        (b"sha512\n", b"a" * 128 + b"\n"),
        (b"sha1\n", b"A" * 40 + b"\n"),
        (b"sha1\n", b"a" * 39 + b"\n"),
        (b"sha256\n", b"a" * 40 + b"\n"),
    ],
    ids=("unsupported-format", "uppercase", "sha1-length", "sha256-length"),
)
def test_empty_tree_identity_rejects_unsupported_or_noncanonical_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    object_format: bytes,
    oid: bytes,
) -> None:
    def synthetic_run(
        _self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = git.MAX_GIT_OUTPUT_BYTES,
    ) -> git.GitResult:
        del maximum
        stdout = object_format if arguments[0] == "rev-parse" else oid
        return git.GitResult(stdout, b"", 0, False, arguments[0])

    monkeypatch.setattr(git.GitRunner, "run", synthetic_run)
    with pytest.raises(
        security.RunnerError,
        match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$",
    ):
        git._empty_tree_oid(git.GitRunner(tmp_path), git.TARGET_REPOSITORY_INVALID_ERROR)


def test_sha256_unborn_uses_a_64_character_empty_tree_oid(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "unborn-sha256"
    if not _initialize_unborn(repo, object_format="sha256"):
        pytest.skip("installed Git does not support SHA-256 repositories")
    _private_state(monkeypatch, tmp_path)
    before = _readonly_state(repo)

    artifact_result = _prepare(repo, "diff-audit")

    payload = _payload(artifact_result)
    data = payload["data"]
    assert isinstance(data, dict)
    expected = (
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
    assert data["baseline_kind"] == "empty_tree"
    assert data["baseline_oid"] == expected
    assert len(expected) == 64
    assert payload["evidence_gaps"] == []
    assert _readonly_state(repo) == before


def test_missing_object_ref_is_not_misclassified_as_unborn(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "damaged-ref"
    assert _initialize_unborn(repo)
    _private_state(monkeypatch, tmp_path)
    reference = repo / ".git" / "refs" / "heads" / "main"
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text(f"{'f' * 40}\n", encoding="ascii")

    with pytest.raises(
        security.RunnerError,
        match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$",
    ):
        _validated_repository(repo, "diff-audit")


@pytest.mark.parametrize("kind", ["bare", "non-git"])
def test_invalid_repository_kinds_remain_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
) -> None:
    repo = tmp_path / kind
    repo.mkdir()
    if kind == "bare":
        _run_git(repo, "init", "--bare", "--quiet")
    _private_state(monkeypatch, tmp_path)

    with pytest.raises(
        security.RunnerError,
        match=f"^{git.TARGET_REPOSITORY_INVALID_ERROR}$",
    ):
        _validated_repository(repo, "diff-audit")


def test_branch_review_rejects_unborn_before_collection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "unborn-branch-review"
    assert _initialize_unborn(repo)
    state = _private_state(monkeypatch, tmp_path)
    target = _validated_repository(repo, "branch-review")
    collected = False

    def unexpected_collection(*_args: object, **_kwargs: object) -> collect.Snapshot:
        nonlocal collected
        collected = True
        raise AssertionError("branch-review collector ran for an unborn repository")

    monkeypatch.setattr(collect, "collect_branch_review", unexpected_collection)
    with pytest.raises(
        security.RunnerError,
        match="branch-review requires a target branch with at least one commit",
    ):
        runner._prepare_snapshot("branch-review", "main", target, GIT)
    assert collected is False
    assert not (state / "codex-exec").exists()


def test_attached_and_detached_artifact_structures_remain_legacy_compatible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "mature-repository"
    assert _initialize_unborn(repo)
    (repo / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    head = _commit(repo)
    (repo / "safe.log").write_text("1 passed\n", encoding="utf-8")
    _private_state(monkeypatch, tmp_path)

    attached_status = _payload(_prepare(repo, "repo-status"))["data"]
    attached_diff = _payload(_prepare(repo, "diff-audit"))["data"]
    assert isinstance(attached_status, dict)
    assert isinstance(attached_diff, dict)
    assert attached_status["head"] == head
    assert attached_status["upstream"] == "not configured"
    assert attached_status["ahead_behind"] == "not available"
    assert "baseline_kind" not in attached_diff
    assert "baseline_oid" not in attached_diff

    _run_git(repo, "switch", "--quiet", "--detach")
    before = _readonly_state(repo)
    detached_status = _payload(_prepare(repo, "repo-status"))["data"]
    detached_diff = _payload(_prepare(repo, "diff-audit"))["data"]
    triage = _prepare(repo, "test-triage", "safe.log")
    assert isinstance(detached_status, dict)
    assert isinstance(detached_diff, dict)
    assert detached_status["current_branch"] == "(detached)"
    assert detached_status["head"] == head
    assert "upstream" not in detached_status
    assert "ahead_behind" not in detached_status
    assert "baseline_kind" not in detached_diff
    assert "baseline_oid" not in detached_diff
    assert _payload(triage)["data"] == {
        "log": "1 passed\n",
        "log_display_name": "test-output.log",
    }
    assert _readonly_state(repo) == before
