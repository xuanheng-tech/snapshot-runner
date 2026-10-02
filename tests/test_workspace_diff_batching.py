"""Bounded workspace and branch diffs preserve complete, quoted-path evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from snapshot_runner import artifact, collect, git, security
from snapshot_runner import cli as runner

GIT = "/usr/bin/git"
MAX_COMMAND_BYTES = git.MAX_GIT_OUTPUT_BYTES
UNCAPTURED_BOUND_BYTES = 64 * 1024 * 1024
PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082"
)


def _run_git(repo: Path, *arguments: str) -> bytes:
    """Repository setup through the runner's own Git environment, never the ambient config."""
    result = git.GitRunner(repo).run(arguments, maximum=UNCAPTURED_BOUND_BYTES)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result.stdout


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _commit(repo: Path, message: str) -> None:
    _run_git(
        repo,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Runner Test",
        "-c",
        "user.email=runner-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        "commit",
        "--quiet",
        "-m",
        message,
    )


def _repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    _run_git(repo, "init", "--quiet", "--initial-branch=main")
    return repo


def _prepare(
    repo: Path, task: str = "diff-audit", argument: str | None = None
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
    return runner._prepare_snapshot(task, argument, target, GIT)


def _payload(snapshot: artifact.SnapshotArtifact) -> dict[str, object]:
    payload = json.loads(snapshot.snapshot_bytes)
    assert isinstance(payload["data"], dict)
    return payload


def _gap_kinds(snapshot: artifact.SnapshotArtifact) -> list[str]:
    return [gap["kind"] for gap in _gaps(snapshot)]


def _gaps(snapshot: artifact.SnapshotArtifact) -> list[dict[str, str]]:
    gaps = json.loads(snapshot.snapshot_bytes)["evidence_gaps"]
    assert isinstance(gaps, list)
    return [gap for gap in gaps if isinstance(gap, dict)]


def _field(snapshot: artifact.SnapshotArtifact, key: str) -> str:
    value = _payload(snapshot)["data"][key]
    assert isinstance(value, str)
    return value


def _single_shot_diff(repo: Path, *, cached: bool) -> bytes:
    """The whole workspace diff in one command: the pre-batching collection route.

    Collected through ``GitRunner`` so the reference sees exactly the environment, config
    overrides and diff options the collector itself uses.
    """
    cached_argument = ("--cached",) if cached else ()
    result = git.GitRunner(repo).run(
        (
            "-c",
            "core.quotePath=true",
            "diff",
            *cached_argument,
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--",
        ),
        maximum=UNCAPTURED_BOUND_BYTES,
    )
    assert result.returncode == 0 and not result.truncated
    return result.stdout


def _record_diff_commands(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, bool]]:
    """Record (stdout bytes, truncated) for every full unified-diff command the runner runs."""
    observed: list[tuple[int, bool]] = []
    original = git.GitRunner.run

    def probe(
        self: git.GitRunner,
        arguments: tuple[str, ...],
        *,
        maximum: int = MAX_COMMAND_BYTES,
    ) -> git.GitResult:
        result = original(self, arguments, maximum=maximum)
        if (
            "diff" in arguments
            and "core.quotePath=true" in arguments
            and "--name-only" not in arguments
        ):
            observed.append((len(result.stdout), result.truncated))
        return result

    monkeypatch.setattr(git.GitRunner, "run", probe)
    return observed


def _grown_repo(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    files: int,
    lines: int,
    stage: bool = True,
) -> Path:
    """Commit a baseline, then grow every file so the escaped diff body dominates."""
    repo = _repository(monkeypatch, tmp_path)
    for index in range(files):
        _write(repo, f"批次目录/文件_{index:04d}.py", "SEED = 0\n")
    _write(repo, "锚点.py", "ANCHOR = 0\n")
    _run_git(repo, "add", "-A", "--")
    _commit(repo, "baseline")
    for index in range(files):
        growth = "".join(f"V{index}_{line} = {line:08d}\n" for line in range(lines))
        _write(repo, f"批次目录/文件_{index:04d}.py", f"SEED = 0\n{growth}")
    if stage:
        _run_git(repo, "add", "-A", "--")
    return repo


def test_a_staged_workspace_diff_beyond_one_command_bound_publishes_complete(monkeypatch, tmp_path):
    """The D3 regression: over-bound escaped diff no longer destroys the snapshot."""
    repo = _grown_repo(monkeypatch, tmp_path, files=400, lines=280)
    reference = _single_shot_diff(repo, cached=True)
    assert len(reference) > MAX_COMMAND_BYTES, "fixture must exceed one command's bound"

    snapshot = _prepare(repo)
    assert _field(snapshot, "staged_diff").encode("utf-8") == reference
    assert _field(snapshot, "staged_diff").count("diff --git ") == 400
    assert _field(snapshot, "unstaged_diff") == ""
    assert "git_output_limit" not in _gap_kinds(snapshot)
    assert "snapshot_limit" not in _gap_kinds(snapshot)


def test_an_unstaged_workspace_diff_beyond_one_command_bound_publishes_complete(
    monkeypatch, tmp_path
):
    repo = _grown_repo(monkeypatch, tmp_path, files=400, lines=280, stage=False)
    reference = _single_shot_diff(repo, cached=False)
    assert len(reference) > MAX_COMMAND_BYTES, "fixture must exceed one command's bound"

    snapshot = _prepare(repo)
    assert _field(snapshot, "unstaged_diff").encode("utf-8") == reference
    assert _field(snapshot, "staged_diff") == ""
    assert "git_output_limit" not in _gap_kinds(snapshot)


def test_batching_reproduces_the_single_shot_diff_byte_for_byte(monkeypatch, tmp_path):
    """Splitting the path set must not reorder, reflow or drop any diff entry."""
    repo = _grown_repo(monkeypatch, tmp_path, files=300, lines=20)
    _write(repo, "q\"uote/it's.py", "Q = 0\n")
    _write(repo, "docs(a)/notes.md", "# notes\n")
    _write(repo, "sp ace/文件 一.py", "S = 0\n")
    _run_git(repo, "add", "-A", "--")
    (repo / "docs(a)/notes.md").write_text("# notes\nedited\n", encoding="utf-8")
    (repo / "锚点.py").unlink()
    os.chmod(repo / "q\"uote/it's.py", 0o755)

    staged = _single_shot_diff(repo, cached=True)
    unstaged = _single_shot_diff(repo, cached=False)
    payload = _payload(_prepare(repo))
    assert payload["data"]["staged_diff"].encode("utf-8") == staged
    assert payload["data"]["unstaged_diff"].encode("utf-8") == unstaged


def test_a_batch_that_still_overflows_is_divided_without_loss(monkeypatch, tmp_path):
    """Path-count limits do not bound diff bodies, so an over-bound batch is divided again."""
    repo = _grown_repo(monkeypatch, tmp_path, files=257, lines=520)
    reference = _single_shot_diff(repo, cached=True)
    assert len(reference) > MAX_COMMAND_BYTES

    observed = _record_diff_commands(monkeypatch)
    snapshot = _prepare(repo)
    assert _field(snapshot, "staged_diff").encode("utf-8") == reference

    refused = [size for size, truncated in observed if truncated]
    admitted = [size for size, truncated in observed if not truncated]
    assert refused, "the fixture must actually overrun one in-limits batch"
    assert admitted and max(admitted) < MAX_COMMAND_BYTES, "every admitted batch stays bounded"
    assert len(admitted) > len(refused), "division must terminate with admitted commands"


def test_division_stops_once_the_snapshot_cannot_carry_the_diff(monkeypatch, tmp_path):
    """Beyond the content budget, division would only accumulate evidence that cannot fit."""
    repo = _grown_repo(monkeypatch, tmp_path, files=257, lines=520)
    paths = [
        entry.decode("utf-8")
        for entry in _run_git(repo, "diff", "--cached", "--name-only", "-z", "--").split(b"\0")
        if entry
    ]

    exhausted = collect.SnapshotBuilder("diff-audit", repo.name, repo)
    exhausted.content_bytes = collect.SNAPSHOT_CONTENT_BUDGET
    with pytest.raises(security.RunnerError, match="remaining snapshot content budget"):
        collect._workspace_unified_diff(
            git.GitRunner(repo), exhausted, "staged-diff", paths, cached=True
        )


def test_pathspec_metacharacters_in_names_are_matched_literally(monkeypatch, tmp_path):
    repo = _repository(monkeypatch, tmp_path)
    names = (
        ":(top,literal)陷阱.py",
        "*全局?.py",
        "[类]目.py",
        "-dash.py",
        "尾随空格 .py",
        "back\\slash.py",
    )
    for index, name in enumerate(names):
        _write(repo, name, f"N = {index}\n")
    _run_git(repo, "add", "-A", "--")
    _commit(repo, "baseline")
    for index, name in enumerate(names):
        _write(repo, name, f"N = {index}\ngrown\n")
    _run_git(repo, "add", "-A", "--")

    reference = _single_shot_diff(repo, cached=True)
    payload = _payload(_prepare(repo))
    assert payload["data"]["staged_diff"].encode("utf-8") == reference
    assert payload["data"]["staged_diff"].count("diff --git ") == len(names)


def test_non_text_files_keep_their_own_routing_while_batching_runs(monkeypatch, tmp_path):
    repo = _grown_repo(monkeypatch, tmp_path, files=300, lines=20)
    _write(repo, "raw/blob.dat", "not text\n")
    (repo / "icon.png").write_bytes(PNG_BYTES)
    _run_git(repo, "add", "-A", "--")

    snapshot = _prepare(repo)
    # A disagreement between the batched diff and the workspace path metadata raises during
    # collection, so a clean collection proves the filtered set stayed 1:1 under batching.
    diff = _field(snapshot, "staged_diff")
    assert diff.count("diff --git ") == 300
    assert "blob.dat" not in diff
    assert "icon.png" not in diff
    contexts = _payload(snapshot)["data"]["file_context"]
    assert isinstance(contexts, list)
    recorded = {str(entry["path"]): str(entry["content"]) for entry in contexts}
    assert recorded["icon.png"].startswith("binary image evidence\nmedia_type: image/png")
    assert any(
        gap["kind"] == "file_refused" and gap["subject"] == "raw/blob.dat"
        for gap in _gaps(snapshot)
    )
    assert "git_output_limit" not in _gap_kinds(snapshot)
    assert "snapshot_limit" not in _gap_kinds(snapshot)


def test_a_single_path_beyond_the_command_bound_still_refuses(monkeypatch, tmp_path):
    """One path cannot be divided further; its over-bound diff stays a fail-closed refusal."""
    repo = _grown_repo(monkeypatch, tmp_path, files=1, lines=1)
    _run_git(repo, "add", "-A", "--")
    _commit(repo, "baseline")
    growth = "".join(f"V0_{line} = {line:08d}\n" for line in range(140_000))
    _write(repo, "批次目录/文件_0000.py", f"SEED = 0\n{growth}")
    _run_git(repo, "add", "-A", "--")
    assert len(_single_shot_diff(repo, cached=True)) > MAX_COMMAND_BYTES

    with pytest.raises(security.RunnerError, match="truncated unified diff evidence was refused"):
        _prepare(repo)


def _branch_diff(repo: Path) -> bytes:
    result = git.GitRunner(repo).run(
        (
            "-c",
            "core.quotePath=true",
            "diff",
            "--find-renames=50%",
            "--no-ext-diff",
            "--no-textconv",
            "main..HEAD",
            "--",
        ),
        maximum=UNCAPTURED_BOUND_BYTES,
    )
    assert result.returncode == 0 and not result.truncated
    return result.stdout


def _repository_files(repo: Path) -> dict[str, tuple[int, str]]:
    return {
        path.relative_to(repo).as_posix(): (
            path.stat().st_mode,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in repo.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("lines", [280, 400])
def test_large_branch_diff_keeps_global_renames_and_complete_bytes(monkeypatch, tmp_path, lines):
    repo = _grown_repo(monkeypatch, tmp_path, files=400, lines=lines)
    # Equal sources/targets leave rename pairing to Git's global candidate set.
    for name in ("a-old.py", "b-old.py"):
        _write(repo, name, "IDENTICAL = 1\n" * 12)
    _run_git(repo, "reset", "--hard", "HEAD")
    _run_git(repo, "add", "--", "a-old.py", "b-old.py")
    _commit(repo, "rename sources")
    _run_git(repo, "switch", "--quiet", "-c", "feature")
    for index in range(400):
        growth = "".join(f"V{index}_{line} = {line:08d}\n" for line in range(lines))
        _write(repo, f"批次目录/文件_{index:04d}.py", f"SEED = 0\n{growth}")
    _run_git(repo, "mv", "--", "a-old.py", "z-new.py")
    _run_git(repo, "mv", "--", "b-old.py", "y-new.py")
    _write(repo, ":(glob)*[字]?.py", "LITERAL = 1\n")
    _run_git(repo, "add", "-A", "--")
    _commit(repo, "large branch")
    reference = _branch_diff(repo)
    assert 2 * 1024 * 1024 < len(reference) < 4 * 1024 * 1024
    assert reference.count(b"similarity index 100%") == 2
    before = _repository_files(repo)

    snapshot = _prepare(repo, "branch-review", "main")

    assert _field(snapshot, "diff").encode("utf-8") == reference
    assert _field(snapshot, "diff").count("diff --git ") == 403
    assert "git_output_limit" not in _gap_kinds(snapshot)
    assert "snapshot_limit" not in _gap_kinds(snapshot)
    assert _repository_files(repo) == before


def test_large_branch_replacements_fit_without_evidence_gaps(monkeypatch, tmp_path):
    repo = _repository(monkeypatch, tmp_path)
    for marker in ("a", "b"):
        for index in range(40):
            body = "".join(f"V{index}_{line} = '{marker * 48}'\n" for line in range(600))
            _write(repo, f"src/module_{index:02d}.py", body)
        _run_git(repo, "add", "-A", "--")
        _commit(repo, f"version {marker}")
        if marker == "a":
            _run_git(repo, "switch", "--quiet", "-c", "feature")
    reference = _branch_diff(repo)
    assert 2 * 1024 * 1024 < len(reference) < 4 * 1024 * 1024

    snapshot = _prepare(repo, "branch-review", "main")

    assert _field(snapshot, "diff").encode("utf-8") == reference
    assert _gaps(snapshot) == []
    assert len(snapshot.snapshot_bytes) < collect.MAX_SNAPSHOT_BYTES


def test_small_branch_snapshot_matches_the_previous_capture_bound(monkeypatch, tmp_path):
    repo = _grown_repo(monkeypatch, tmp_path, files=3, lines=10)
    _run_git(repo, "switch", "--quiet", "-c", "feature")
    _commit(repo, "small branch")
    current = _prepare(repo, "branch-review", "main")
    original = git.GitRunner.run

    def previous_capture(self, arguments, *, maximum=MAX_COMMAND_BYTES):
        if "core.quotePath=true" in arguments and "--find-renames=50%" in arguments:
            maximum = MAX_COMMAND_BYTES
        return original(self, arguments, maximum=maximum)

    monkeypatch.setattr(git.GitRunner, "run", previous_capture)
    previous = _prepare(repo, "branch-review", "main")
    assert current.snapshot_bytes == previous.snapshot_bytes
    assert current.snapshot_id == previous.snapshot_id


def test_branch_over_the_shared_budget_publishes_no_artifact(monkeypatch, tmp_path):
    repo = _grown_repo(monkeypatch, tmp_path, files=1, lines=1)
    _run_git(repo, "switch", "--quiet", "-c", "feature")
    _write(repo, "批次目录/文件_0000.py", "VALUE = 1\n" * (collect.MAX_SNAPSHOT_BYTES // 9))
    _run_git(repo, "add", "-A", "--")
    _commit(repo, "over budget")
    before = _repository_files(repo)

    with pytest.raises(security.RunnerError, match="remaining snapshot content budget"):
        _prepare(repo, "branch-review", "main")

    assert not list((tmp_path / "state").rglob("snapshot.json"))
    assert _repository_files(repo) == before


def test_branch_capture_accounts_for_metadata_and_json_escaping(monkeypatch, tmp_path):
    repo = _grown_repo(monkeypatch, tmp_path, files=1, lines=1)
    _run_git(repo, "switch", "--quiet", "-c", "feature")
    _write(repo, "批次目录/文件_0000.py", 'VALUE = "' + "\\" * 1000 + '"\n')
    _run_git(repo, "add", "-A", "--")
    _commit(repo, "escaped content")
    reference = _branch_diff(repo)
    monkeypatch.setattr(collect, "SNAPSHOT_CONTENT_BUDGET", len(reference) + 600)
    original = git.GitRunner.run
    limits = []

    def probe(self, arguments, *, maximum=MAX_COMMAND_BYTES):
        result = original(self, arguments, maximum=maximum)
        if "core.quotePath=true" in arguments and "--find-renames=50%" in arguments:
            limits.append(maximum)
            assert not result.truncated
        return result

    monkeypatch.setattr(git.GitRunner, "run", probe)
    with pytest.raises(security.RunnerError, match="remaining snapshot content budget"):
        _prepare(repo, "branch-review", "main")

    assert len(limits) == 1
    assert len(reference) <= limits[0] < collect.SNAPSHOT_CONTENT_BUDGET - 2
    assert not list((tmp_path / "state").rglob("snapshot.json"))


def test_branch_with_no_remaining_budget_does_not_run_git(monkeypatch, tmp_path):
    builder = collect.SnapshotBuilder("branch-review", "repo", tmp_path)
    builder.content_bytes = collect.SNAPSHOT_CONTENT_BUDGET - 2

    def unexpected_git(*args, **kwargs):
        pytest.fail("an exhausted branch budget must not start Git")

    monkeypatch.setattr(git.GitRunner, "run", unexpected_git)
    with pytest.raises(security.RunnerError, match="remaining snapshot content budget"):
        collect._branch_unified_diff(git.GitRunner(tmp_path), builder, "main..HEAD", ["file.py"])
