from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_snapshot_runner import artifact, git, security
from codex_snapshot_runner import cli as runner

GIT = "/usr/bin/git"


def _run_git(repo: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments],
        cwd="/",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result.stdout


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _initialize(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    with_commit: bool = True,
) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    state = tmp_path / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    _run_git(repo, "init", "--quiet", "--initial-branch=main")
    if with_commit:
        _write(repo, "plain.py", "PLAIN = 1\n")
        _run_git(repo, "add", "--", "plain.py")
        _commit(repo, "baseline")
    return repo, state


def _commit(repo: Path, message: str) -> None:
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


def _prepare(
    repo: Path,
    task: str = "diff-audit",
    argument: str | None = None,
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
    return json.loads(snapshot.snapshot_bytes)


def _cli_snapshot(
    repo: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[bytes, str]:
    assert runner.main(["prepare", "diff-audit", "--repo", os.fspath(repo)]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    fields = dict(
        line.split(": ", 1)
        for line in captured.out.splitlines()
        if line.startswith(("snapshot_id: ", "snapshot: "))
    )
    return Path(fields["snapshot"]).read_bytes(), fields["snapshot_id"]


def _path_changes(payload: dict[str, object], repo: Path) -> set[tuple[str | None, str | None]]:
    data = payload["data"]
    assert isinstance(data, dict)
    changes: set[tuple[str | None, str | None]] = set()
    for key in ("staged_diff", "unstaged_diff"):
        raw = data[key]
        assert isinstance(raw, str)
        changes.update(security.unified_diff_path_changes(raw, repository_root=repo))
    return changes


def test_diff_audit_cli_accepts_git_quoted_paths_in_mixed_workspace_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path)
    baseline = {
        "file with spaces.py": "old spaces\n",
        "dir with spaces/file name.txt": "old directory\n",
        "记录/任务 说明.md": "old staged and unstaged\n",
        "混合 dir/中文 name.txt": "old mixed\n",
        'quote"name.py': "old quote\n",
        "back\\slash.txt": "old backslash\n",
        "rename old/旧 name.txt": "rename body\n",
    }
    for path, content in baseline.items():
        _write(repo, path, content)
    _run_git(repo, "add", "--", *baseline)
    _commit(repo, "quoted path baseline")
    _run_git(repo, "config", "core.quotePath", "false")

    _write(repo, "file with spaces.py", "staged spaces\n")
    _run_git(repo, "add", "--", "file with spaces.py")
    _write(repo, "dir with spaces/file name.txt", "unstaged directory\n")
    _write(repo, "记录/任务 说明.md", "index version\n")
    _run_git(repo, "add", "--", "记录/任务 说明.md")
    _write(repo, "记录/任务 说明.md", "worktree version\n")
    _write(repo, "混合 dir/中文 name.txt", "unstaged mixed\n")
    _write(repo, 'added "quote" 中文.py', "added\n")
    _run_git(repo, "add", "--", 'added "quote" 中文.py')
    (repo / "back\\slash.txt").unlink()
    _run_git(repo, "add", "-u", "--", "back\\slash.txt")
    (repo / "rename new").mkdir()
    _run_git(repo, "mv", "--", "rename old/旧 name.txt", "rename new/新 name.txt")
    _write(repo, "未跟踪 dir/说明 文件.txt", "untracked\n")
    _write(repo, "plain.py", "PLAIN = 2\n")

    config_before = (repo / ".git/config").read_bytes()
    first_bytes, first_id = _cli_snapshot(repo, capsys)
    second_bytes, second_id = _cli_snapshot(repo, capsys)
    payload = json.loads(first_bytes)
    data = payload["data"]
    assert isinstance(data, dict)

    assert first_bytes == second_bytes
    assert first_id == second_id == hashlib.sha256(first_bytes).hexdigest()
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False
    assert (repo / ".git/config").read_bytes() == config_before

    changes = _path_changes(payload, repo)
    assert ("file with spaces.py", "file with spaces.py") in changes
    assert ("dir with spaces/file name.txt", "dir with spaces/file name.txt") in changes
    assert ("记录/任务 说明.md", "记录/任务 说明.md") in changes
    assert ("混合 dir/中文 name.txt", "混合 dir/中文 name.txt") in changes
    assert (None, 'added "quote" 中文.py') in changes
    assert ("back\\slash.txt", None) in changes
    assert ("rename old/旧 name.txt", None) in changes
    assert (None, "rename new/新 name.txt") in changes
    assert ("plain.py", "plain.py") in changes

    contexts = data["file_context"]
    assert isinstance(contexts, list)
    context_paths = {context["path"] for context in contexts}
    assert "未跟踪 dir/说明 文件.txt" in context_paths
    assert 'added "quote" 中文.py' in context_paths
    assert "记录/任务 说明.md" in context_paths


def test_branch_review_accepts_rename_paths_with_spaces_and_non_ascii(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path)
    old_path = "rename old/旧 name.txt"
    new_path = "rename new/新 name.txt"
    _write(repo, old_path, "before\n")
    _run_git(repo, "add", "--", old_path)
    _commit(repo, "rename baseline")
    _run_git(repo, "branch", "base")
    (repo / "rename new").mkdir()
    _run_git(repo, "mv", "--", old_path, new_path)
    _commit(repo, "rename path")

    result = _prepare(repo, "branch-review", "base")
    payload = _payload(result)
    data = payload["data"]
    assert isinstance(data, dict)
    diff = data["diff"]
    assert isinstance(diff, str)
    assert security.unified_diff_path_changes(diff, repository_root=repo) == ((old_path, new_path),)
    assert payload["evidence_gaps"] == []
    assert payload["truncated"] is False


def test_unborn_diff_audit_accepts_ascii_spaces_and_non_ascii(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path, with_commit=False)
    paths = ("plain.py", "未出生 dir/file name 中文.txt")
    for path in paths:
        _write(repo, path, f"{path}\n")
    _run_git(repo, "add", "--", *paths)

    payload = _payload(_prepare(repo))
    data = payload["data"]
    assert isinstance(data, dict)
    staged = data["staged_diff"]
    assert isinstance(staged, str)
    assert set(security.unified_diff_path_changes(staged, repository_root=repo)) == {
        (None, path) for path in paths
    }
    assert data["baseline_kind"] == "empty_tree"
    assert payload["evidence_gaps"] == []


def test_git_octal_utf8_path_escapes_decode_to_canonical_unicode() -> None:
    escaped = r"\350\256\260\345\275\225/\344\273\273\345\212\241 \350\257\264\346\230\216.md"
    path = "记录/任务 说明.md"
    raw = (
        f'diff --git "a/{escaped}" "b/{escaped}"\n'
        f'--- "a/{escaped}"\n'
        f'+++ "b/{escaped}"\n'
        "@@ -1 +1 @@\n"
        "-before\n"
        "+after\n"
    )
    assert security.unified_diff_path_changes(raw, repository_root=None) == ((path, path),)
    assert security.sanitize_text(raw, scan_mode=security.ScanMode.UNIFIED_DIFF).text == raw


@pytest.mark.parametrize(
    "raw",
    [
        'diff --git "a/bad.py" "b/bad.py\n',
        r'diff --git "a/bad\q.py" "b/bad\q.py"' "\n",
        r'diff --git "a/bad-\377.py" "b/bad-\377.py"' "\n",
        "diff --git a/../bad.py b/../bad.py\n",
        "diff --git c/bad.py b/bad.py\n",
        ("diff --git a/bad.py b/bad.py\n--- /dev/null\n+++ b/bad.py\n@@ -0,0 +1 @@\n+bad\n"),
    ],
)
def test_malformed_or_unsafe_git_patch_paths_are_refused(raw: str) -> None:
    with pytest.raises(security.SecurityError):
        security.sanitize_text(raw, scan_mode=security.ScanMode.UNIFIED_DIFF)


def test_non_utf8_repository_path_remains_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo, _state = _initialize(monkeypatch, tmp_path)
    raw_path = os.fsencode(repo) + b"/bad-\xff.txt"
    descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"invalid path encoding\n")
    finally:
        os.close(descriptor)

    with pytest.raises(security.RunnerError, match="repository path evidence is not valid UTF-8"):
        _prepare(repo)
