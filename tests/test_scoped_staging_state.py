"""Scoped diff-audit must reproduce the source index and worktree states exactly."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from snapshot_runner import cli, isolation


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(repo), *arguments],
        cwd="/",
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.fixture
def staging_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.setattr(isolation, "TEMP_ROOT", tmp_path / "runner-temp")

    repo = tmp_path / "target-repository"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    _git(repo, "config", "user.name", "Staging Test")
    _git(repo, "config", "user.email", "staging@example.invalid")
    names = ("staged_only.py", "unstaged_only.py", "both.py", "reverted.py", "staged_delete.py")
    for name in names:
        (repo / name).write_text("BASE\n", encoding="utf-8")
    _git(repo, "add", "--", *names)
    _git(repo, "commit", "--quiet", "-m", "baseline")

    # index != HEAD, worktree == index
    (repo / "staged_only.py").write_text("STAGED\n", encoding="utf-8")
    _git(repo, "add", "--", "staged_only.py")
    # index == HEAD, worktree != index
    (repo / "unstaged_only.py").write_text("WORKTREE\n", encoding="utf-8")
    # index != HEAD and worktree != index
    (repo / "both.py").write_text("STAGED\n", encoding="utf-8")
    _git(repo, "add", "--", "both.py")
    (repo / "both.py").write_text("WORKTREE\n", encoding="utf-8")
    # index != HEAD while the worktree matches HEAD again
    (repo / "reverted.py").write_text("STAGED\n", encoding="utf-8")
    _git(repo, "add", "--", "reverted.py")
    (repo / "reverted.py").write_text("BASE\n", encoding="utf-8")
    # staged deletion with the worktree file removed as well
    _git(repo, "rm", "--quiet", "--", "staged_delete.py")
    # never tracked
    (repo / "untracked.py").write_text("UNTRACKED\n", encoding="utf-8")
    return repo


def _summary(repo: Path, relative: str, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    exit_code = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            relative,
            "--summary",
        ]
    )
    assert exit_code == 0
    return json.loads(capsys.readouterr().out)


def _porcelain_code(repo: Path, relative: str) -> str:
    line = _git(repo, "status", "--porcelain=v1", "--", relative).splitlines()[0]
    return line[:2]


@pytest.mark.parametrize(
    ("relative", "expected_code", "staged", "unstaged", "untracked"),
    [
        ("staged_only.py", "M ", 1, 0, 0),
        ("unstaged_only.py", " M", 0, 1, 0),
        ("both.py", "MM", 1, 1, 0),
        ("reverted.py", "MM", 1, 1, 0),
        ("staged_delete.py", "D ", 1, 0, 0),
        ("untracked.py", "??", 0, 0, 1),
    ],
)
def test_scoped_audit_preserves_source_staging_state(
    staging_repository: Path,
    capsys: pytest.CaptureFixture[str],
    relative: str,
    expected_code: str,
    staged: int,
    unstaged: int,
    untracked: int,
) -> None:
    assert _porcelain_code(staging_repository, relative) == expected_code
    result = _summary(staging_repository, relative, capsys)["result"]
    assert isinstance(result, dict)
    assert (result["staged"], result["unstaged"], result["untracked"]) == (
        staged,
        unstaged,
        untracked,
    )


def test_scoped_audit_reports_staged_and_unstaged_diffs_separately(
    staging_repository: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    summary = _summary(staging_repository, "both.py", capsys)
    snapshot = json.loads(
        (Path(str(summary["artifact"]))).read_text(encoding="utf-8"),
    )
    data = snapshot["data"]
    assert "+STAGED" in data["staged_diff"]
    assert "+WORKTREE" in data["unstaged_diff"]
    assert data["status_short"].startswith("MM ")


def test_scoped_audit_preserves_staged_executable_mode(
    staging_repository: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = staging_repository / "mode.py"
    target.write_text("BASE\n", encoding="utf-8")
    target.chmod(0o644)
    _git(staging_repository, "add", "--", "mode.py")
    _git(staging_repository, "commit", "--quiet", "-m", "mode baseline")
    target.chmod(0o755)
    _git(staging_repository, "add", "--", "mode.py")

    assert _porcelain_code(staging_repository, "mode.py") == "M "
    result = _summary(staging_repository, "mode.py", capsys)["result"]
    assert isinstance(result, dict)
    assert (result["staged"], result["unstaged"]) == (1, 0)


def test_scoped_audit_refuses_unmerged_index_entries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "conflict-state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.setattr(isolation, "TEMP_ROOT", tmp_path / "conflict-temp")

    repo = tmp_path / "conflict-repository"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    _git(repo, "config", "user.name", "Conflict Test")
    _git(repo, "config", "user.email", "conflict@example.invalid")
    (repo / "conflict.py").write_text("BASE\n", encoding="utf-8")
    _git(repo, "add", "--", "conflict.py")
    _git(repo, "commit", "--quiet", "-m", "baseline")
    _git(repo, "checkout", "--quiet", "-b", "side")
    (repo / "conflict.py").write_text("SIDE\n", encoding="utf-8")
    _git(repo, "commit", "--quiet", "-am", "side")
    _git(repo, "checkout", "--quiet", "main")
    (repo / "conflict.py").write_text("MAIN\n", encoding="utf-8")
    _git(repo, "commit", "--quiet", "-am", "main")
    merge = subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(repo), "merge", "side"],
        cwd="/",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert merge.returncode != 0
    assert _git(repo, "ls-files", "--unmerged", "--", "conflict.py").strip()

    exit_code = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "conflict.py",
            "--summary",
        ]
    )
    assert exit_code == 2
    assert "unmerged" in capsys.readouterr().err
