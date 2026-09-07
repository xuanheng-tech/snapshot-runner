from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_snapshot_runner import cli, isolation, security


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


def _repository(tmp_path: Path) -> Path:
    repo = tmp_path / "target-repository"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=main")
    _git(repo, "config", "user.name", "Scoped Review Test")
    _git(repo, "config", "user.email", "scoped-review@example.invalid")
    for name in ("selected.py", "unrelated.py", "removed.py", "unsafe.yaml"):
        (repo / name).write_text(f"BASE_{name}\n", encoding="utf-8")
    _git(repo, "add", "--", "selected.py", "unrelated.py", "removed.py", "unsafe.yaml")
    _git(repo, "commit", "--quiet", "-m", "baseline")
    return repo


@pytest.fixture
def isolated_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path, Path]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    temp_root = tmp_path / "runner-temp"
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    monkeypatch.setattr(isolation, "TEMP_ROOT", temp_root)
    return _repository(tmp_path), state, temp_root


def _assert_no_task_directory(temp_root: Path) -> None:
    assert temp_root.is_dir()
    assert list(temp_root.iterdir()) == []


def test_scoped_diff_audit_cleans_clone_and_keeps_only_exact_paths(
    isolated_environment: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, state, temp_root = isolated_environment
    (repo / "selected.py").write_text("SELECTED_CHANGE\n", encoding="utf-8")
    (repo / "unrelated.py").write_text("UNRELATED_CHANGE\n", encoding="utf-8")
    (repo / "removed.py").unlink()
    status_before = _git(repo, "status", "--short", "--untracked-files=all")
    worktrees_before = _git(repo, "worktree", "list", "--porcelain")

    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "selected.py",
            "--scope-path",
            "removed.py",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "snapshot_id:" in output
    _assert_no_task_directory(temp_root)
    assert _git(repo, "status", "--short", "--untracked-files=all") == status_before
    assert _git(repo, "worktree", "list", "--porcelain") == worktrees_before
    snapshots = list((state / "codex-exec" / "snapshots").glob("*/snapshot.json"))
    assert len(snapshots) == 1
    payload = json.loads(snapshots[0].read_text(encoding="utf-8"))
    data = payload["data"]
    assert data["review_scope"] == {
        "mode": isolation.REVIEW_SCOPE_MODE,
        "paths": ["removed.py", "selected.py"],
    }
    assert "selected.py" in data["status_short"]
    assert "removed.py" in data["status_short"]
    assert "unrelated.py" not in json.dumps(data, ensure_ascii=False)
    preview = snapshots[0].with_name("preview.txt").read_text(encoding="utf-8")
    assert "review_scope: mode=isolated-clone exact_paths=2" in preview


def test_collection_failure_cleans_temporary_clone(
    isolated_environment: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state, temp_root = isolated_environment
    (repo / "unsafe.yaml").write_text("unsafe: changed\n", encoding="utf-8")

    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "unsafe.yaml",
        ]
    )

    assert result == 2
    assert security.YAML_CONTENT_REFUSED in capsys.readouterr().err
    _assert_no_task_directory(temp_root)


def test_unexpected_exception_cleans_temporary_clone(
    isolated_environment: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state, temp_root = isolated_environment
    (repo / "selected.py").write_text("SELECTED_CHANGE\n", encoding="utf-8")

    def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("synthetic unexpected failure")

    monkeypatch.setattr(cli, "_prepare_snapshot", fail)
    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "selected.py",
        ]
    )

    assert result == 2
    assert "RUNNER_UNEXPECTED_ERROR" in capsys.readouterr().err
    _assert_no_task_directory(temp_root)


def test_clone_command_failure_cleans_temporary_directory(
    isolated_environment: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state, temp_root = isolated_environment
    (repo / "selected.py").write_text("SELECTED_CHANGE\n", encoding="utf-8")

    def fail(*_args: object, **_kwargs: object) -> None:
        raise security.RunnerError(
            security.SNAPSHOT_COLLECTION_FAILED,
            "synthetic clone command failure",
        )

    monkeypatch.setattr(isolation, "_clone_repository", fail)
    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "selected.py",
        ]
    )

    assert result == 2
    assert "synthetic clone command failure" in capsys.readouterr().err
    _assert_no_task_directory(temp_root)


@pytest.mark.parametrize(
    "paths",
    [
        (".",),
        ("/tmp/outside.py",),
        ("../outside.py",),
        (".git/config",),
        ("selected.py", "selected.py"),
    ],
)
def test_unsafe_scope_paths_are_rejected_before_temp_creation(
    isolated_environment: tuple[Path, Path, Path],
    paths: tuple[str, ...],
) -> None:
    _repo, _state, temp_root = isolated_environment

    with pytest.raises(security.RunnerError):
        isolation.validate_scope_paths(paths)

    assert not temp_root.exists()


@pytest.mark.parametrize("relative", ["selected.py", "directory"])
def test_unchanged_or_directory_scope_is_rejected_and_cleaned(
    isolated_environment: tuple[Path, Path, Path],
    capsys: pytest.CaptureFixture[str],
    relative: str,
) -> None:
    repo, _state, temp_root = isolated_environment
    if relative == "directory":
        (repo / relative).mkdir()
        (repo / relative / "value.py").write_text("VALUE = 1\n", encoding="utf-8")

    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            relative,
        ]
    )

    assert result == 2
    capsys.readouterr()
    _assert_no_task_directory(temp_root)


def test_symlink_scope_and_symlink_cleanup_target_are_refused(
    isolated_environment: tuple[Path, Path, Path],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state, temp_root = isolated_environment
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.py"
    marker.write_text("OUTSIDE\n", encoding="utf-8")
    (repo / "linked.py").symlink_to(marker)

    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "linked.py",
        ]
    )

    assert result == 2
    capsys.readouterr()
    _assert_no_task_directory(temp_root)
    link = temp_root / "hostile-link"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(security.RunnerError):
        isolation.remove_owned_temp_directory(temp_root, link)
    assert marker.read_text(encoding="utf-8") == "OUTSIDE\n"


def test_cleanup_rejects_root_unexpected_path_and_nested_worktree(
    isolated_environment: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, _state, temp_root = isolated_environment
    temp_root.mkdir(mode=0o700)
    temp_root.chmod(0o700)
    unexpected = tmp_path / "unexpected"
    unexpected.mkdir()
    with pytest.raises(security.RunnerError):
        isolation.remove_owned_temp_directory(temp_root, temp_root)
    with pytest.raises(security.RunnerError):
        isolation.remove_owned_temp_directory(temp_root, unexpected)

    nested_root = repo / "must-not-be-created"
    monkeypatch.setattr(isolation, "TEMP_ROOT", nested_root)
    (repo / "selected.py").write_text("SELECTED_CHANGE\n", encoding="utf-8")
    result = cli.main(
        [
            "prepare",
            "diff-audit",
            "--repo",
            os.fspath(repo),
            "--scope-path",
            "selected.py",
        ]
    )
    assert result == 2
    assert "cannot be nested" in capsys.readouterr().err
    assert not nested_root.exists()
