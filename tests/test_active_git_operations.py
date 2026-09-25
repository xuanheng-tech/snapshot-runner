from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from snapshot_runner import cli as runner
from snapshot_runner import legacy_v2, security

GIT = "/usr/bin/git"


def _run_git(
    repo: Path,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    cmd = [
        GIT,
        "-C",
        os.fspath(repo),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.name=Runner Test",
        "-c",
        "user.email=runner-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        *arguments,
    ]
    result = subprocess.run(
        cmd,
        cwd="/",
        capture_output=True,
        timeout=30,
        check=False,
    )
    if check:
        assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    return result


def _git_text(repo: Path, *arguments: str) -> str:
    return _run_git(repo, *arguments).stdout.decode("utf-8", errors="strict").strip()


def _initialize_repo(repo: Path, branch: str = "main") -> str:
    repo.mkdir(parents=True, exist_ok=True)
    _run_git(repo, "init", "--quiet", f"--initial-branch={branch}")
    _run_git(repo, "config", "user.name", "Runner Test")
    _run_git(repo, "config", "user.email", "runner-test@example.invalid")
    _run_git(repo, "config", "commit.gpgsign", "false")
    (repo / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    _run_git(repo, "add", "safe.py")
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
        "commit",
        "--quiet",
        "-m",
        "baseline commit",
    )
    return _git_text(repo, "rev-parse", "HEAD")


def _private_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


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


def _payload_from_summary(stdout: str) -> dict[str, object]:
    summary = json.loads(stdout)
    artifact_path = Path(summary["artifact"])
    return json.loads(artifact_path.read_text(encoding="utf-8"))


def test_ordinary_repository_preserves_existing_behavior(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)

    assert "active_operation" not in summary["result"]
    assert set(summary["result"]) == {
        "changed_files",
        "tracked_modified",
        "untracked",
        "staged",
        "unstaged",
        "upstream",
        "ahead_behind",
    }
    assert summary["status"] == "complete"
    assert summary["next_action"] == "continue"

    payload = _payload_from_summary(captured.out)
    data = payload["data"]
    assert isinstance(data, dict)
    assert "active_operation" not in data

    preview_path = Path(summary["artifact"]).with_name("preview.txt")
    preview_text = preview_path.read_text(encoding="utf-8")
    assert "active_operation:" not in preview_text


def test_active_merge_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    # Create feature branch with divergent commit
    _run_git(repo, "checkout", "-b", "feature")
    (repo / "feature.py").write_text("FEATURE = True\n", encoding="utf-8")
    _run_git(repo, "add", "feature.py")
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
        "commit",
        "-m",
        "feature commit",
    )
    feature_oid = _git_text(repo, "rev-parse", "HEAD")

    # Switch back to main and make a commit
    _run_git(repo, "checkout", "main")
    (repo / "main_work.py").write_text("WORK = True\n", encoding="utf-8")
    _run_git(repo, "add", "main_work.py")
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
        "commit",
        "-m",
        "main commit",
    )

    # Run merge with --no-commit
    _run_git(repo, "merge", "--no-commit", "--no-ff", "feature")
    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    assert (git_dir / "MERGE_HEAD").exists()

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)

    assert summary["result"]["active_operation"] == "merge"
    assert summary["next_action"] == "open_artifact"

    payload = _payload_from_summary(captured.out)
    active_op = payload["data"]["active_operation"]
    assert isinstance(active_op, dict)
    assert active_op["type"] == "merge"
    assert active_op["heads"] == [feature_oid]
    assert "Merge branch 'feature'" in active_op.get("message", "")

    preview_path = Path(summary["artifact"]).with_name("preview.txt")
    preview_text = preview_path.read_text(encoding="utf-8")
    assert "active_operation: merge\n" in preview_text


def test_active_octopus_merge_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    # Branch 1
    _run_git(repo, "checkout", "-b", "f1")
    (repo / "f1.py").write_text("F1 = 1\n", encoding="utf-8")
    _run_git(repo, "add", "f1.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "f1",
    )
    f1_oid = _git_text(repo, "rev-parse", "HEAD")

    # Branch 2
    _run_git(repo, "checkout", "main")
    _run_git(repo, "checkout", "-b", "f2")
    (repo / "f2.py").write_text("F2 = 2\n", encoding="utf-8")
    _run_git(repo, "add", "f2.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "f2",
    )
    f2_oid = _git_text(repo, "rev-parse", "HEAD")

    _run_git(repo, "checkout", "main")
    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    (git_dir / "MERGE_HEAD").write_text(f"{f1_oid}\n{f2_oid}\n", encoding="ascii")
    (git_dir / "MERGE_MSG").write_text("Octopus merge\n", encoding="utf-8")
    (git_dir / "MERGE_MODE").write_text("no-ff\n", encoding="ascii")

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    payload = _payload_from_summary(captured.out)
    active_op = payload["data"]["active_operation"]
    assert active_op == {
        "type": "merge",
        "heads": [f1_oid, f2_oid],
        "message": "Octopus merge\n",
        "mode": "no-ff",
    }


def test_active_cherry_pick_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    _run_git(repo, "checkout", "-b", "pick-branch")
    (repo / "safe.py").write_text("PICK = True\n", encoding="utf-8")
    _run_git(repo, "add", "safe.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "pick commit",
    )
    pick_oid = _git_text(repo, "rev-parse", "HEAD")

    _run_git(repo, "checkout", "main")
    (repo / "safe.py").write_text("MAIN = True\n", encoding="utf-8")
    _run_git(repo, "add", "safe.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "main update",
    )

    _run_git(repo, "cherry-pick", pick_oid, check=False)
    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    assert (git_dir / "CHERRY_PICK_HEAD").exists()

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["result"]["active_operation"] == "cherry-pick"
    assert summary["next_action"] == "open_artifact"

    payload = _payload_from_summary(captured.out)
    active_op = payload["data"]["active_operation"]
    assert active_op == {"type": "cherry-pick", "head": pick_oid}

    preview_path = Path(summary["artifact"]).with_name("preview.txt")
    preview_text = preview_path.read_text(encoding="utf-8")
    assert "active_operation: cherry-pick\n" in preview_text


def test_active_revert_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    (repo / "second.py").write_text("SECOND = True\n", encoding="utf-8")
    _run_git(repo, "add", "second.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "second commit",
    )
    second_oid = _git_text(repo, "rev-parse", "HEAD")

    _run_git(repo, "revert", "--no-commit", second_oid)
    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    assert (git_dir / "REVERT_HEAD").exists()

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["result"]["active_operation"] == "revert"
    assert summary["next_action"] == "open_artifact"

    payload = _payload_from_summary(captured.out)
    active_op = payload["data"]["active_operation"]
    assert active_op == {"type": "revert", "head": second_oid}

    preview_path = Path(summary["artifact"]).with_name("preview.txt")
    preview_text = preview_path.read_text(encoding="utf-8")
    assert "active_operation: revert\n" in preview_text


def test_active_rebase_merge_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    # Feature branch with conflict
    _run_git(repo, "checkout", "-b", "rebase-branch")
    (repo / "conflict.py").write_text("FEATURE = 1\n", encoding="utf-8")
    _run_git(repo, "add", "conflict.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "conflict feature",
    )
    feature_oid = _git_text(repo, "rev-parse", "HEAD")

    # Main with conflicting edit
    _run_git(repo, "checkout", "main")
    (repo / "conflict.py").write_text("MAIN = 2\n", encoding="utf-8")
    _run_git(repo, "add", "conflict.py")
    _run_git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "conflict main",
    )
    main_oid = _git_text(repo, "rev-parse", "HEAD")

    _run_git(repo, "checkout", "rebase-branch")
    rebase_proc = _run_git(repo, "rebase", "main", check=False)
    assert rebase_proc.returncode != 0

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    assert (git_dir / "rebase-merge").is_dir()

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["result"]["active_operation"] == "rebase"
    assert summary["next_action"] == "open_artifact"

    payload = _payload_from_summary(captured.out)
    active_op = payload["data"]["active_operation"]
    assert active_op["type"] == "rebase"
    assert active_op["onto"] == main_oid
    assert active_op["orig_head"] == feature_oid
    assert active_op["head_name"] == "refs/heads/rebase-branch"
    assert active_op["interactive"] is True
    assert active_op["step"] == 1
    assert active_op["total_steps"] == 1

    preview_path = Path(summary["artifact"]).with_name("preview.txt")
    preview_text = preview_path.read_text(encoding="utf-8")
    assert "active_operation: rebase\n" in preview_text


def test_active_rebase_apply_detected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    head_oid = _initialize_repo(repo)

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    rebase_apply = git_dir / "rebase-apply"
    rebase_apply.mkdir()
    (rebase_apply / "rebasing").write_text("", encoding="ascii")
    (rebase_apply / "head-name").write_text("refs/heads/main\n", encoding="ascii")
    (rebase_apply / "onto").write_text(f"{head_oid}\n", encoding="ascii")
    (rebase_apply / "orig-head").write_text(f"{head_oid}\n", encoding="ascii")
    (rebase_apply / "next").write_text("1\n", encoding="ascii")
    (rebase_apply / "last").write_text("3\n", encoding="ascii")

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"])
    assert result == 0
    captured = capsys.readouterr()
    summary = json.loads(captured.out)
    assert summary["result"]["active_operation"] == "rebase"

    payload = _payload_from_summary(captured.out)
    active_op = payload["data"]["active_operation"]
    assert active_op == {
        "type": "rebase",
        "head_name": "refs/heads/main",
        "onto": head_oid,
        "orig_head": head_oid,
        "interactive": False,
        "step": 1,
        "total_steps": 3,
    }


def test_ambiguous_operations_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    head_oid = _initialize_repo(repo)

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))

    # Conflicting merge and cherry-pick
    (git_dir / "MERGE_HEAD").write_text(f"{head_oid}\n", encoding="ascii")
    (git_dir / "CHERRY_PICK_HEAD").write_text(f"{head_oid}\n", encoding="ascii")

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)])
    assert result == 2
    captured = capsys.readouterr()
    assert (
        "workflow_failed: SNAPSHOT_COLLECTION_FAILED: ambiguous active Git operation metadata"
        in captured.err
    )

    # Conflicting rebase-merge and rebase-apply
    (git_dir / "MERGE_HEAD").unlink()
    (git_dir / "CHERRY_PICK_HEAD").unlink()
    (git_dir / "rebase-merge").mkdir()
    (git_dir / "rebase-apply").mkdir()
    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)])
    assert result == 2
    captured = capsys.readouterr()
    assert "SNAPSHOT_COLLECTION_FAILED" in captured.err

    # Orphaned REBASE_HEAD
    (git_dir / "rebase-merge").rmdir()
    (git_dir / "rebase-apply").rmdir()
    (git_dir / "REBASE_HEAD").write_text(f"{head_oid}\n", encoding="ascii")
    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)])
    assert result == 2
    captured = capsys.readouterr()
    assert "orphaned REBASE_HEAD" in captured.err


@pytest.mark.parametrize(
    ("marker_setup", "expected_err_fragment"),
    [
        (lambda gd: (gd / "MERGE_HEAD").write_text("\n", encoding="ascii"), "MERGE_HEAD is empty"),
        (
            lambda gd: (gd / "MERGE_HEAD").write_text("not-an-oid\n", encoding="ascii"),
            "invalid OID in MERGE_HEAD",
        ),
        (
            lambda gd: (gd / "MERGE_HEAD").write_text("a" * 40, encoding="ascii"),
            "missing trailing newline",
        ),
        (
            lambda gd: (gd / "MERGE_HEAD").write_bytes(b"a" * 40 + b"\r\n"),
            "carriage return in MERGE_HEAD",
        ),
        (
            lambda gd: (gd / "MERGE_HEAD").write_bytes(b"a" * 40 + b"\x00\n"),
            "null byte in MERGE_HEAD",
        ),
        (
            lambda gd: (gd / "CHERRY_PICK_HEAD").write_text("", encoding="ascii"),
            "CHERRY_PICK_HEAD missing trailing newline",
        ),
        (
            lambda gd: (gd / "CHERRY_PICK_HEAD").write_text("bad\n", encoding="ascii"),
            "invalid OID in CHERRY_PICK_HEAD",
        ),
        (
            lambda gd: (gd / "REVERT_HEAD").write_text("bad\n", encoding="ascii"),
            "invalid OID in REVERT_HEAD",
        ),
    ],
)
def test_malformed_metadata_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    marker_setup: object,
    expected_err_fragment: str,
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    marker_setup(git_dir)

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)])
    assert result == 2
    captured = capsys.readouterr()
    assert expected_err_fragment in captured.err


def test_unsafe_symlinks_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    _initialize_repo(repo)

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    (git_dir / "target_file").write_text("a" * 40 + "\n", encoding="ascii")
    os.symlink("target_file", git_dir / "MERGE_HEAD")

    result = runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)])
    assert result == 2
    captured = capsys.readouterr()
    assert "symlink MERGE_HEAD refused" in captured.err


def test_artifact_schema_validation_rejects_invalid_active_operation() -> None:
    # Unknown type
    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation({"type": "magic_rebase"})

    # Missing required keys
    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation({"type": "merge"})

    # Invalid heads
    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation({"type": "merge", "heads": []})

    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation({"type": "merge", "heads": ["invalid-oid"]})

    # Extra keys
    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation(
            {"type": "merge", "heads": ["a" * 40], "unauthorized": True}
        )

    # Invalid rebase keys
    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation(
            {
                "type": "rebase",
                "head_name": "refs/heads/main",
                "onto": "a" * 40,
                "orig_head": "b" * 40,
                "step": -1,
            }
        )

    with pytest.raises(security.RunnerError, match="snapshot active-operation schema is invalid"):
        legacy_v2._validate_active_operation(
            {
                "type": "rebase",
                "head_name": "refs/heads/main",
                "onto": "a" * 40,
                "orig_head": "b" * 40,
                "step": "one",
            }
        )


def test_active_operation_determinism(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state = _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    head_oid = _initialize_repo(repo)

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    (git_dir / "MERGE_HEAD").write_text(f"{head_oid}\n", encoding="ascii")
    (git_dir / "MERGE_MSG").write_text("Merge commit message\n", encoding="utf-8")

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)]) == 0
    snapshot_root = state / "snapshot-runner" / "snapshots"
    first_snapshot_id = list(snapshot_root.iterdir())[0].name
    first_bytes = (snapshot_root / first_snapshot_id / "snapshot.json").read_bytes()

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)]) == 0
    snapshots = list(snapshot_root.iterdir())
    assert len(snapshots) == 1
    second_bytes = (snapshot_root / first_snapshot_id / "snapshot.json").read_bytes()
    assert first_bytes == second_bytes


def test_read_only_behavior_with_active_operation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _private_state(monkeypatch, tmp_path)
    repo = tmp_path / "target-repo"
    head_oid = _initialize_repo(repo)

    git_dir = Path(_git_text(repo, "rev-parse", "--path-format=absolute", "--absolute-git-dir"))
    (git_dir / "CHERRY_PICK_HEAD").write_text(f"{head_oid}\n", encoding="ascii")

    before = _readonly_state(repo)
    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)]) == 0
    assert _readonly_state(repo) == before

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"]) == 0
    assert _readonly_state(repo) == before
