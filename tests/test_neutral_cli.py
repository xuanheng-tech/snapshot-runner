from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINTS = {
    "repo-status": "repo_status_main",
    "diff-audit": "diff_audit_main",
    "branch-review": "branch_review_main",
    "test-triage": "test_triage_main",
}


@pytest.fixture
def workspace(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "target"
    repo.mkdir(mode=0o700)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "XDG_STATE_HOME": str(state),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }

    def git(*args: str) -> None:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            env=env,
            capture_output=True,
            check=True,
        )

    git("init", "-q", "-b", "main")
    (repo / "value.py").write_text("value = 1\n")
    git("add", "value.py")
    git("commit", "-qm", "baseline")
    git("switch", "-qc", "feature")
    (repo / "value.py").write_text("value = 2\n")
    git("add", "value.py")
    git("commit", "-qm", "feature")
    (repo / "value.py").write_text("value = 3\n")
    (repo / "failed.log").write_text("FAILED tests/test_value.py::test_value\n1 failed\n")
    return repo, env


def invoke(entry: str, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            f"from codex_snapshot_runner.cli import {entry}; raise SystemExit({entry}())",
            *args,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def files(repo: Path) -> dict[str, str]:
    return {
        str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in repo.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize("task", ENTRYPOINTS)
def test_neutral_and_alias_share_evidence_and_preserve_target(workspace, task: str) -> None:
    repo, env = workspace
    args = ["--repo", str(repo), "--summary"]
    if task == "branch-review":
        args.append("main")
    elif task == "test-triage":
        args.append("failed.log")
    before = files(repo)
    neutral = invoke("snapshot_runner_main", [task, *args], env)
    alias = invoke(ENTRYPOINTS[task], args, env)
    assert neutral.returncode == alias.returncode == 0
    assert neutral.stderr == alias.stderr == ""
    assert neutral.stdout == alias.stdout
    summary = json.loads(neutral.stdout)
    artifact = Path(summary["artifact"])
    assert artifact.parts[-4:-2] == ("codex-exec", "snapshots")
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == summary["snapshot_id"]
    assert json.loads(artifact.read_bytes())["producer_security_epoch"] == 4
    assert files(repo) == before
    if task == "test-triage":
        assert summary["status"] == "complete"
        assert summary["next_action"] == "open_artifact"


@pytest.mark.parametrize("args", [[], ["--repo", "relative"], ["--unexpected"]])
def test_neutral_and_alias_keep_argument_error_contract(workspace, args: list[str]) -> None:
    _, env = workspace
    neutral = invoke("snapshot_runner_main", ["repo-status", *args], env)
    alias = invoke("repo_status_main", args, env)
    assert neutral.returncode == alias.returncode == 2
    assert neutral.stdout == alias.stdout == ""
    assert neutral.stderr == alias.stderr


def test_neutral_help_version_and_legacy_human_guidance(workspace) -> None:
    repo, env = workspace
    help_result = invoke("snapshot_runner_main", ["--help"], env)
    assert help_result.returncode == 0
    assert all(task in help_result.stdout for task in ENTRYPOINTS)
    assert "--version" in help_result.stdout
    assert "untrusted evidence" in help_result.stdout
    assert "Codex" not in help_result.stdout
    version = invoke("snapshot_runner_main", ["--version"], env)
    assert version.returncode == 0 and version.stdout == "snapshot-runner 1.6.1\n"
    args = ["--repo", str(repo)]
    neutral = invoke("snapshot_runner_main", ["repo-status", *args], env)
    alias = invoke("repo_status_main", args, env)
    assert neutral.returncode == alias.returncode == 0
    assert neutral.stdout.split("manual_workflow:")[0] == alias.stdout.split("manual_workflow:")[0]
    assert "coding agent or automation" in neutral.stdout and "ChatGPT" not in neutral.stdout
    assert "coding agent or automation" in alias.stdout and "ChatGPT" not in alias.stdout
