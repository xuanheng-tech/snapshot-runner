from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TASKS = ("repo-status", "diff-audit", "branch-review", "test-triage")
# 2.0.0 removed the provider-named alias entrypoints.
REMOVED_ALIAS_ENTRYPOINTS = (
    "repo_status_main",
    "diff_audit_main",
    "branch_review_main",
    "test_triage_main",
)


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
            f"from snapshot_runner.cli import {entry}; raise SystemExit({entry}())",
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


@pytest.mark.parametrize("task", TASKS)
def test_primary_cli_collects_evidence_and_preserves_target(workspace, task: str) -> None:
    repo, env = workspace
    args = ["--repo", str(repo), "--summary"]
    if task == "branch-review":
        args.append("main")
    elif task == "test-triage":
        args.append("failed.log")
    before = files(repo)
    result = invoke("snapshot_runner_main", [task, *args], env)
    assert result.returncode == 0
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    artifact = Path(summary["artifact"])
    assert artifact.parts[-4:-2] == ("snapshot-runner", "snapshots")
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == summary["snapshot_id"]
    assert json.loads(artifact.read_bytes())["producer_security_epoch"] == 4
    assert files(repo) == before
    # Determinism: an identical repeat reuses the same content-addressed artifact.
    repeat = invoke("snapshot_runner_main", [task, *args], env)
    assert repeat.returncode == 0
    assert json.loads(repeat.stdout)["snapshot_id"] == summary["snapshot_id"]
    if task == "test-triage":
        assert summary["status"] == "complete"
        assert summary["next_action"] == "open_artifact"


@pytest.mark.parametrize("args", [[], ["--repo", "relative"], ["--unexpected"]])
def test_primary_cli_keeps_argument_error_contract(workspace, args: list[str]) -> None:
    _, env = workspace
    result = invoke("snapshot_runner_main", ["repo-status", *args], env)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.startswith("workflow_failed:")


def test_provider_named_alias_entrypoints_no_longer_exist(workspace) -> None:
    _, env = workspace
    for entry in REMOVED_ALIAS_ENTRYPOINTS:
        result = invoke(entry, [], env)
        assert result.returncode != 0
        assert "ImportError" in result.stderr or "cannot import name" in result.stderr


def test_primary_help_version_and_neutral_guidance(workspace) -> None:
    repo, env = workspace
    help_result = invoke("snapshot_runner_main", ["--help"], env)
    assert help_result.returncode == 0
    assert all(task in help_result.stdout for task in TASKS)
    assert "--version" in help_result.stdout
    assert "untrusted evidence" in help_result.stdout
    assert "Codex" not in help_result.stdout
    version = invoke("snapshot_runner_main", ["--version"], env)
    assert version.returncode == 0 and version.stdout == "snapshot-runner 2.0.0\n"
    prepared = invoke("snapshot_runner_main", ["repo-status", "--repo", str(repo)], env)
    assert prepared.returncode == 0
    assert "coding agent or automation" in prepared.stdout
    assert "ChatGPT" not in prepared.stdout and "Codex" not in prepared.stdout
