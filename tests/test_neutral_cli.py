from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from snapshot_runner import __version__, cli

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
@pytest.mark.parametrize("entry", ["snapshot_runner_main", "main"])
def test_collection_clis_preserve_evidence_and_target(workspace, task: str, entry: str) -> None:
    repo, env = workspace
    args = ["--repo", str(repo), "--summary"]
    if task == "branch-review":
        args.append("main")
    elif task == "test-triage":
        args.append("failed.log")
    before = files(repo)
    prefix = [] if entry == "snapshot_runner_main" else ["prepare"]
    result = invoke(entry, [*prefix, task, *args], env)
    assert result.returncode == 0
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    artifact = Path(summary["artifact"])
    assert artifact.parts[-4:-2] == ("snapshot-runner", "snapshots")
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == summary["snapshot_id"]
    assert json.loads(artifact.read_bytes())["producer_security_epoch"] == 5
    assert files(repo) == before
    # Determinism: an identical repeat reuses the same content-addressed artifact.
    repeat = invoke(entry, [*prefix, task, *args], env)
    assert repeat.returncode == 0
    assert json.loads(repeat.stdout)["snapshot_id"] == summary["snapshot_id"]
    if task == "test-triage":
        assert summary["status"] == "complete"
        assert summary["next_action"] == "open_artifact"
    elif task == "branch-review":
        # A non-empty sealed range is complete evidence awaiting review, so it must point at
        # the existing targeted selectors instead of the whole artifact.
        assert summary["status"] == "complete"
        assert summary["evidence_gap"] is False
        assert summary["result"]["commits"] == 1
        assert summary["next_action"] == "read_targeted"


@pytest.mark.parametrize("args", [[], ["--repo", "relative"], ["--unexpected"]])
def test_primary_cli_keeps_argument_error_contract(workspace, args: list[str]) -> None:
    _, env = workspace
    result = invoke("snapshot_runner_main", ["repo-status", *args], env)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.startswith("workflow_failed:")


@pytest.mark.parametrize(
    ("task", "metavar"), [("branch-review", "BASE"), ("test-triage", "TEST_LOG")]
)
def test_required_collection_argument_is_explicit_and_rejected_before_collection(
    task: str,
    metavar: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "SYNTHETIC_CLI_MARKER"
    monkeypatch.setattr(sys, "argv", [marker, task, "--repo", f"/{marker}"])
    monkeypatch.setattr(cli, "_run_prepare", lambda _args: pytest.fail("collection ran"))
    assert cli.snapshot_runner_main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(
        f"workflow_failed: {cli.ARGUMENT_ERROR}: {cli.CLI_ARGUMENT_ERROR}; "
    )
    assert f"usage: snapshot-runner {task}" in captured.err
    assert metavar in captured.err and f"[{metavar}]" not in captured.err
    assert marker not in captured.err
    assert captured.err.count("\n") == 1
    assert len(captured.err.encode("utf-8")) <= 512


@pytest.mark.parametrize(
    ("entry", "args", "guidance"),
    [
        ("main", ["prepare", "repo-status", "--initial-publish-evidence"], "diff-audit only"),
        (
            "main",
            ["prepare", "repo-status", "--scope-path", "SYNTHETIC_CLI_MARKER"],
            "diff-audit only",
        ),
        ("main", ["prepare", "test-triage"], "test-triage requires TEST_LOG"),
        (
            "main",
            ["prepare", "repo-status", "SYNTHETIC_CLI_MARKER"],
            "accepts no positional argument",
        ),
        (
            "snapshot_runner_main",
            ["diff-audit", "--generated-tree", "SYNTHETIC_CLI_MARKER"],
            "--generated-tree requires --initial-publish-evidence",
        ),
        (
            "snapshot_runner_main",
            ["diff-audit", "--initial-publish-evidence", "--scope-path", "SYNTHETIC_CLI_MARKER"],
            "--scope-path cannot combine with --initial-publish-evidence",
        ),
        (
            "snapshot_runner_main",
            ["repo-status", "--scope-path", "SYNTHETIC_CLI_MARKER"],
            "usage: snapshot-runner",
        ),
    ],
)
def test_invalid_collection_arguments_give_safe_guidance_before_collection(
    entry: str,
    args: list[str],
    guidance: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "SYNTHETIC_CLI_MARKER"
    monkeypatch.setattr(sys, "argv", [marker, *args, "--repo", f"/{marker}"])
    monkeypatch.setattr(cli, "_run_prepare", lambda _args: pytest.fail("collection ran"))
    assert getattr(cli, entry)() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith(
        f"workflow_failed: {cli.ARGUMENT_ERROR}: {cli.CLI_ARGUMENT_ERROR}"
    )
    assert guidance in captured.err
    assert marker not in captured.err
    assert captured.err.count("\n") == 1
    assert len(captured.err.encode("utf-8")) <= 512


def test_legacy_prepare_accepts_options_before_task() -> None:
    arguments = cli.build_argument_parser().parse_args(
        ["prepare", "--repo", "/fixture", "--summary", "branch-review", "main"]
    )
    assert arguments.task == "branch-review"
    assert arguments.task_argument == "main"
    assert arguments.repo == "/fixture"
    assert arguments.summary is True


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
    assert version.returncode == 0 and version.stdout == f"snapshot-runner {__version__}\n"
    prepared = invoke("snapshot_runner_main", ["repo-status", "--repo", str(repo)], env)
    assert prepared.returncode == 0
    assert "coding agent or automation" in prepared.stdout
    assert "ChatGPT" not in prepared.stdout and "Codex" not in prepared.stdout
