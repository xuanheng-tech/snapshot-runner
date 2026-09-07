from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

import codex_snapshot_runner as runner_namespace
from codex_snapshot_runner import artifact as artifact_module
from codex_snapshot_runner import cli as runner
from codex_snapshot_runner import collect, git

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SUMMARY_KEYS = [
    "summary_schema_version",
    "runner_version",
    "command",
    "snapshot_id",
    "artifact",
    "repository",
    "head",
    "scope",
    "status",
    "next_action",
    "result",
    "truncated",
    "evidence_gap",
    "warnings",
    "warnings_omitted",
]


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


def _initialize_repository(root: Path, branch: str = "target-main") -> Path:
    repo = root / "target-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", f"--initial-branch={branch}")
    (repo / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "safe.py")
    _git(
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
        "BASELINE_COMMIT_BODY",
    )
    return repo


def _private_state(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = root / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


def _safe_snapshot(task: str) -> collect.Snapshot:
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
    return collect.Snapshot(task, PROJECT_ROOT.name, data, manifest)


def _summary_artifact(
    snapshot: collect.Snapshot, directory: Path
) -> artifact_module.SnapshotArtifact:
    envelope = snapshot.as_envelope()
    snapshot_bytes = artifact_module._serialize_snapshot(envelope)
    snapshot_id = hashlib.sha256(snapshot_bytes).hexdigest()
    return artifact_module.SnapshotArtifact(
        snapshot_id,
        snapshot.task,
        snapshot_bytes,
        envelope,
        directory / snapshot_id,
    )


def test_default_output_is_exact_and_summary_preserves_artifact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "safe.py").write_text("VALUE = 2\n", encoding="utf-8")

    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(repo)]) == 0
    captured = capsys.readouterr()
    snapshot_root = state / "codex-exec" / "snapshots"
    directories = list(snapshot_root.iterdir())
    assert len(directories) == 1
    directory = directories[0]
    assert captured.out == (
        f"snapshot_id: {directory.name}\n"
        f"snapshot: {directory / 'snapshot.json'}\n"
        f"preview: {directory / 'preview.txt'}\n"
        f"security_boundary: {collect.SECURITY_NOTICE}\n"
        "manual_workflow:\n"
        f"  1. review {directory / 'preview.txt'}\n"
        "  2. manually upload preview.txt or snapshot.json to ChatGPT\n"
        "  3. save the analysis result in the project record\n"
    )
    assert captured.err == ""

    snapshot_bytes = (directory / "snapshot.json").read_bytes()
    assert runner.main(["prepare", "repo-status", "--repo", os.fspath(repo), "--summary"]) == 0
    summary_capture = capsys.readouterr()
    summary = json.loads(summary_capture.out)
    assert summary_capture.err == ""
    assert summary["snapshot_id"] == directory.name
    assert summary["artifact"] == os.fspath(directory / "snapshot.json")
    assert (directory / "snapshot.json").read_bytes() == snapshot_bytes
    assert list(snapshot_root.iterdir()) == [directory]


@pytest.mark.parametrize(
    ("task", "task_argument", "result_keys", "next_action"),
    [
        (
            "repo-status",
            None,
            {
                "changed_files",
                "tracked_modified",
                "untracked",
                "staged",
                "unstaged",
                "upstream",
                "ahead_behind",
            },
            "open_artifact",
        ),
        (
            "diff-audit",
            None,
            {
                "changed_files",
                "tracked_modified",
                "untracked",
                "staged",
                "unstaged",
                "diff_files",
                "additions",
                "deletions",
                "file_contexts",
            },
            "open_artifact",
        ),
        (
            "branch-review",
            "target-main",
            {"commits", "diff_files", "additions", "deletions", "deleted_files", "file_contexts"},
            "continue",
        ),
        (
            "test-triage",
            "safe.log",
            {"log_characters", "log_bytes", "log_lines"},
            "open_artifact",
        ),
    ],
)
def test_summary_public_entry_emits_bounded_json_for_all_four_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    task: str,
    task_argument: str | None,
    result_keys: set[str],
    next_action: str,
) -> None:
    _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "safe.py").write_text('MARKER = "SUMMARY_DIFF_BODY"\n', encoding="utf-8")
    if task == "test-triage":
        (repo / "safe.log").write_text("SUMMARY_COMPLETE_LOG_BODY\n", encoding="utf-8")
    argv = ["prepare", task, "--repo", os.fspath(repo), "--summary"]
    if task_argument is not None:
        argv.append(task_argument)

    assert runner.main(argv) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.endswith("\n")
    assert captured.out.count("\n") == 1
    assert len(captured.out.encode("utf-8")) <= artifact_module.MAX_SUMMARY_BYTES
    for excluded in ("SUMMARY_DIFF_BODY", "SUMMARY_COMPLETE_LOG_BODY", "BASELINE_COMMIT_BODY"):
        assert excluded not in captured.out

    summary = json.loads(captured.out)
    assert list(summary) == SUMMARY_KEYS
    assert summary["summary_schema_version"] == artifact_module.SUMMARY_SCHEMA_VERSION == 1
    assert summary["runner_version"] == runner_namespace.__version__ == "1.4.0"
    assert summary["command"] == task
    assert summary["repository"] == repo.name
    assert summary["status"] == "complete"
    assert summary["next_action"] == next_action
    assert summary["truncated"] is False
    assert summary["evidence_gap"] is False
    assert summary["warnings"] == []
    assert summary["warnings_omitted"] == 0
    assert set(summary["result"]) == result_keys
    if task in {"repo-status", "branch-review"}:
        assert isinstance(summary["head"], str)
    else:
        assert summary["head"] is None

    snapshot_path = Path(summary["artifact"])
    snapshot_bytes = snapshot_path.read_bytes()
    assert snapshot_path.name == "snapshot.json"
    assert snapshot_path.parent.name == summary["snapshot_id"]
    assert hashlib.sha256(snapshot_bytes).hexdigest() == summary["snapshot_id"]
    assert json.loads(snapshot_bytes)["task"] == task


def test_summary_serialization_is_deterministic_and_does_not_mutate_artifact(
    tmp_path: Path,
) -> None:
    snapshot = _safe_snapshot("diff-audit")
    snapshot.data["staged_diff"] = (
        "diff --git a/safe.py b/safe.py\n"
        "--- a/safe.py\n"
        "+++ b/safe.py\n"
        "@@ -1 +1 @@\n"
        "---SUMMARY_OLD_BODY\n"
        "+++SUMMARY_NEW_BODY\n"
    )
    artifact = _summary_artifact(snapshot, tmp_path)
    original_snapshot_bytes = artifact.snapshot_bytes
    original_envelope_bytes = artifact_module._serialize_snapshot(artifact.envelope)

    first = artifact_module._build_summary_output(artifact, runner_namespace.__version__)
    second = artifact_module._build_summary_output(artifact, runner_namespace.__version__)

    assert first == second
    assert first.endswith(b"\n")
    assert b"SUMMARY_OLD_BODY" not in first
    assert b"SUMMARY_NEW_BODY" not in first
    assert json.loads(first)["result"]["additions"] == 1
    assert json.loads(first)["result"]["deletions"] == 1
    assert artifact.snapshot_bytes == original_snapshot_bytes
    assert artifact_module._serialize_snapshot(artifact.envelope) == original_envelope_bytes


def test_summary_warnings_are_bounded_and_surface_truncation(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("diff-audit")
    gap_count = artifact_module.SUMMARY_WARNING_LIMIT + 3
    snapshot.evidence_gaps = [
        collect.EvidenceGap("file_limit", f"safe-{index}.txt", "bounded evidence omitted", index)
        for index in range(gap_count)
    ]
    artifact = _summary_artifact(snapshot, tmp_path)

    summary = json.loads(
        artifact_module._build_summary_output(artifact, runner_namespace.__version__)
    )

    assert summary["status"] == "partial"
    assert summary["next_action"] == "open_artifact"
    assert summary["truncated"] is True
    assert summary["evidence_gap"] is True
    assert len(summary["warnings"]) == artifact_module.SUMMARY_WARNING_LIMIT
    assert summary["warnings_omitted"] == 3
    assert [warning["subject"] for warning in summary["warnings"]] == [
        f"safe-{index}.txt" for index in range(artifact_module.SUMMARY_WARNING_LIMIT)
    ]


def test_summary_collapses_exact_path_scope_without_exposing_path_list(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("diff-audit")
    snapshot.data["review_scope"] = {
        "mode": "isolated-clone",
        "paths": ["first.py", "nested/second.py"],
    }
    artifact = _summary_artifact(snapshot, tmp_path)

    output = artifact_module._build_summary_output(artifact, runner_namespace.__version__)
    summary = json.loads(output)

    assert summary["scope"] == {"kind": "exact-paths", "path_count": 2}
    assert b"first.py" not in output
    assert b"nested/second.py" not in output


def test_summary_bounds_long_scope_text_with_explicit_omission_count(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("repo-status")
    branch = "refs/heads/" + "a" * (artifact_module.SUMMARY_TEXT_LIMIT + 20)
    snapshot.data["current_branch"] = branch
    artifact = _summary_artifact(snapshot, tmp_path)

    output = artifact_module._build_summary_output(artifact, runner_namespace.__version__)
    summary = json.loads(output)

    assert summary["scope"]["branch"] == {
        "prefix": branch[: artifact_module.SUMMARY_TEXT_LIMIT],
        "omitted_characters": 31,
    }
    assert branch.encode() not in output


def test_summary_mode_preserves_failure_exit_and_error_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_repo = tmp_path / "missing-repository"
    observed: list[tuple[int, str, str]] = []
    for optional in ([], ["--summary"]):
        result = runner.main(
            ["prepare", "repo-status", "--repo", os.fspath(missing_repo), *optional]
        )
        captured = capsys.readouterr()
        observed.append((result, captured.out, captured.err))

    assert observed[0] == observed[1]
    assert observed[0][0] == 2
    assert observed[0][1] == ""
    assert observed[0][2].startswith("workflow_failed:")
