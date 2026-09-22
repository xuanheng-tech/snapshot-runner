from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import snapshot_runner as runner_namespace
from snapshot_runner import artifact as artifact_module
from snapshot_runner import cli as runner
from snapshot_runner import collect, git

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_KEYS = [
    "evidence_schema_version",
    "runner_version",
    "command",
    "snapshot_id",
    "repository",
    "artifact",
    "selector",
    "status",
    "truncated",
    "evidence_gap",
    "found",
    "evidence",
    "trust_boundary",
    "security_notice",
]
MISSING_ERROR = (
    "workflow_failed: ARTIFACT_NOT_FOUND: snapshot not found in the private snapshot store\n"
)
ARGUMENT_ERROR = "workflow_failed: ARGUMENT_ERROR: invalid command-line arguments\n"
NO_REPO_ERROR = "workflow_failed: ARGUMENT_ERROR: explicit --repo is required for read\n"
NAME_MISMATCH_ERROR = (
    "workflow_failed: ARTIFACT_VALIDATION_FAILED: snapshot repository does not match "
    "validated target\n"
)
FIELD_MISSING_ERROR = (
    "workflow_failed: ARGUMENT_ERROR: requested evidence field is not present in the "
    "snapshot task data\n"
)


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


def _initialize_repository(root: Path) -> Path:
    repo = root / "target-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet", "--initial-branch=target-main")
    (repo / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repo, "add", "safe.py")
    _git(
        repo,
        "-c",
        "user.name=Runner Test",
        "-c",
        "user.email=runner-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "TARGETED_EVIDENCE_BASELINE",
    )
    return repo


def _private_state(root: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state = root / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    monkeypatch.setenv("XDG_STATE_HOME", os.fspath(state))
    return state


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


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


def _evidence_artifact(
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


def _read_output(
    repo: Path,
    snapshot_id: str,
    capsys: pytest.CaptureFixture[str],
    *selector: str,
) -> tuple[int, str, str]:
    exit_code = runner.main(
        ["read", "--repo", os.fspath(repo), *selector, snapshot_id], neutral=True
    )
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def _prepare_summary(
    repo: Path,
    capsys: pytest.CaptureFixture[str],
    task: str = "diff-audit",
) -> dict[str, object]:
    assert runner.main([task, "--repo", os.fspath(repo), "--summary"], neutral=True) == 0
    return json.loads(capsys.readouterr().out)


def test_summary_to_targeted_read_covers_index_field_and_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "safe.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "notes.txt").write_text("NOTES_BODY\n", encoding="utf-8")
    _git(repo, "add", "notes.txt")
    repository_hashes = _file_hashes(repo)

    summary = _prepare_summary(repo, capsys)
    snapshot_id = str(summary["snapshot_id"])
    assert snapshot_id
    store_directory = state / "snapshot-runner" / "snapshots" / snapshot_id
    data = json.loads((store_directory / "snapshot.json").read_bytes())["data"]
    store_hashes = _file_hashes(store_directory)

    exit_code, out, err = _read_output(repo, snapshot_id, capsys)
    assert (exit_code, err) == (0, "")
    assert out.count("\n") == 1
    assert len(out.encode("utf-8")) <= artifact_module.MAX_EVIDENCE_BYTES
    assert os.fspath(repo) not in out
    index = json.loads(out)
    assert list(index) == EVIDENCE_KEYS
    assert index["evidence_schema_version"] == artifact_module.EVIDENCE_SCHEMA_VERSION == 1
    assert index["runner_version"] == runner_namespace.__version__
    assert index["command"] == "diff-audit"
    assert index["snapshot_id"] == snapshot_id
    assert index["repository"] == repo.name
    assert index["artifact"] == os.fspath(store_directory / "snapshot.json")
    assert index["selector"] == {"kind": "index"}
    assert index["status"] == "complete"
    assert index["truncated"] is False
    assert index["evidence_gap"] is False
    assert index["found"] is True
    assert index["trust_boundary"] == collect.TRUST_BOUNDARY
    assert index["security_notice"] == collect.SECURITY_NOTICE
    evidence = index["evidence"]
    assert [entry["field"] for entry in evidence["fields"]] == list(data)
    assert evidence["diff_sections"] == {
        "staged_diff": {"total": 1},
        "unstaged_diff": {"total": 1},
    }
    assert [(entry["path"], entry["bytes"]) for entry in evidence["file_context"]] == [
        (context["path"], len(str(context["content"]).encode("utf-8")))
        for context in data["file_context"]
    ]
    assert evidence["deleted_files"] == []
    assert evidence["conversion_safety_files"] == []
    assert evidence["initial_publication_files"] == []
    assert evidence["evidence_gaps"] == []

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--field", "status_short")
    assert (exit_code, err) == (0, "")
    field = json.loads(out)
    assert field["selector"] == {"kind": "field", "value": "status_short"}
    assert field["found"] is True
    assert field["evidence"] == {"field": "status_short", "value": data["status_short"]}

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--path", "safe.py")
    assert (exit_code, err) == (0, "")
    payload = json.loads(out)
    assert payload["found"] is True
    targeted = payload["evidence"]
    assert targeted["path"] == "safe.py"
    assert [entry["content"] for entry in targeted["file_context"]] == [
        (repo / "safe.py").read_text(encoding="utf-8")
    ]
    unstaged = targeted["diff_sections"]["unstaged_diff"]
    assert unstaged["total"] == 1
    assert unstaged["matched"] == 1
    section = unstaged["sections"][0]
    assert section.startswith("diff --git a/safe.py b/safe.py\n")
    assert section in data["unstaged_diff"]
    assert targeted["diff_sections"]["staged_diff"]["matched"] == 0
    assert targeted["evidence_gaps"] == []

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--path", "notes.txt")
    assert (exit_code, err) == (0, "")
    staged = json.loads(out)["evidence"]["diff_sections"]["staged_diff"]
    assert staged["matched"] == 1
    assert staged["sections"][0].startswith("diff --git a/notes.txt b/notes.txt\n")

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--path", "absent.py")
    assert (exit_code, err) == (0, "")
    absent = json.loads(out)
    assert absent["found"] is False
    absent_evidence = absent["evidence"]
    assert absent_evidence["file_context"] == []
    assert absent_evidence["deleted_files"] == []
    assert all(
        entry["matched"] == 0 and entry["sections"] == []
        for entry in absent_evidence["diff_sections"].values()
    )

    _, first_out, _ = _read_output(repo, snapshot_id, capsys)
    _, second_out, _ = _read_output(repo, snapshot_id, capsys)
    assert first_out == second_out
    assert _file_hashes(repo) == repository_hashes
    assert _file_hashes(store_directory) == store_hashes


def test_read_rejects_missing_or_invalid_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)

    exit_code, out, err = _read_output(repo, "a" * 64, capsys)
    assert (exit_code, out, err) == (2, "", MISSING_ERROR)

    for invalid in ("xyz", "A" * 64, "a" * 63, "a" * 63 + "g"):
        exit_code, out, err = _read_output(repo, invalid, capsys)
        assert (exit_code, out, err) == (2, "", ARGUMENT_ERROR), invalid

    exit_code = runner.main(["read", "a" * 64], neutral=True)
    captured = capsys.readouterr()
    assert (exit_code, captured.out, captured.err) == (2, "", NO_REPO_ERROR)

    exit_code, out, err = _read_output(Path("relative-repo"), "a" * 64, capsys)
    assert exit_code == 2 and out == ""
    assert err.startswith("workflow_failed: REPOSITORY_VALIDATION_FAILED:")

    exit_code, out, err = _read_output(
        repo, "a" * 64, capsys, "--field", "status_short", "--path", "safe.py"
    )
    assert (exit_code, out, err) == (2, "", ARGUMENT_ERROR)

    for invalid_path in ("../escape", "/absolute", ".git/config", "", "secret.pem"):
        exit_code, out, err = _read_output(repo, "a" * 64, capsys, "--path", invalid_path)
        assert (exit_code, out, err) == (2, "", ARGUMENT_ERROR), invalid_path


def test_read_rejects_a_field_that_the_snapshot_task_data_lacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "safe.py").write_text("VALUE = 2\n", encoding="utf-8")
    snapshot_id = str(_prepare_summary(repo, capsys)["snapshot_id"])

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--field", "not-a-field")
    assert (exit_code, out, err) == (2, "", FIELD_MISSING_ERROR)


def test_read_refuses_a_snapshot_from_a_differently_named_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "safe.py").write_text("VALUE = 2\n", encoding="utf-8")
    snapshot_id = str(_prepare_summary(repo, capsys)["snapshot_id"])

    other = tmp_path / "other-repo"
    other.mkdir()
    exit_code, out, err = _read_output(other, snapshot_id, capsys)
    assert (exit_code, out, err) == (2, "", NAME_MISMATCH_ERROR)


def test_evidence_partial_status_surfaces_gaps_without_failing(
    tmp_path: Path,
) -> None:
    snapshot = _safe_snapshot("diff-audit")
    snapshot.evidence_gaps = [
        collect.EvidenceGap("file_limit", "missing.py", "bounded evidence omitted", 7)
    ]
    artifact = _evidence_artifact(snapshot, tmp_path)

    index = json.loads(
        artifact_module._build_evidence_output(
            artifact, runner_namespace.__version__, repository_root=tmp_path
        )
    )
    assert index["status"] == "partial"
    assert index["truncated"] is True
    assert index["evidence_gap"] is True
    assert index["evidence"]["evidence_gaps"] == snapshot.as_envelope()["evidence_gaps"]

    targeted = json.loads(
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            path="missing.py",
        )
    )
    assert targeted["found"] is True
    assert [gap["subject"] for gap in targeted["evidence"]["evidence_gaps"]] == ["missing.py"]

    unrelated = json.loads(
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            path="other.py",
        )
    )
    assert unrelated["found"] is False
    assert unrelated["evidence"]["evidence_gaps"] == []


def test_path_attribution_follows_rename_metadata(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("branch-review")
    snapshot.data["diff"] = (
        "diff --git a/old.py b/new.py\n"
        "similarity index 100%\n"
        "rename from old.py\n"
        "rename to new.py\n"
        "diff --git a/keep.py b/keep.py\n"
        "--- a/keep.py\n"
        "+++ b/keep.py\n"
        "@@ -1 +1 @@\n"
        "-keep old\n"
        "+keep new\n"
    )
    artifact = _evidence_artifact(snapshot, tmp_path)

    index = json.loads(
        artifact_module._build_evidence_output(
            artifact, runner_namespace.__version__, repository_root=tmp_path
        )
    )
    assert index["evidence"]["diff_sections"] == {"diff": {"total": 2}}

    for target in ("old.py", "new.py"):
        targeted = json.loads(
            artifact_module._build_evidence_output(
                artifact,
                runner_namespace.__version__,
                repository_root=tmp_path,
                path=target,
            )
        )
        sections = targeted["evidence"]["diff_sections"]["diff"]
        assert targeted["found"] is True, target
        assert sections["total"] == 2
        assert sections["matched"] == 1
        assert sections["sections"][0].startswith("diff --git a/old.py b/new.py\n")

    unrelated = json.loads(
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            path="gone.py",
        )
    )
    assert unrelated["found"] is False
    assert unrelated["evidence"]["diff_sections"]["diff"]["matched"] == 0


def test_field_mode_is_verbatim_deterministic_and_non_mutating(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("diff-audit")
    artifact = _evidence_artifact(snapshot, tmp_path)
    original_bytes = artifact.snapshot_bytes

    first = artifact_module._build_evidence_output(
        artifact,
        runner_namespace.__version__,
        repository_root=tmp_path,
        field="file_context",
    )
    second = artifact_module._build_evidence_output(
        artifact,
        runner_namespace.__version__,
        repository_root=tmp_path,
        field="file_context",
    )
    decoded = json.loads(first)
    assert first == second
    assert decoded["evidence"]["value"] == snapshot.data["file_context"]
    assert artifact.snapshot_bytes == original_bytes

    with pytest.raises(runner.RunnerError) as excinfo:
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            field="absent",
        )
    assert excinfo.value.code == artifact_module.ARTIFACT_VALIDATION_FAILED


@pytest.mark.parametrize("task", sorted(artifact_module.TASKS))
def test_index_fields_match_every_task_data_field(
    tmp_path: Path,
    task: str,
) -> None:
    snapshot = _safe_snapshot(task)
    artifact = _evidence_artifact(snapshot, tmp_path)

    index = json.loads(
        artifact_module._build_evidence_output(
            artifact, runner_namespace.__version__, repository_root=tmp_path
        )
    )
    assert {entry["field"] for entry in index["evidence"]["fields"]} == set(snapshot.data)


def test_path_mode_finds_nothing_for_log_only_tasks(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("test-triage")
    artifact = _evidence_artifact(snapshot, tmp_path)

    targeted = json.loads(
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            path="test-output.log",
        )
    )
    assert targeted["found"] is False
    assert targeted["status"] == "complete"
    assert targeted["evidence"]["diff_sections"] == {}
    assert targeted["evidence"]["file_context"] == []


def _invoke_read_cli(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from snapshot_runner.cli import snapshot_runner_main; "
            "raise SystemExit(snapshot_runner_main())",
            *args,
        ],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def test_neutral_help_and_version_expose_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _private_state(tmp_path, monkeypatch)
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": os.fspath(home),
        "XDG_STATE_HOME": os.environ["XDG_STATE_HOME"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }

    help_result = _invoke_read_cli(["--help"], env)
    assert help_result.returncode == 0
    assert "read" in help_result.stdout
    version_result = _invoke_read_cli(["read", "--version"], env)
    assert version_result.returncode == 0
    assert version_result.stdout == f"snapshot-runner {runner_namespace.__version__}\n"


def test_read_never_needs_git_after_snapshot_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "safe.py").write_text("VALUE = 2\n", encoding="utf-8")
    snapshot_id = str(_prepare_summary(repo, capsys)["snapshot_id"])
    repository_hashes = _file_hashes(repo)

    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    env = {
        "PATH": os.fspath(empty_bin),
        "HOME": os.fspath(home),
        "XDG_STATE_HOME": os.fspath(state),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }
    result = _invoke_read_cli(
        ["read", "--repo", os.fspath(repo), "--field", "status_short", snapshot_id],
        env,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    decoded = json.loads(result.stdout)
    assert decoded["evidence"]["value"] == " M safe.py\n"
    assert _file_hashes(repo) == repository_hashes


def _path_diff_sections(
    artifact: artifact_module.SnapshotArtifact,
    tmp_path: Path,
    target: str,
) -> dict[str, object]:
    payload = json.loads(
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            path=target,
        )
    )
    return payload


def test_path_attribution_follows_copy_metadata_without_duplication(
    tmp_path: Path,
) -> None:
    snapshot = _safe_snapshot("branch-review")
    snapshot.data["diff"] = (
        "diff --git a/src.py b/dest.py\nsimilarity index 100%\ncopy from src.py\ncopy to dest.py\n"
    )
    artifact = _evidence_artifact(snapshot, tmp_path)

    index = json.loads(
        artifact_module._build_evidence_output(
            artifact, runner_namespace.__version__, repository_root=tmp_path
        )
    )
    assert index["evidence"]["diff_sections"] == {"diff": {"total": 1}}

    matched_sections: dict[str, str] = {}
    for target in ("src.py", "dest.py"):
        payload = _path_diff_sections(artifact, tmp_path, target)
        sections = payload["evidence"]["diff_sections"]["diff"]
        assert payload["found"] is True, target
        assert sections["total"] == 1
        assert sections["matched"] == 1, target
        assert len(sections["sections"]) == 1, target
        matched_sections[target] = sections["sections"][0]

    assert matched_sections["src.py"] == matched_sections["dest.py"]
    assert matched_sections["src.py"].startswith("diff --git a/src.py b/dest.py\n")

    unrelated = _path_diff_sections(artifact, tmp_path, "keep.py")
    assert unrelated["found"] is False
    assert unrelated["evidence"]["diff_sections"]["diff"]["matched"] == 0


def test_path_attribution_for_added_file_via_dev_null(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("branch-review")
    snapshot.data["diff"] = (
        "diff --git a/added.py b/added.py\n"
        "new file mode 100644\n"
        "index 0000000..abcdef1\n"
        "--- /dev/null\n"
        "+++ b/added.py\n"
        "@@ -0,0 +1 @@\n"
        "+print('added')\n"
    )
    artifact = _evidence_artifact(snapshot, tmp_path)

    added = _path_diff_sections(artifact, tmp_path, "added.py")
    assert added["found"] is True
    sections = added["evidence"]["diff_sections"]["diff"]
    assert sections["total"] == 1
    assert sections["matched"] == 1
    assert sections["sections"][0].startswith("diff --git a/added.py b/added.py\n")

    missing = _path_diff_sections(artifact, tmp_path, "absent.py")
    assert missing["found"] is False
    assert missing["evidence"]["diff_sections"]["diff"]["matched"] == 0


def test_path_attribution_for_deleted_file_via_dev_null_and_metadata(
    tmp_path: Path,
) -> None:
    snapshot = _safe_snapshot("branch-review")
    snapshot.data["diff"] = (
        "diff --git a/gone.py b/gone.py\n"
        "deleted file mode 100644\n"
        "index abcdef1..0000000\n"
        "--- a/gone.py\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-print('gone')\n"
    )
    snapshot.data["deleted_files"] = [{"path": "gone.py", "reason": "deleted"}]
    artifact = _evidence_artifact(snapshot, tmp_path)

    deleted = _path_diff_sections(artifact, tmp_path, "gone.py")
    assert deleted["found"] is True
    assert deleted["evidence"]["deleted_files"] == [{"path": "gone.py", "reason": "deleted"}]
    sections = deleted["evidence"]["diff_sections"]["diff"]
    assert sections["total"] == 1
    assert sections["matched"] == 1
    assert sections["sections"][0].startswith("diff --git a/gone.py b/gone.py\n")

    missing = _path_diff_sections(artifact, tmp_path, "keep.py")
    assert missing["found"] is False
    assert missing["evidence"]["deleted_files"] == []
    assert missing["evidence"]["diff_sections"]["diff"]["matched"] == 0


def test_path_attribution_decodes_quoted_non_ascii_paths(tmp_path: Path) -> None:
    snapshot = _safe_snapshot("branch-review")
    escaped = r"\347\233\256\345\275\225/x y.py"
    canonical = "目录/x y.py"
    snapshot.data["diff"] = (
        f'diff --git "a/{escaped}" "b/{escaped}"\n'
        f'--- "a/{escaped}"\n'
        f'+++ "b/{escaped}"\n'
        "@@ -1 +1 @@\n"
        "-before\n"
        "+after\n"
    )
    artifact = _evidence_artifact(snapshot, tmp_path)

    found = _path_diff_sections(artifact, tmp_path, canonical)
    assert found["found"] is True
    sections = found["evidence"]["diff_sections"]["diff"]
    assert sections["total"] == 1
    assert sections["matched"] == 1

    missing = _path_diff_sections(artifact, tmp_path, "absent.py")
    assert missing["found"] is False
    assert missing["evidence"]["diff_sections"]["diff"]["matched"] == 0


def test_field_mode_returns_verbatim_diff_and_caps_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert artifact_module.MAX_EVIDENCE_BYTES == 8 * 1024 * 1024

    verbatim = (
        "diff --git a/large.py b/large.py\n"
        "--- a/large.py\n"
        "+++ b/large.py\n"
        "@@ -1 +1 @@\n"
        "-" + ("old line " * 200) + "\n"
        "+" + ("new line " * 200) + "\n"
    )
    snapshot = _safe_snapshot("diff-audit")
    snapshot.data["staged_diff"] = verbatim
    artifact = _evidence_artifact(snapshot, tmp_path)

    field = json.loads(
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            field="staged_diff",
        )
    )
    assert field["evidence"] == {"field": "staged_diff", "value": verbatim}

    monkeypatch.setattr(artifact_module, "MAX_EVIDENCE_BYTES", 16)
    with pytest.raises(runner.RunnerError) as excinfo:
        artifact_module._build_evidence_output(
            artifact,
            runner_namespace.__version__,
            repository_root=tmp_path,
            field="staged_diff",
        )
    assert excinfo.value.code == artifact_module.ARTIFACT_VALIDATION_FAILED
    assert "hard output limit exceeded: evidence" in str(excinfo.value)


def _publish_csv_diff_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[Path, str, Path, dict[str, object]]:
    state = _private_state(tmp_path, monkeypatch)
    repo = _initialize_repository(tmp_path)
    (repo / "data.csv").write_text("col_a,col_b\n1,2\n", encoding="utf-8")
    _git(repo, "add", "data.csv")
    snapshot_id = str(_prepare_summary(repo, capsys)["snapshot_id"])
    store_dir = state / "snapshot-runner" / "snapshots" / snapshot_id
    envelope = json.loads((store_dir / "snapshot.json").read_bytes())
    return repo, snapshot_id, store_dir, envelope


@pytest.mark.parametrize("removal", ["delete", "move"])
def test_read_survives_removing_a_referenced_csv_after_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    removal: str,
) -> None:
    repo, snapshot_id, _store_dir, envelope = _publish_csv_diff_snapshot(
        tmp_path, monkeypatch, capsys
    )
    data = envelope["data"]
    assert isinstance(data, dict)
    staged_diff = data["staged_diff"]
    assert isinstance(staged_diff, str)
    assert "data.csv" in staged_diff

    if removal == "delete":
        (repo / "data.csv").unlink()
    else:
        (repo / "data.csv").rename(repo / "moved.csv")

    exit_code, out, err = _read_output(repo, snapshot_id, capsys)
    assert (exit_code, err) == (0, "")
    index = json.loads(out)
    assert index["selector"] == {"kind": "index"}
    assert index["snapshot_id"] == snapshot_id

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--field", "staged_diff")
    assert (exit_code, err) == (0, "")
    field = json.loads(out)
    assert field["evidence"] == {"field": "staged_diff", "value": staged_diff}

    exit_code, out, err = _read_output(repo, snapshot_id, capsys, "--path", "data.csv")
    assert (exit_code, err) == (0, "")
    payload = json.loads(out)
    assert payload["found"] is True
    staged = payload["evidence"]["diff_sections"]["staged_diff"]
    assert staged["matched"] >= 1
    assert any("data.csv" in section for section in staged["sections"])


def test_read_fails_closed_on_a_tampered_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repo, snapshot_id, store_dir, _envelope = _publish_csv_diff_snapshot(
        tmp_path, monkeypatch, capsys
    )
    path = store_dir / "snapshot.json"
    original = bytearray(path.read_bytes())
    original[len(original) // 2] ^= 0x20
    path.write_bytes(bytes(original))

    exit_code, out, err = _read_output(repo, snapshot_id, capsys)
    assert exit_code == 2
    assert out == ""
    assert err.startswith("workflow_failed: ARTIFACT_PUBLISH_FAILED:")
    assert "data.csv" not in out
