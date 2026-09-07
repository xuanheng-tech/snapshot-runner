from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_snapshot_runner import artifact, collect, git, security
from codex_snapshot_runner import cli as runner

GIT = "/usr/bin/git"


def _run_git(repo: Path, *arguments: str) -> None:
    result = subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments],
        cwd="/",
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


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
    repo: Path,
    *,
    initial: bool = True,
    generated_trees: tuple[str, ...] = ("generated",),
) -> artifact.SnapshotArtifact:
    target_path, target_name, runner_path = runner._validate_target_repository_path(os.fspath(repo))
    target = git._validate_target_repository_context(
        target_path,
        target_name,
        runner_path,
        artifact._state_home(target_path),
        GIT,
        "diff-audit",
    )
    return runner._prepare_snapshot(
        "diff-audit",
        None,
        target,
        GIT,
        initial_publish_evidence=initial,
        generated_trees=generated_trees,
    )


def _manifest_entry(path: str, content: bytes) -> dict[str, object]:
    return {
        "path": path,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _write_generated_tree(
    repo: Path,
    members: dict[str, bytes],
    *,
    entries: list[dict[str, object]] | None = None,
    total_bytes: int | None = None,
) -> None:
    root = repo / "generated"
    root.mkdir()
    for relative, content in members.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    manifest_entries = (
        entries
        if entries is not None
        else [_manifest_entry(path, content) for path, content in sorted(members.items())]
    )
    manifest = {
        "file_count": len(manifest_entries),
        "total_bytes": (
            sum(int(entry["bytes"]) for entry in manifest_entries)
            if total_bytes is None
            else total_bytes
        ),
        "files": manifest_entries,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True),
        encoding="utf-8",
    )


def _payload(result: artifact.SnapshotArtifact) -> dict[str, object]:
    return json.loads(result.snapshot_bytes)


def test_generated_manifest_covers_complete_initial_publication(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    for index in range(89):
        (repo / f"manual-{index:03}.txt").write_text(f"manual {index}\n", encoding="utf-8")
    members = {
        f"schema-{index:03}.json": json.dumps({"type": "object", "index": index}).encode()
        for index in range(275)
    }
    _write_generated_tree(repo, members)

    result = _prepare(repo)

    payload = _payload(result)
    publication = payload["data"]["initial_publication"]
    assert payload["truncated"] is False
    assert payload["evidence_gaps"] == []
    assert publication["complete"] is True
    assert publication["sensitive_scan"] == "complete"
    assert publication["changed_file_count"] == 365
    assert publication["covered_file_count"] == 365
    assert publication["content_file_count"] == 90
    assert publication["generated_file_count"] == 275
    assert len(publication["files"]) == 365
    assert sum(record["coverage"] == "generated_manifest" for record in publication["files"]) == 275


def test_generated_manifest_rejects_unlisted_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    members = {"one.json": b"{}", "unlisted.json": b"{}"}
    _write_generated_tree(repo, members, entries=[_manifest_entry("one.json", b"{}")])

    with pytest.raises(security.RunnerError, match="does not exactly match"):
        _prepare(repo)


def test_generated_manifest_rejects_missing_declared_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    missing = _manifest_entry("missing.json", b"{}")
    _write_generated_tree(repo, {"one.json": b"{}"}, entries=[missing])

    with pytest.raises(security.RunnerError, match="does not exactly match"):
        _prepare(repo)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("sha256", "0" * 64, "SHA-256 does not match"),
        ("bytes", 3, "size does not match"),
    ],
)
def test_generated_manifest_rejects_member_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    field: str,
    replacement: object,
    message: str,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    entry = _manifest_entry("one.json", b"{}")
    entry[field] = replacement
    _write_generated_tree(repo, {"one.json": b"{}"}, entries=[entry], total_bytes=2)

    with pytest.raises(security.RunnerError, match=message):
        _prepare(repo)


def test_generated_manifest_rejects_duplicate_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    entry = _manifest_entry("one.json", b"{}")
    _write_generated_tree(repo, {"one.json": b"{}"}, entries=[entry, entry], total_bytes=4)

    with pytest.raises(security.RunnerError, match="duplicate path"):
        _prepare(repo)


@pytest.mark.parametrize("unsafe_path", ["../outside.json", "/absolute.json"])
def test_generated_manifest_rejects_unsafe_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    entry = _manifest_entry(unsafe_path, b"{}")
    _write_generated_tree(repo, {}, entries=[entry])

    with pytest.raises(security.RunnerError, match="unsafe or invalid"):
        _prepare(repo)


def test_generated_tree_rejects_symlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    _write_generated_tree(repo, {"one.json": b"{}"})
    (repo / "generated" / "one.json").unlink()
    (repo / "generated" / "one.json").symlink_to("manifest.json")

    with pytest.raises(security.RunnerError, match="symlink"):
        _prepare(repo)


def test_generated_file_secret_pattern_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    token = "sk-proj-" + "A" * 24
    _write_generated_tree(repo, {"one.json": json.dumps({"token": token}).encode()})

    with pytest.raises(security.RunnerError, match="credential pattern"):
        _prepare(repo)


def test_ordinary_source_cannot_use_generated_manifest_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    _write_generated_tree(repo, {"source.py": b"VALUE = 1\n"})

    with pytest.raises(security.RunnerError, match="unsafe or invalid"):
        _prepare(repo)


@pytest.mark.parametrize(
    ("file_count", "complete", "gap_count"),
    [(128, True, 0), (129, False, 1)],
)
def test_initial_publication_has_bounded_manual_file_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    file_count: int,
    complete: bool,
    gap_count: int,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    for index in range(file_count):
        (repo / f"manual-{index:03}.txt").write_text("safe\n", encoding="utf-8")

    payload = _payload(_prepare(repo, generated_trees=()))
    publication = payload["data"]["initial_publication"]

    assert publication["complete"] is complete
    assert publication["content_file_count"] == min(file_count, 128)
    assert len(payload["evidence_gaps"]) == gap_count
    assert payload["truncated"] is (not complete)
    if not complete:
        assert payload["evidence_gaps"][0]["kind"] == "file_count_limit"


def test_normal_mode_keeps_default_64_file_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repo = _repository(monkeypatch, tmp_path)
    for index in range(65):
        (repo / f"manual-{index:03}.txt").write_text("safe\n", encoding="utf-8")

    payload = _payload(_prepare(repo, initial=False, generated_trees=()))

    assert payload["truncated"] is True
    assert len(payload["data"]["file_context"]) == 64
    assert payload["evidence_gaps"][0]["kind"] == "file_count_limit"


def test_generated_evidence_keeps_eight_mib_hard_limit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert collect.MAX_SNAPSHOT_BYTES == 8 * 1024 * 1024
    repo = _repository(monkeypatch, tmp_path)
    content = b"{}"
    entry = _manifest_entry("one.json", content)
    _write_generated_tree(
        repo,
        {"one.json": content},
        entries=[entry],
        total_bytes=collect.MAX_SNAPSHOT_BYTES + 1,
    )

    with pytest.raises(security.RunnerError, match="count or size bounds"):
        _prepare(repo)


def test_generated_tree_options_are_initial_diff_audit_only() -> None:
    parser = runner.build_argument_parser()
    arguments = parser.parse_args(
        ["prepare", "repo-status", "--repo", "/tmp/repo", "--initial-publish-evidence"]
    )
    with pytest.raises(security.RunnerError, match="invalid command-line arguments"):
        runner._validate_arguments(arguments)

    arguments = parser.parse_args(
        ["prepare", "diff-audit", "--repo", "/tmp/repo", "--generated-tree", "schemas"]
    )
    with pytest.raises(security.RunnerError, match="invalid command-line arguments"):
        runner._validate_arguments(arguments)
