from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_snapshot_runner import artifact, collect, security


def _diff_audit_builder(repo: Path, status: str) -> collect.SnapshotBuilder:
    builder = collect.SnapshotBuilder("diff-audit", repo.name, repo)
    builder.add_text(
        "status_short", status, source="git-status", scan_mode=security.ScanMode.PLAIN_TEXT
    )
    builder.add_text(
        "staged_diff", "", source="staged-diff", scan_mode=security.ScanMode.UNIFIED_DIFF
    )
    builder.add_text(
        "unstaged_diff", "", source="unstaged-diff", scan_mode=security.ScanMode.UNIFIED_DIFF
    )
    return builder


def _synthetic_context(size: int) -> str:
    line = f"{'x' * 80}\n"
    return (line * (size // len(line) + 1))[:size]


def test_collects_codex_project_context_without_evidence_gap(tmp_path: Path) -> None:
    relative = "codex-project-context"
    content = "#!/usr/bin/env bash\nexec printf 'synthetic project context\\n'\n"
    context_path = tmp_path / relative
    context_path.write_text(content, encoding="utf-8")
    context_path.chmod(0o755)
    builder = _diff_audit_builder(tmp_path, f"?? {relative}\n")

    collect._add_context(builder, [relative])
    envelope = builder.finish().as_envelope()

    context = envelope["data"]["file_context"][0]
    preview = artifact._build_preview_summary("a" * 64, envelope)
    assert not security.is_relevant_text_path(relative)
    assert security.is_extensionless_text_candidate(relative)
    assert relative not in security.ALLOWED_EXTENSIONLESS_NAMES
    assert context["path"] == relative
    assert "synthetic project context" in context["content"]
    assert context["source"] == "worktree"
    assert context["executable"] is True
    assert envelope["evidence_gaps"] == []
    assert envelope["truncated"] is False
    assert "file_refused" not in json.dumps(envelope)
    assert "completeness: evidence_gaps=0 truncated=no incomplete=no" in preview


def test_collects_large_uv_lock_up_to_four_mib_without_evidence_gap(tmp_path: Path) -> None:
    relative = "uv.lock"
    content = _synthetic_context(collect.MAX_FILE_BYTES + 1)
    (tmp_path / relative).write_text(content, encoding="utf-8")
    builder = _diff_audit_builder(tmp_path, f" M {relative}\n")

    collect._add_context(builder, [relative])
    envelope = builder.finish().as_envelope()

    assert envelope["data"]["file_context"] == [{"path": relative, "content": content}]
    assert envelope["evidence_gaps"] == []
    assert envelope["truncated"] is False


def test_keeps_similarly_named_large_lockfile_at_ordinary_limit(tmp_path: Path) -> None:
    relative = "not-uv.lock"
    content = _synthetic_context(collect.MAX_FILE_BYTES + 1)
    (tmp_path / relative).write_text(content, encoding="utf-8")
    builder = _diff_audit_builder(tmp_path, f" M {relative}\n")

    collect._add_context(builder, [relative])
    envelope = builder.finish().as_envelope()
    preview = artifact._build_preview_summary("a" * 64, envelope)

    assert envelope["data"]["file_context"] == [
        {"path": relative, "content": content[: collect.MAX_FILE_BYTES]}
    ]
    assert envelope["evidence_gaps"] == [
        {
            "kind": "file_limit",
            "subject": relative,
            "reason": "file context truncated at 256 KiB",
            "omitted_bytes": 1,
        }
    ]
    assert envelope["truncated"] is True
    assert "completeness: evidence_gaps=1 truncated=yes incomplete=yes" in preview


def test_keeps_uv_lock_over_four_mib_incomplete(tmp_path: Path) -> None:
    relative = "uv.lock"
    content = _synthetic_context(collect.UV_LOCK_MAX_FILE_BYTES + 1)
    (tmp_path / relative).write_text(content, encoding="utf-8")
    builder = _diff_audit_builder(tmp_path, f" M {relative}\n")

    collect._add_context(builder, [relative])
    envelope = builder.finish().as_envelope()
    preview = artifact._build_preview_summary("a" * 64, envelope)

    assert envelope["data"]["file_context"] == [
        {"path": relative, "content": content[: collect.UV_LOCK_MAX_FILE_BYTES]}
    ]
    assert envelope["evidence_gaps"] == [
        {
            "kind": "file_limit",
            "subject": relative,
            "reason": "file context truncated at 4 MiB",
            "omitted_bytes": 1,
        }
    ]
    assert envelope["truncated"] is True
    assert "completeness: evidence_gaps=1 truncated=yes incomplete=yes" in preview


def test_keeps_small_regular_file_context_behavior_unchanged(tmp_path: Path) -> None:
    relative = "small.lock"
    content = "small synthetic lock context\n"
    (tmp_path / relative).write_text(content, encoding="utf-8")
    builder = _diff_audit_builder(tmp_path, f" M {relative}\n")

    collect._add_context(builder, [relative])
    envelope = builder.finish().as_envelope()

    assert envelope["data"]["file_context"] == [{"path": relative, "content": content}]
    assert envelope["evidence_gaps"] == []
    assert envelope["truncated"] is False


@pytest.mark.parametrize("relative", ["codex-project-context.foo", "artifact.dat"])
def test_keeps_unknown_extension_context_refused(tmp_path: Path, relative: str) -> None:
    (tmp_path / relative).write_text("synthetic context\n", encoding="utf-8")
    builder = _diff_audit_builder(tmp_path, f"?? {relative}\n")

    collect._add_context(builder, [relative])
    envelope = builder.finish().as_envelope()

    preview = artifact._build_preview_summary("a" * 64, envelope)
    assert not security.is_relevant_text_path(relative)
    assert not security.is_extensionless_text_candidate(relative)
    assert envelope["data"]["file_context"] == []
    assert envelope["evidence_gaps"] == [
        {
            "kind": "file_refused",
            "subject": relative,
            "reason": "sensitive or unsupported file type refused",
        }
    ]
    assert envelope["truncated"] is True
    assert "completeness: evidence_gaps=1 truncated=yes incomplete=yes" in preview
