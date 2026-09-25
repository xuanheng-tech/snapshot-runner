"""Human and machine views rendered from an already-validated snapshot artifact."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .evidence import _diff_section_texts, _matched_diff_sections
from .model import (
    DIFF_EVIDENCE_FIELDS,
    EVIDENCE_SCHEMA_VERSION,
    MAX_EVIDENCE_BYTES,
    MAX_SUMMARY_BYTES,
    SECURITY_NOTICE,
    SNAPSHOT_GIT_OID_RE,
    SUMMARY_SCHEMA_VERSION,
    SUMMARY_TEXT_LIMIT,
    SUMMARY_WARNING_LIMIT,
    TASKS,
    TRUST_BOUNDARY,
    SnapshotArtifact,
)
from .security import (
    ARTIFACT_VALIDATION_FAILED,
    RunnerError,
)


def _build_preview_summary(snapshot_id: str, envelope: dict[str, object]) -> str:
    data = envelope["data"]
    assert isinstance(data, dict)
    status = data.get("status_short")
    status_lines = status.splitlines() if isinstance(status, str) else None
    if status_lines is None:
        status_counts: tuple[object, ...] = ("n/a",) * 4
    else:
        status_counts = (
            sum(line[:2] not in {"??", "!!"} for line in status_lines),
            sum(line.startswith("??") for line in status_lines),
            sum(line[0] not in {" ", "?", "!"} for line in status_lines),
            sum(line[1] not in {" ", "?", "!"} for line in status_lines),
        )

    diffs = [data[key] for key in ("staged_diff", "unstaged_diff", "diff") if key in data]
    diff_lines = [line for diff in diffs for line in diff.splitlines()]
    diff_counts: tuple[object, ...] = (
        tuple(
            sum(line.startswith(prefix) and not line.startswith(prefix * 3) for line in diff_lines)
            for prefix in "+-"
        )
        if diffs
        else ("n/a", "n/a")
    )
    changed_files = (
        len(status_lines)
        if status_lines is not None
        else (sum(line.startswith("diff --git ") for line in diff_lines) if diffs else "n/a")
    )
    branch = data.get("current_branch", data.get("target_ref"))
    if not isinstance(branch, str) or not branch or "\n" in branch or "\r" in branch:
        branch = "n/a"
    head = data.get("head", data.get("target_head"))
    if not isinstance(head, str) or (
        head != "unborn" and SNAPSHOT_GIT_OID_RE.fullmatch(head) is None
    ):
        head = "n/a"
    conversion = data.get("conversion_safety")
    review_scope = data.get("review_scope")
    active_op = data.get("active_operation")
    scope_line = ""
    if isinstance(review_scope, dict) and isinstance(review_scope.get("paths"), list):
        scope_line = (
            f"review_scope: mode={review_scope.get('mode')} "
            f"exact_paths={len(review_scope['paths'])}\n"
        )
    operation_line = ""
    if isinstance(active_op, dict) and isinstance(active_op.get("type"), str):
        operation_line = f"active_operation: {active_op['type']}\n"
    incomplete = bool(envelope["truncated"]) or (
        isinstance(conversion, dict) and conversion.get("content_diff_complete") is False
    )
    return (
        "MANUAL REVIEW REQUIRED BEFORE UPLOAD\n"
        f"snapshot_id: {snapshot_id}\ntask: {envelope['task']}\n"
        f"git: branch={branch} head={head}\n"
        f"{operation_line}"
        "changes: "
        f"tracked_modified={status_counts[0]} untracked={status_counts[1]} "
        f"staged={status_counts[2]} unstaged={status_counts[3]} changed_files={changed_files}\n"
        f"diff: additions={diff_counts[0]} deletions={diff_counts[1]}\n"
        f"{scope_line}"
        f"completeness: evidence_gaps={len(envelope['evidence_gaps'])} "
        f"truncated={'yes' if envelope['truncated'] else 'no'} "
        f"incomplete={'yes' if incomplete else 'no'}\n"
        "complete_evidence: snapshot.json (review this file for the full evidence)\n"
    )


def _summary_status_counts(data: dict[str, object]) -> dict[str, int]:
    status = data.get("status_short")
    if not isinstance(status, str):
        return {}
    lines = status.splitlines()
    return {
        "changed_files": len(lines),
        "tracked_modified": sum(line[:2] not in {"??", "!!"} for line in lines),
        "untracked": sum(line.startswith("??") for line in lines),
        "staged": sum(bool(line) and line[0] not in {" ", "?", "!"} for line in lines),
        "unstaged": sum(len(line) > 1 and line[1] not in {" ", "?", "!"} for line in lines),
    }


def _summary_diff_counts(data: dict[str, object]) -> dict[str, int]:
    diffs = [
        value
        for key in ("staged_diff", "unstaged_diff", "diff")
        if isinstance((value := data.get(key)), str)
    ]
    if not diffs:
        return {}
    lines = [line for diff in diffs for line in diff.splitlines()]
    return {
        "diff_files": sum(line.startswith("diff --git ") for line in lines),
        "additions": sum(line.startswith("+") and not line.startswith("+++ ") for line in lines),
        "deletions": sum(line.startswith("-") and not line.startswith("--- ") for line in lines),
    }


def _bounded_summary_text(value: object) -> object:
    assert isinstance(value, str)
    if len(value) <= SUMMARY_TEXT_LIMIT:
        return value
    return {
        "prefix": value[:SUMMARY_TEXT_LIMIT],
        "omitted_characters": len(value) - SUMMARY_TEXT_LIMIT,
    }


def _summary_scope(task: str, data: dict[str, object]) -> dict[str, object]:
    if task == "repo-status":
        return {"kind": "repository", "branch": _bounded_summary_text(data["current_branch"])}
    if task == "diff-audit":
        initial_publication = data.get("initial_publication")
        if isinstance(initial_publication, dict):
            return {"kind": "initial-publication"}
        review_scope = data.get("review_scope")
        if isinstance(review_scope, dict):
            paths = review_scope.get("paths")
            assert isinstance(paths, list)
            return {"kind": "exact-paths", "path_count": len(paths)}
        return {"kind": "worktree"}
    if task == "branch-review":
        return {
            "kind": "branch-range",
            "base": _bounded_summary_text(data["base"]),
            "target": _bounded_summary_text(data["target_ref"]),
        }
    return {"kind": "test-log", "name": _bounded_summary_text(data["log_display_name"])}


def _summary_result(task: str, data: dict[str, object]) -> dict[str, object]:
    if task == "repo-status":
        result = {
            **_summary_status_counts(data),
            "upstream": _bounded_summary_text(data.get("upstream", "not available")),
            "ahead_behind": data.get("ahead_behind", "not available"),
        }
        if "active_operation" in data:
            active = data["active_operation"]
            if isinstance(active, dict) and isinstance(active.get("type"), str):
                result["active_operation"] = _bounded_summary_text(active["type"])
        return result
    if task == "diff-audit":
        result: dict[str, object] = {
            **_summary_status_counts(data),
            **_summary_diff_counts(data),
            "file_contexts": len(data["file_context"]),
        }
        initial_publication = data.get("initial_publication")
        if isinstance(initial_publication, dict):
            result.update(
                {
                    "covered_files": initial_publication["covered_file_count"],
                    "content_files": initial_publication["content_file_count"],
                    "generated_files": initial_publication["generated_file_count"],
                }
            )
        return result
    if task == "branch-review":
        return {
            "commits": len(data["commits"].splitlines()),
            **_summary_diff_counts(data),
            "deleted_files": len(data["deleted_files"]),
            "file_contexts": len(data["file_context"]),
        }
    log = data["log"]
    assert isinstance(log, str)
    return {
        "log_characters": len(log),
        "log_bytes": len(log.encode("utf-8")),
        "log_lines": len(log.splitlines()),
    }


def _summary_warnings(
    envelope: dict[str, object], data: dict[str, object]
) -> tuple[list[dict[str, object]], int]:
    gaps = envelope["evidence_gaps"]
    assert isinstance(gaps, list)
    warnings = [dict(gap) for gap in gaps if isinstance(gap, dict)]
    conversion = data.get("conversion_safety")
    if isinstance(conversion, dict) and conversion.get("content_diff_complete") is False:
        warnings.append(
            {
                "kind": "content_diff_incomplete",
                "subject": "conversion_safety",
                "reason": "converted content evidence is incomplete",
            }
        )
    initial_publication = data.get("initial_publication")
    if isinstance(initial_publication, dict) and initial_publication.get("complete") is False:
        warnings.append(
            {
                "kind": "initial_publication_incomplete",
                "subject": "initial_publication",
                "reason": "initial publication evidence is incomplete",
            }
        )
    bounded = warnings[:SUMMARY_WARNING_LIMIT]
    return bounded, len(warnings) - len(bounded)


def _build_summary_output(artifact: SnapshotArtifact, runner_version: str) -> bytes:
    envelope = artifact.envelope
    task = envelope.get("task")
    data = envelope.get("data")
    repository = envelope.get("repository")
    gaps = envelope.get("evidence_gaps")
    if (
        task != artifact.task
        or task not in TASKS
        or not isinstance(data, dict)
        or not isinstance(repository, str)
        or not isinstance(gaps, list)
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "summary source artifact is invalid")

    result = _summary_result(task, data)
    truncated = envelope.get("truncated") is True
    conversion = data.get("conversion_safety")
    initial_publication = data.get("initial_publication")
    incomplete = (
        truncated
        or (isinstance(conversion, dict) and conversion.get("content_diff_complete") is False)
        or (isinstance(initial_publication, dict) and initial_publication.get("complete") is False)
    )
    if task in {"repo-status", "diff-audit"}:
        review_needed = result["changed_files"] != 0 or "active_operation" in data
    elif task == "branch-review":
        review_needed = any(result[key] != 0 for key in ("commits", "diff_files", "deleted_files"))
    else:
        review_needed = True
    # Summary counts cannot assess a mid-flight Git operation or a collected test log, and any
    # incompleteness or evidence gap has to be inspected in the artifact itself, so those still
    # require it whole. Complete evidence that merely awaits review can be fetched selectively
    # through `read --path/--field` rather than by consuming the entire snapshot.
    whole_artifact_required = (
        bool(gaps)
        or task == "test-triage"
        or (task == "repo-status" and "active_operation" in data)
    )
    if incomplete or whole_artifact_required:
        next_action = "open_artifact"
    elif review_needed:
        next_action = "read_targeted"
    else:
        next_action = "continue"
    warnings, warnings_omitted = _summary_warnings(envelope, data)
    head = (
        data.get("head")
        if task == "repo-status"
        else data.get("target_head")
        if task == "branch-review"
        else "unborn"
        if task == "diff-audit" and data.get("baseline_kind") == "empty_tree"
        else None
    )
    summary: dict[str, object] = {
        "summary_schema_version": SUMMARY_SCHEMA_VERSION,
        "runner_version": runner_version,
        "command": task,
        "snapshot_id": artifact.snapshot_id,
        "artifact": os.fspath(artifact.directory / "snapshot.json"),
        "repository": repository,
        "head": head,
        "scope": _summary_scope(task, data),
        "status": "partial" if incomplete else "complete",
        "next_action": next_action,
        "result": result,
        "truncated": truncated,
        "evidence_gap": bool(gaps),
        "warnings": warnings,
        "warnings_omitted": warnings_omitted,
    }
    encoded = json.dumps(summary, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_SUMMARY_BYTES:
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "hard output limit exceeded: summary")
    return encoded


def _encoded_evidence_size(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _evidence_index(data: dict[str, object], gaps: list[object]) -> dict[str, object]:
    fields = [{"field": key, "bytes": _encoded_evidence_size(value)} for key, value in data.items()]
    diff_sections: dict[str, object] = {}
    for key in DIFF_EVIDENCE_FIELDS:
        value = data.get(key)
        if isinstance(value, str):
            diff_sections[key] = {"total": len(_diff_section_texts(value))}
    contexts = data.get("file_context")
    file_context: list[object] = []
    if isinstance(contexts, list):
        for context in contexts:
            if not isinstance(context, dict) or not isinstance(context.get("path"), str):
                continue
            entry: dict[str, object] = {
                "path": context["path"],
                "bytes": len(str(context.get("content", "")).encode("utf-8")),
            }
            source = context.get("source")
            if isinstance(source, str):
                entry["source"] = source
            file_context.append(entry)
    deleted = data.get("deleted_files")
    deleted_files = list(deleted) if isinstance(deleted, list) else []
    conversion = data.get("conversion_safety")
    conversion_safety_files: list[object] = []
    if isinstance(conversion, dict) and isinstance(conversion.get("files"), list):
        for record in conversion["files"]:
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                conversion_safety_files.append(record["path"])
    publication = data.get("initial_publication")
    initial_publication_files: list[object] = []
    if isinstance(publication, dict) and isinstance(publication.get("files"), list):
        for record in publication["files"]:
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                initial_publication_files.append(
                    {
                        "path": record["path"],
                        "coverage": record.get("coverage"),
                        "bytes": record.get("bytes"),
                    }
                )
    return {
        "fields": fields,
        "diff_sections": diff_sections,
        "file_context": file_context,
        "deleted_files": deleted_files,
        "conversion_safety_files": conversion_safety_files,
        "initial_publication_files": initial_publication_files,
        "evidence_gaps": list(gaps),
    }


def _evidence_for_path(
    data: dict[str, object],
    gaps: list[object],
    target_path: str,
    repository_root: Path,
) -> tuple[dict[str, object], bool]:
    contexts = data.get("file_context")
    file_context: list[object] = []
    if isinstance(contexts, list):
        file_context = [
            context
            for context in contexts
            if isinstance(context, dict) and context.get("path") == target_path
        ]
    deleted = data.get("deleted_files")
    deleted_files: list[object] = []
    if isinstance(deleted, list):
        deleted_files = [
            record
            for record in deleted
            if isinstance(record, dict) and record.get("path") == target_path
        ]
    conversion = data.get("conversion_safety")
    conversion_safety_files: list[object] = []
    if isinstance(conversion, dict) and isinstance(conversion.get("files"), list):
        conversion_safety_files = [
            record
            for record in conversion["files"]
            if isinstance(record, dict) and record.get("path") == target_path
        ]
    publication = data.get("initial_publication")
    initial_publication_files: list[object] = []
    if isinstance(publication, dict) and isinstance(publication.get("files"), list):
        initial_publication_files = [
            record
            for record in publication["files"]
            if isinstance(record, dict) and record.get("path") == target_path
        ]
    targeted_gaps = [
        gap for gap in gaps if isinstance(gap, dict) and gap.get("subject") == target_path
    ]
    diff_sections: dict[str, object] = {}
    matched_any = False
    for key in DIFF_EVIDENCE_FIELDS:
        value = data.get(key)
        if isinstance(value, str):
            matched = _matched_diff_sections(value, target_path, repository_root)
            diff_sections[key] = matched
            matched_count = matched["matched"]
            matched_any = matched_any or (isinstance(matched_count, int) and matched_count > 0)
    evidence: dict[str, object] = {
        "path": target_path,
        "file_context": file_context,
        "deleted_files": deleted_files,
        "conversion_safety_files": conversion_safety_files,
        "initial_publication_files": initial_publication_files,
        "evidence_gaps": targeted_gaps,
        "diff_sections": diff_sections,
    }
    found = (
        bool(file_context)
        or bool(deleted_files)
        or bool(conversion_safety_files)
        or bool(initial_publication_files)
        or bool(targeted_gaps)
        or matched_any
    )
    return evidence, found


def _build_evidence_output(
    artifact: SnapshotArtifact,
    runner_version: str,
    *,
    repository_root: Path,
    field: str | None = None,
    path: str | None = None,
) -> bytes:
    envelope = artifact.envelope
    task = envelope.get("task")
    data = envelope.get("data")
    repository = envelope.get("repository")
    gaps = envelope.get("evidence_gaps")
    if (
        task != artifact.task
        or task not in TASKS
        or not isinstance(data, dict)
        or not isinstance(repository, str)
        or not isinstance(gaps, list)
        or (field is not None and path is not None)
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "evidence source artifact is invalid")
    truncated = envelope.get("truncated") is True
    conversion = data.get("conversion_safety")
    initial_publication = data.get("initial_publication")
    incomplete = (
        truncated
        or (isinstance(conversion, dict) and conversion.get("content_diff_complete") is False)
        or (isinstance(initial_publication, dict) and initial_publication.get("complete") is False)
    )
    if field is not None:
        if field not in data:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "evidence field selector does not match snapshot data"
            )
        selector: dict[str, object] = {"kind": "field", "value": field}
        evidence: dict[str, object] = {"field": field, "value": data[field]}
        found = True
    elif path is not None:
        selector = {"kind": "path", "value": path}
        evidence, found = _evidence_for_path(data, gaps, path, repository_root)
    else:
        selector = {"kind": "index"}
        evidence = _evidence_index(data, gaps)
        found = True
    output: dict[str, object] = {
        "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "runner_version": runner_version,
        "command": task,
        "snapshot_id": artifact.snapshot_id,
        "repository": repository,
        "artifact": os.fspath(artifact.directory / "snapshot.json"),
        "selector": selector,
        "status": "partial" if incomplete else "complete",
        "truncated": truncated,
        "evidence_gap": bool(gaps),
        "found": found,
        "evidence": evidence,
        "trust_boundary": TRUST_BOUNDARY,
        "security_notice": SECURITY_NOTICE,
    }
    encoded = json.dumps(output, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "hard output limit exceeded: evidence")
    return encoded
