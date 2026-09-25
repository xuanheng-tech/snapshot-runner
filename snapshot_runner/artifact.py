"""Canonical snapshot artifacts and atomic private publication."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath

from .model import (
    MAX_META_BYTES,
    MAX_SNAPSHOT_BYTES,
    PRODUCER_SECURITY_EPOCH,
    SNAPSHOT_META_SCHEMA_VERSION,
)
from .security import (
    ARTIFACT_VALIDATION_FAILED,
    SCAN_CLASSIFIER_VERSION,
    YAML_CONTENT_REFUSED,
    RunnerError,
    ScanMode,
    ScanModeBinding,
    ScanModeManifest,
    SecurityError,
    classify_scan_mode,
)


def _runner_security_error(error: SecurityError, fallback: str) -> RunnerError:
    if str(error) == YAML_CONTENT_REFUSED:
        return RunnerError(ARTIFACT_VALIDATION_FAILED, YAML_CONTENT_REFUSED)
    return RunnerError(ARTIFACT_VALIDATION_FAILED, fallback)


def _is_safe_relative_repository_path(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    candidate = PurePosixPath(value)
    return (
        value not in {".", ".."}
        and not candidate.is_absolute()
        and ".." not in candidate.parts
        and candidate.as_posix() == value
        and not any(character in value for character in ("\x00", "\r", "\n"))
    )


def _is_canonical_local_ref(value: object, prefixes: tuple[str, ...]) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefixes)
        and len(value.encode("utf-8")) <= 4096
        and not any(character in value for character in ("\x00", "\r", "\n", " "))
        and not any(fragment in value for fragment in ("..", "@{", "//"))
        and not value.endswith((".", "/"))
        and not any(character in value for character in "~^:?*[\\")
    )


def _protect_snapshot_redactions(
    value: dict[str, object],
) -> tuple[dict[str, object], dict[str, object] | None]:
    redactions = value.get("redactions")
    if isinstance(redactions, dict):
        protected = {
            **value,
            "redactions": {
                f"category_{index}": count for index, count in enumerate(redactions.values())
            },
        }
        return protected, dict(redactions)
    return value, None


def _restore_snapshot_redactions(value: object, redactions: dict[str, object] | None) -> object:
    if redactions is None:
        return value
    if not isinstance(value, dict):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "validated snapshot redaction container is invalid"
        )
    return {**value, "redactions": redactions}


def _serialize_snapshot(envelope: dict[str, object]) -> bytes:
    encoded = (
        json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            "hard output limit exceeded: snapshot.json",
        )
    return encoded


def _serialize_snapshot_meta(meta: dict[str, object]) -> bytes:
    encoded = json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(encoded) > MAX_META_BYTES:
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "hard output limit exceeded: meta")
    return encoded


def _collect_string_modes(
    value: object,
    bindings: dict[tuple[str | int, ...], ScanMode],
    path: tuple[str | int, ...] = (),
) -> None:
    if isinstance(value, str):
        bindings[path] = ScanMode.PLAIN_TEXT
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _collect_string_modes(item, bindings, (*path, index))
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                _collect_string_modes(item, bindings, (*path, key))


def _snapshot_data_scan_manifest(envelope: dict[str, object]) -> ScanModeManifest:
    data = envelope["data"]
    task = str(envelope["task"])
    assert isinstance(data, dict)
    bindings: dict[tuple[str | int, ...], ScanMode] = {}
    plain_fields: dict[str, tuple[str, ...]] = {
        "repo-status": (
            "current_branch",
            "head",
            "status_short",
            "recent_commits",
            "local_branches",
        ),
        "diff-audit": ("status_short",),
        "branch-review": (
            "base",
            "base_commit",
            "target_ref",
            "target_head",
            "merge_base_commit",
            "range_semantics",
            "commits",
        ),
        "test-triage": ("log", "log_display_name"),
    }
    for key in plain_fields[task]:
        bindings[(key,)] = ScanMode.PLAIN_TEXT
    for key in ("upstream", "ahead_behind", "baseline_kind", "baseline_oid"):
        if key in data:
            bindings[(key,)] = ScanMode.PLAIN_TEXT
    conversion_safety = data.get("conversion_safety")
    if conversion_safety is not None:
        _collect_string_modes(conversion_safety, bindings, ("conversion_safety",))
    initial_publication = data.get("initial_publication")
    if initial_publication is not None:
        _collect_string_modes(initial_publication, bindings, ("initial_publication",))
    review_scope = data.get("review_scope")
    if review_scope is not None:
        _collect_string_modes(review_scope, bindings, ("review_scope",))
    active_operation = data.get("active_operation")
    if active_operation is not None:
        _collect_string_modes(active_operation, bindings, ("active_operation",))
    if task == "diff-audit":
        bindings[("staged_diff",)] = ScanMode.UNIFIED_DIFF
        bindings[("unstaged_diff",)] = ScanMode.UNIFIED_DIFF
    elif task == "branch-review":
        bindings[("diff",)] = ScanMode.UNIFIED_DIFF
        deleted_files = data.get("deleted_files", [])
        if isinstance(deleted_files, list):
            for index, deleted in enumerate(deleted_files):
                assert isinstance(deleted, dict)
                for key in ("path", "status", "blob_oid", "blob_commit"):
                    bindings[("deleted_files", index, key)] = ScanMode.PLAIN_TEXT
    contexts = data.get("file_context", [])
    if isinstance(contexts, list):
        for index, context in enumerate(contexts):
            assert isinstance(context, dict)
            path = str(context["path"])
            bindings[("file_context", index, "path")] = ScanMode.PLAIN_TEXT
            if "source" in context:
                bindings[("file_context", index, "content")] = ScanMode.PLAIN_TEXT
                bindings[("file_context", index, "source")] = ScanMode.PLAIN_TEXT
            else:
                try:
                    bindings[("file_context", index, "content")] = classify_scan_mode(path)
                except SecurityError as exc:
                    raise _runner_security_error(
                        exc, "snapshot file-context path cannot determine a scan mode"
                    ) from exc
    actual_strings: dict[tuple[str | int, ...], ScanMode] = {}
    _collect_string_modes(data, actual_strings)
    if set(bindings) != set(actual_strings):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot scan manifest does not exactly cover task data"
        )
    return ScanModeManifest(
        SCAN_CLASSIFIER_VERSION,
        tuple(
            ScanModeBinding(path, mode)
            for path, mode in sorted(bindings.items(), key=lambda item: repr(item[0]))
        ),
    )


def _snapshot_scan_manifest(value: dict[str, object]) -> ScanModeManifest:
    bindings: dict[tuple[str | int, ...], ScanMode] = {}
    _collect_string_modes(value, bindings)
    data_manifest = _snapshot_data_scan_manifest(value)
    for binding in data_manifest.bindings:
        bindings[("data", *binding.path)] = binding.mode
    return ScanModeManifest(
        SCAN_CLASSIFIER_VERSION,
        tuple(
            ScanModeBinding(path, mode)
            for path, mode in sorted(bindings.items(), key=lambda item: repr(item[0]))
        ),
    )


def _snapshot_meta(
    snapshot_id: str,
    task: str,
    repository: str,
    snapshot_bytes: bytes,
    preview_bytes: bytes,
) -> dict[str, object]:
    return {
        "schema_version": SNAPSHOT_META_SCHEMA_VERSION,
        "producer_security_epoch": PRODUCER_SECURITY_EPOCH,
        "snapshot_id": snapshot_id,
        "task": task,
        "repository": repository,
        "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "snapshot_bytes": len(snapshot_bytes),
        "preview_sha256": hashlib.sha256(preview_bytes).hexdigest(),
        "preview_bytes": len(preview_bytes),
    }
