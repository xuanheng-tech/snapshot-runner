"""Validation of the persisted snapshot 2 / producer-security-epoch 4 document format."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .artifact import (
    _is_canonical_local_ref,
    _is_safe_relative_repository_path,
    _runner_security_error,
)
from .git import IMAGE_EVIDENCE_MAX_BYTES
from .isolation import MAX_SCOPE_PATHS, REVIEW_SCOPE_MODE
from .model import (
    MAX_CONVERSION_RECORDS,
    MAX_EVIDENCE_GAPS,
    MAX_GENERATED_TREE_BYTES,
    MAX_GENERATED_TREE_FILES,
    MAX_INITIAL_CONTEXT_FILES,
    MAX_PREVIEW_BYTES,
    MAX_SNAPSHOT_BYTES,
    PRODUCER_SECURITY_EPOCH,
    REDACTION_CATEGORIES,
    SECURITY_NOTICE,
    SNAPSHOT_GIT_OID_RE,
    SNAPSHOT_ID_RE,
    SNAPSHOT_META_SCHEMA_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
    TASKS,
    TRUST_BOUNDARY,
    _publication_workspace_sha256,
)
from .security import (
    ARTIFACT_VALIDATION_FAILED,
    RunnerError,
    SecurityError,
    classify_scan_mode,
    is_extensionless_text_candidate,
    is_raster_image_evidence,
    is_sensitive_repository_path,
)
from .security import (
    is_safe_repository_name as _is_safe_repository_name,
)


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= (2**63 - 1)


def _is_exact_version(value: object, expected: int) -> bool:
    return type(value) is int and value == expected


def _require_exact_keys(
    value: object,
    required: frozenset[str] | set[str],
    *,
    optional: frozenset[str] | set[str] = frozenset(),
    description: str,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, f"{description} must be an object")
    keys = set(value)
    if not required <= keys or not keys <= required | optional:
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, f"{description} schema is invalid")
    if any(not isinstance(key, str) for key in value):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, f"{description} keys must be strings")
    return value


def _validate_snapshot_meta_schema(value: object) -> dict[str, object]:
    keys = {
        "schema_version",
        "producer_security_epoch",
        "snapshot_id",
        "task",
        "repository",
        "snapshot_sha256",
        "snapshot_bytes",
        "preview_sha256",
        "preview_bytes",
    }
    meta = _require_exact_keys(value, keys, description="snapshot meta")
    if (
        not _is_exact_version(meta.get("schema_version"), SNAPSHOT_META_SCHEMA_VERSION)
        or not _is_exact_version(meta.get("producer_security_epoch"), PRODUCER_SECURITY_EPOCH)
        or meta.get("task") not in TASKS
        or not _is_safe_repository_name(meta.get("repository"))
        or not isinstance(meta.get("snapshot_id"), str)
        or SNAPSHOT_ID_RE.fullmatch(str(meta["snapshot_id"])) is None
        or not isinstance(meta.get("snapshot_sha256"), str)
        or SNAPSHOT_ID_RE.fullmatch(str(meta["snapshot_sha256"])) is None
        or not isinstance(meta.get("preview_sha256"), str)
        or SNAPSHOT_ID_RE.fullmatch(str(meta["preview_sha256"])) is None
        or not _is_nonnegative_int(meta.get("snapshot_bytes"))
        or not _is_nonnegative_int(meta.get("preview_bytes"))
        or int(meta["snapshot_bytes"]) > MAX_SNAPSHOT_BYTES
        or int(meta["preview_bytes"]) > MAX_PREVIEW_BYTES
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot meta schema is invalid")
    return meta


CONVERSION_DISABLED_TYPES = frozenset(
    {
        "clean_filter",
        "content_filter_attribute",
        "external_attributes_file",
        "external_diff",
        "external_diff_driver",
        "process_filter",
        "required_filter",
        "smudge_filter",
        "textconv",
    }
)


def _is_optional_oid(value: object) -> bool:
    return value is None or (
        isinstance(value, str) and SNAPSHOT_GIT_OID_RE.fullmatch(value) is not None
    )


def _is_optional_nonnegative_int(value: object) -> bool:
    return value is None or _is_nonnegative_int(value)


def _validate_conversion_safety(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "external_commands_executed",
        "content_diff_complete",
        "disabled_config_types",
        "files",
    }:
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot conversion-safety schema is invalid"
        )
    disabled_config_types = value.get("disabled_config_types")
    files = value.get("files")
    if (
        value.get("external_commands_executed") is not False
        or not isinstance(value.get("content_diff_complete"), bool)
        or not isinstance(disabled_config_types, list)
        or any(
            not isinstance(disabled_type, str) or disabled_type not in CONVERSION_DISABLED_TYPES
            for disabled_type in disabled_config_types
        )
        or disabled_config_types != sorted(set(disabled_config_types))
        or not isinstance(files, list)
        or len(files) > MAX_CONVERSION_RECORDS
        or value.get("content_diff_complete") is not (not bool(files))
    ):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot conversion-safety summary is invalid"
        )
    expected_file_keys = {
        "path",
        "tracked",
        "untracked",
        "staged_status",
        "unstaged_status",
        "old_blob_oid",
        "old_blob_size",
        "new_blob_oid",
        "new_blob_size",
        "index_stages",
        "conversion_required",
        "disabled_types",
        "raw_content_captured",
        "converted_content_unavailable_reason",
        "worktree_state",
        "worktree_size",
    }
    for file_record in files:
        if not isinstance(file_record, dict) or set(file_record) != expected_file_keys:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot conversion file schema is invalid"
            )
        disabled_types = file_record.get("disabled_types")
        index_stages = file_record.get("index_stages")
        if (
            not _is_safe_relative_repository_path(file_record.get("path"))
            or not isinstance(file_record.get("tracked"), bool)
            or not isinstance(file_record.get("untracked"), bool)
            or file_record.get("tracked") is file_record.get("untracked")
            or file_record.get("staged_status") not in {"changed", "unchanged", "not_applicable"}
            or file_record.get("unstaged_status")
            not in {
                "not_applicable",
                "raw_changed",
                "raw_unchanged",
                "unknown_conversion_required",
            }
            or not _is_optional_oid(file_record.get("old_blob_oid"))
            or not _is_optional_nonnegative_int(file_record.get("old_blob_size"))
            or not _is_optional_oid(file_record.get("new_blob_oid"))
            or not _is_optional_nonnegative_int(file_record.get("new_blob_size"))
            or file_record.get("conversion_required") is not True
            or not isinstance(file_record.get("raw_content_captured"), bool)
            or not isinstance(file_record.get("converted_content_unavailable_reason"), str)
            or not isinstance(file_record.get("worktree_state"), str)
            or not _is_optional_nonnegative_int(file_record.get("worktree_size"))
            or not isinstance(disabled_types, list)
            or not disabled_types
            or any(
                not isinstance(disabled_type, str) or disabled_type not in CONVERSION_DISABLED_TYPES
                for disabled_type in disabled_types
            )
            or disabled_types != sorted(set(disabled_types))
            or not isinstance(index_stages, list)
            or len(index_stages) > 4
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot conversion file metadata is invalid"
            )
        for index_entry in index_stages:
            if (
                not isinstance(index_entry, dict)
                or set(index_entry) != {"stage", "object_id", "mode"}
                or index_entry.get("stage") not in {0, 1, 2, 3}
                or SNAPSHOT_GIT_OID_RE.fullmatch(str(index_entry.get("object_id"))) is None
                or re.fullmatch(r"[0-7]{6}", str(index_entry.get("mode"))) is None
            ):
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED, "snapshot conversion index metadata is invalid"
                )


def _validate_review_scope(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"mode", "paths"}:
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot review-scope schema is invalid")
    paths = value.get("paths")
    if (
        value.get("mode") != REVIEW_SCOPE_MODE
        or not isinstance(paths, list)
        or not paths
        or len(paths) > MAX_SCOPE_PATHS
        or paths != sorted(paths)
        or len(set(paths)) != len(paths)
        or any(
            not _is_safe_relative_repository_path(path)
            or path == ".git"
            or path.startswith(".git/")
            or "\t" in path
            or is_sensitive_repository_path(path)
            for path in paths
        )
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot review-scope schema is invalid")


def _validate_active_operation(value: object) -> None:
    if not isinstance(value, dict):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid")
    op_type = value.get("type")
    if not isinstance(op_type, str):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid")

    if op_type == "merge":
        allowed = {"type", "heads", "message", "mode"}
        if not set(value).issubset(allowed) or "heads" not in value:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        heads = value["heads"]
        if not isinstance(heads, list) or not (1 <= len(heads) <= 64):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        for head in heads:
            if not isinstance(head, str) or SNAPSHOT_GIT_OID_RE.fullmatch(head) is None:
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
                )
        if "message" in value and (
            not isinstance(value["message"], str) or len(value["message"]) > 4096
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        if "mode" in value and (not isinstance(value["mode"], str) or len(value["mode"]) > 256):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
    elif op_type in {"cherry-pick", "revert"}:
        allowed = {"type", "head"}
        if set(value) != allowed:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        head = value["head"]
        if not isinstance(head, str) or SNAPSHOT_GIT_OID_RE.fullmatch(head) is None:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
    elif op_type == "rebase":
        required = {"type", "head_name", "onto", "orig_head"}
        allowed = {
            "type",
            "head_name",
            "onto",
            "orig_head",
            "stopped_sha",
            "step",
            "total_steps",
            "interactive",
        }
        if not (required <= set(value) <= allowed):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        head_name = value["head_name"]
        if (
            not isinstance(head_name, str)
            or not head_name
            or len(head_name) > 4096
            or "\n" in head_name
            or "\r" in head_name
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        for key in ("onto", "orig_head"):
            val = value[key]
            if not isinstance(val, str) or SNAPSHOT_GIT_OID_RE.fullmatch(val) is None:
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
                )
        if "stopped_sha" in value:
            sha = value["stopped_sha"]
            if sha is not None and (
                not isinstance(sha, str) or SNAPSHOT_GIT_OID_RE.fullmatch(sha) is None
            ):
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
                )
        if "interactive" in value and not isinstance(value["interactive"], bool):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        for key in ("step", "total_steps"):
            if key in value:
                num = value[key]
                if num is not None and (
                    isinstance(num, bool) or not isinstance(num, int) or num < 0
                ):
                    raise RunnerError(
                        ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
                    )
    elif op_type == "bisect":
        allowed = {"type", "start"}
        if set(value) != allowed:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        start = value["start"]
        if (
            not isinstance(start, str)
            or not start
            or len(start) > 4096
            or "\n" in start
            or "\r" in start
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
    elif op_type == "am":
        allowed = {"type", "step", "total_steps"}
        if not set(value).issubset(allowed):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
            )
        for key in ("step", "total_steps"):
            if key in value:
                num = value[key]
                if num is not None and (
                    isinstance(num, bool) or not isinstance(num, int) or num < 0
                ):
                    raise RunnerError(
                        ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid"
                    )
    else:
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot active-operation schema is invalid")


def _validate_initial_publication(
    value: object,
    contexts: list[object],
    *,
    truncated: bool,
) -> None:
    publication_keys = {
        "schema_version",
        "mode",
        "complete",
        "sensitive_scan",
        "changed_file_count",
        "covered_file_count",
        "content_file_count",
        "generated_file_count",
        "workspace_sha256",
        "files",
        "generated_trees",
    }
    publication = _require_exact_keys(
        value,
        publication_keys,
        description="initial publication evidence",
    )
    files = publication.get("files")
    trees = publication.get("generated_trees")
    counts = (
        publication.get("changed_file_count"),
        publication.get("covered_file_count"),
        publication.get("content_file_count"),
        publication.get("generated_file_count"),
    )
    if (
        not _is_exact_version(publication.get("schema_version"), 1)
        or publication.get("mode") != "unborn"
        or not isinstance(publication.get("complete"), bool)
        or publication.get("sensitive_scan") not in {"complete", "partial"}
        or any(not _is_nonnegative_int(count) for count in counts)
        or not isinstance(files, list)
        or not isinstance(trees, list)
        or not isinstance(publication.get("workspace_sha256"), str)
        or SNAPSHOT_ID_RE.fullmatch(str(publication.get("workspace_sha256"))) is None
    ):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            "initial publication evidence schema is invalid",
        )
    changed_count, covered_count, content_count, generated_count = (int(item) for item in counts)
    if (
        content_count > MAX_INITIAL_CONTEXT_FILES
        or generated_count > MAX_GENERATED_TREE_FILES
        or changed_count > MAX_INITIAL_CONTEXT_FILES + MAX_GENERATED_TREE_FILES
        or covered_count != len(files)
        or covered_count != content_count + generated_count
        or covered_count > changed_count
    ):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            "initial publication evidence counts are invalid",
        )

    content_keys = {"path", "bytes", "sha256", "executable", "coverage"}
    generated_keys = {*content_keys, "manifest_path"}
    paths: list[str] = []
    content_paths: set[str] = set()
    generated_by_manifest: dict[str, list[dict[str, object]]] = {}
    generated_bytes = 0
    for file_record in files:
        if not isinstance(file_record, dict):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "initial publication file evidence is invalid",
            )
        coverage = file_record.get("coverage")
        expected_keys = content_keys if coverage == "content" else generated_keys
        path = file_record.get("path")
        byte_size = file_record.get("bytes")
        sha256 = file_record.get("sha256")
        if (
            set(file_record) != expected_keys
            or coverage not in {"content", "generated_manifest"}
            or not _is_safe_relative_repository_path(path)
            or not _is_nonnegative_int(byte_size)
            or int(byte_size) > MAX_GENERATED_TREE_BYTES
            or not isinstance(sha256, str)
            or SNAPSHOT_ID_RE.fullmatch(sha256) is None
            or not isinstance(file_record.get("executable"), bool)
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "initial publication file evidence is invalid",
            )
        assert isinstance(path, str)
        paths.append(path)
        if coverage == "content":
            content_paths.add(path)
            continue
        manifest_path = file_record.get("manifest_path")
        if (
            not _is_safe_relative_repository_path(manifest_path)
            or PurePosixPath(path).suffix.lower() != ".json"
            or path == manifest_path
            or file_record.get("executable") is not False
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "generated-manifest file evidence is invalid",
            )
        assert isinstance(manifest_path, str)
        generated_by_manifest.setdefault(manifest_path, []).append(file_record)
        generated_bytes += int(byte_size)
    if (
        paths != sorted(paths)
        or len(paths) != len(set(paths))
        or len(content_paths) != content_count
        or sum(len(items) for items in generated_by_manifest.values()) != generated_count
        or generated_bytes > MAX_GENERATED_TREE_BYTES
        or _publication_workspace_sha256(files) != publication["workspace_sha256"]
    ):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            "initial publication path coverage is invalid",
        )

    tree_keys = {
        "path",
        "manifest_path",
        "manifest_bytes",
        "manifest_sha256",
        "file_count",
        "total_bytes",
    }
    roots: list[str] = []
    seen_manifests: set[str] = set()
    for tree in trees:
        if not isinstance(tree, dict) or set(tree) != tree_keys:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "initial publication generated-tree evidence is invalid",
            )
        root = tree.get("path")
        manifest_path = tree.get("manifest_path")
        manifest_bytes = tree.get("manifest_bytes")
        manifest_sha256 = tree.get("manifest_sha256")
        file_count = tree.get("file_count")
        total_bytes = tree.get("total_bytes")
        if (
            not _is_safe_relative_repository_path(root)
            or not isinstance(root, str)
            or manifest_path != f"{root}/manifest.json"
            or manifest_path in seen_manifests
            or not _is_nonnegative_int(manifest_bytes)
            or int(manifest_bytes) > MAX_GENERATED_TREE_BYTES
            or not isinstance(manifest_sha256, str)
            or SNAPSHOT_ID_RE.fullmatch(manifest_sha256) is None
            or not _is_nonnegative_int(file_count)
            or not _is_nonnegative_int(total_bytes)
            or int(file_count) > MAX_GENERATED_TREE_FILES
            or int(total_bytes) > MAX_GENERATED_TREE_BYTES
            or any(
                PurePosixPath(root).is_relative_to(PurePosixPath(existing))
                or PurePosixPath(existing).is_relative_to(PurePosixPath(root))
                for existing in roots
            )
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "initial publication generated-tree evidence is invalid",
            )
        roots.append(root)
        assert isinstance(manifest_path, str)
        seen_manifests.add(manifest_path)
        manifest_records = [
            record
            for record in files
            if record.get("coverage") == "content" and record.get("path") == manifest_path
        ]
        members = generated_by_manifest.get(manifest_path, [])
        if (
            len(manifest_records) != 1
            or manifest_records[0].get("bytes") != manifest_bytes
            or manifest_records[0].get("sha256") != manifest_sha256
            or len(members) != file_count
            or sum(int(record["bytes"]) for record in members) != total_bytes
            or any(
                not PurePosixPath(str(record["path"])).is_relative_to(PurePosixPath(root))
                for record in members
            )
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "initial publication generated-tree coverage is invalid",
            )
    if roots != sorted(roots) or set(generated_by_manifest) != seen_manifests:
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            "initial publication generated-tree declarations are invalid",
        )

    context_paths = [
        context.get("path")
        for context in contexts
        if isinstance(context, dict) and set(context) == {"path", "content"}
    ]
    contexts_match = (
        len(context_paths) == len(contexts)
        and len(context_paths) == len(set(context_paths))
        and set(context_paths) == content_paths
    )
    fully_covered = changed_count == covered_count
    expected_complete = not truncated and fully_covered and contexts_match
    if publication.get("complete") is not expected_complete or publication.get(
        "sensitive_scan"
    ) != ("complete" if fully_covered else "partial"):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            "initial publication completeness evidence is invalid",
        )


def _validate_snapshot_envelope(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot schema requires a JSON object")
    expected_keys = {
        "schema_version",
        "producer_security_epoch",
        "task",
        "repository",
        "data",
        "truncated",
        "evidence_gaps",
        "redactions",
        "trust_boundary",
        "security_notice",
    }
    if (
        set(value) != expected_keys
        or not _is_exact_version(value.get("schema_version"), SNAPSHOT_SCHEMA_VERSION)
        or not _is_exact_version(value.get("producer_security_epoch"), PRODUCER_SECURITY_EPOCH)
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot envelope schema is invalid")
    task = value.get("task")
    repository = value.get("repository")
    data = value.get("data")
    gaps = value.get("evidence_gaps")
    redactions = value.get("redactions")
    if task not in TASKS or not _is_safe_repository_name(repository):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot task or repository is invalid")
    if (
        value.get("trust_boundary") != TRUST_BOUNDARY
        or value.get("security_notice") != SECURITY_NOTICE
    ):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot threat-model declarations are invalid"
        )
    if not isinstance(data, dict) or not isinstance(gaps, list) or not isinstance(redactions, dict):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot evidence schema is invalid")
    if len(gaps) > MAX_EVIDENCE_GAPS + 1 or value.get("truncated") is not bool(gaps):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot evidence-gap schema is invalid")
    for gap in gaps:
        if (
            not isinstance(gap, dict)
            or not set(gap)
            <= {
                "kind",
                "subject",
                "reason",
                "omitted_bytes",
            }
            or not {"kind", "subject", "reason"} <= set(gap)
        ):
            raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot evidence-gap entry is invalid")
        if not all(isinstance(gap[key], str) for key in ("kind", "subject", "reason")):
            raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot evidence-gap text is invalid")
        omitted = gap.get("omitted_bytes")
        if omitted is not None and (
            not isinstance(omitted, int) or isinstance(omitted, bool) or omitted < 0
        ):
            raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot omitted-byte count is invalid")
    if any(
        not isinstance(key, str)
        or key not in REDACTION_CATEGORIES
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count <= 0
        for key, count in redactions.items()
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot redaction summary is invalid")
    required_data: dict[str, dict[str, type]] = {
        "repo-status": {
            "current_branch": str,
            "head": str,
            "status_short": str,
            "recent_commits": str,
            "local_branches": str,
        },
        "diff-audit": {
            "status_short": str,
            "staged_diff": str,
            "unstaged_diff": str,
            "file_context": list,
        },
        "branch-review": {
            "base": str,
            "base_commit": str,
            "target_ref": str,
            "target_head": str,
            "merge_base_commit": str,
            "range_semantics": str,
            "commits": str,
            "diff": str,
            "deleted_files": list,
            "file_context": list,
        },
        "test-triage": {"log": str, "log_display_name": str},
    }
    schema = required_data[str(task)]
    optional_data_by_task = {
        "repo-status": {"conversion_safety", "upstream", "ahead_behind", "active_operation"},
        "diff-audit": {
            "conversion_safety",
            "baseline_kind",
            "baseline_oid",
            "initial_publication",
            "review_scope",
        },
        "branch-review": {"conversion_safety"},
        "test-triage": set(),
    }
    optional_data = optional_data_by_task[str(task)]
    if (
        not set(schema) <= set(data)
        or not (set(data) - set(schema) <= optional_data)
        or any(not isinstance(data[key], kind) for key, kind in schema.items())
    ):
        raise RunnerError(ARTIFACT_VALIDATION_FAILED, "snapshot task data schema is invalid")
    if "conversion_safety" in data:
        _validate_conversion_safety(data["conversion_safety"])
    if "review_scope" in data:
        _validate_review_scope(data["review_scope"])
    if "active_operation" in data:
        _validate_active_operation(data["active_operation"])
    if task == "repo-status":
        upstream_fields = {"upstream", "ahead_behind"}
        present_upstream_fields = set(data) & upstream_fields
        detached = data["current_branch"] == "(detached)"
        if detached and present_upstream_fields:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "detached repository-status schema is invalid"
            )
        if not detached:
            upstream = data.get("upstream")
            ahead_behind = data.get("ahead_behind")
            target_is_valid = (
                isinstance(upstream, str)
                and bool(upstream)
                and upstream.strip() == upstream
                and "\n" not in upstream
                and "\r" not in upstream
            )
            relationship_is_valid = isinstance(ahead_behind, str) and (
                ahead_behind == "not available"
                or re.fullmatch(r"(?:0|[1-9][0-9]*) / (?:0|[1-9][0-9]*)", ahead_behind) is not None
            )
            unconfigured_with_relationship = (
                upstream == "not configured" and ahead_behind != "not available"
            )
            unborn_with_relationship = data["head"] == "unborn" and ahead_behind != "not available"
            if (
                present_upstream_fields != upstream_fields
                or not target_is_valid
                or not relationship_is_valid
                or unconfigured_with_relationship
                or unborn_with_relationship
            ):
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED,
                    "repository-status upstream schema is invalid",
                )
    if task == "diff-audit":
        baseline_fields = {"baseline_kind", "baseline_oid"}
        present_baseline_fields = set(data) & baseline_fields
        if present_baseline_fields and (
            present_baseline_fields != baseline_fields
            or data["baseline_kind"] != "empty_tree"
            or not isinstance(data["baseline_oid"], str)
            or SNAPSHOT_GIT_OID_RE.fullmatch(data["baseline_oid"]) is None
        ):
            raise RunnerError(ARTIFACT_VALIDATION_FAILED, "diff baseline schema is invalid")
        if "initial_publication" in data and present_baseline_fields != baseline_fields:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "initial publication evidence requires an unborn baseline",
            )
    contexts = data.get("file_context", [])
    if isinstance(contexts, list):
        for context in contexts:
            if not isinstance(context, dict):
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED, "snapshot file-context schema is invalid"
                )
            if set(context) == {"path", "content"}:
                if not all(isinstance(context[key], str) for key in ("path", "content")):
                    raise RunnerError(
                        ARTIFACT_VALIDATION_FAILED,
                        "snapshot file-context schema is invalid",
                    )
                try:
                    classify_scan_mode(context["path"])
                except SecurityError as exc:
                    raise _runner_security_error(
                        exc, "snapshot file-context path is invalid"
                    ) from exc
                continue
            allowed_sources = (
                {"index", "worktree", "untracked"}
                if task == "diff-audit"
                else {"target"}
                if task == "branch-review"
                else set()
            )
            if (
                set(context) != {"path", "content", "source", "executable"}
                or not isinstance(context.get("path"), str)
                or not isinstance(context.get("content"), str)
                or context.get("source") not in allowed_sources
                or not isinstance(context.get("executable"), bool)
                or not (
                    is_extensionless_text_candidate(str(context.get("path")))
                    or is_raster_image_evidence(
                        str(context.get("path")),
                        str(context.get("content")),
                        maximum_bytes=IMAGE_EVIDENCE_MAX_BYTES,
                    )
                )
            ):
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED,
                    "snapshot versioned file-context schema is invalid",
                )
    if "initial_publication" in data:
        _validate_initial_publication(
            data["initial_publication"],
            contexts,
            truncated=bool(value["truncated"]),
        )
    if task == "branch-review":
        if (
            not _is_canonical_local_ref(data["base"], ("refs/heads/", "refs/tags/"))
            or not _is_canonical_local_ref(data["target_ref"], ("refs/heads/",))
            or data["range_semantics"] != "merge-base-to-target-head"
            or any(
                SNAPSHOT_GIT_OID_RE.fullmatch(str(data[key])) is None
                for key in ("base_commit", "target_head", "merge_base_commit")
            )
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "branch-review sealed range schema is invalid"
            )
        deleted_files = data["deleted_files"]
        assert isinstance(deleted_files, list)
        for deleted in deleted_files:
            if (
                not isinstance(deleted, dict)
                or set(deleted) != {"path", "status", "blob_oid", "blob_size", "blob_commit"}
                or deleted.get("status") != "deleted"
                or not _is_safe_relative_repository_path(deleted.get("path"))
                or SNAPSHOT_GIT_OID_RE.fullmatch(str(deleted.get("blob_oid"))) is None
                or not _is_nonnegative_int(deleted.get("blob_size"))
                or deleted.get("blob_commit") != data["merge_base_commit"]
            ):
                raise RunnerError(
                    ARTIFACT_VALIDATION_FAILED, "branch-review deleted-file metadata is invalid"
                )
    return value
