"""Canonical snapshot artifacts and atomic private publication."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .collect import (
    IMAGE_EVIDENCE_MAX_BYTES,
    MAX_CONVERSION_RECORDS,
    MAX_EVIDENCE_GAPS,
    MAX_GENERATED_TREE_BYTES,
    MAX_GENERATED_TREE_FILES,
    MAX_INITIAL_CONTEXT_FILES,
    MAX_SNAPSHOT_BYTES,
    PRODUCER_SECURITY_EPOCH,
    SECURITY_NOTICE,
    TRUST_BOUNDARY,
    _publication_workspace_sha256,
)
from .isolation import MAX_SCOPE_PATHS, REVIEW_SCOPE_MODE
from .security import (
    ARTIFACT_PUBLISH_FAILED,
    ARTIFACT_VALIDATION_FAILED,
    REPOSITORY_VALIDATION_FAILED,
    YAML_CONTENT_REFUSED,
    RunnerError,
    ScanMode,
    ScanModeBinding,
    ScanModeManifest,
    SecurityError,
    classify_scan_mode,
    era_rules,
    is_extensionless_text_candidate,
    is_raster_image_evidence,
    is_sensitive_repository_path,
    sanitize_json_value,
    unified_diff_path_changes,
)
from .security import (
    is_safe_repository_name as _is_safe_repository_name,
)
from .security import (
    paths_overlap as _paths_overlap,
)
from .security import (
    validate_no_symlink_ancestors as _validate_no_symlink_ancestors,
)
from .verifiers import ArtifactVerifier, resolve_verifier, verifier_for

SNAPSHOT_PUBLISH_DURABILITY_ERROR = "snapshot published but snapshot-store durability sync failed"
STATE_HOME_MISSING_ERROR = "state home must already exist as a private directory"
MAX_META_BYTES = 64 * 1024
MAX_PREVIEW_BYTES = 16 * 1024 * 1024
MAX_SUMMARY_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = MAX_SNAPSHOT_BYTES
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ACTIVE_REPOSITORY_ROOT: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "_ACTIVE_REPOSITORY_ROOT", default=None
)


@contextlib.contextmanager
def active_repository_root(repository_root: Path | None):
    """Safely bind active repository root to ContextVar with guaranteed reset."""
    token = _ACTIVE_REPOSITORY_ROOT.set(repository_root)
    try:
        yield
    finally:
        _ACTIVE_REPOSITORY_ROOT.reset(token)


TASKS = ("repo-status", "diff-audit", "branch-review", "test-triage")
SNAPSHOT_ID_RE = re.compile(r"[0-9a-f]{64}")
SNAPSHOT_GIT_OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
SNAPSHOT_META_SCHEMA_VERSION = 2
SUMMARY_SCHEMA_VERSION = 2
EVIDENCE_SCHEMA_VERSION = 1
SUMMARY_TEXT_LIMIT = 256
SUMMARY_WARNING_LIMIT = 5
SNAPSHOT_FILE_NAMES = frozenset({"meta.json", "preview.txt", "snapshot.json"})
DIFF_EVIDENCE_FIELDS = ("staged_diff", "unstaged_diff", "diff")


def _runner_security_error(error: SecurityError, fallback: str) -> RunnerError:
    if str(error) == YAML_CONTENT_REFUSED:
        return RunnerError(ARTIFACT_VALIDATION_FAILED, YAML_CONTENT_REFUSED)
    return RunnerError(ARTIFACT_VALIDATION_FAILED, fallback)


@dataclass(frozen=True, slots=True)
class SnapshotArtifact:
    snapshot_id: str
    task: str
    snapshot_bytes: bytes
    envelope: dict[str, object]
    directory: Path


def _state_home(target_repo: Path | None = None) -> Path:
    raw = os.environ.get("XDG_STATE_HOME")
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, "XDG_STATE_HOME must be absolute")
    else:
        path = Path.home() / ".local" / "state"
    if ".." in path.parts:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, "state home must be a canonical path")
    normalized = Path(os.path.abspath(path))
    _validate_no_symlink_ancestors(normalized, "state home")
    try:
        resolved = normalized.resolve(strict=False)
        runner_repository = REPOSITORY_ROOT.resolve(strict=True)
        target_repository = target_repo.resolve(strict=True) if target_repo is not None else None
    except OSError as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, "unable to resolve state home") from exc
    if _paths_overlap(resolved, runner_repository) or (
        target_repository is not None and _paths_overlap(resolved, target_repository)
    ):
        raise RunnerError(
            REPOSITORY_VALIDATION_FAILED,
            "state home must be outside and separate from the repository",
        )
    try:
        state_stat = normalized.lstat()
    except FileNotFoundError as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, STATE_HOME_MISSING_ERROR) from exc
    except OSError as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, "unable to inspect state home") from exc
    if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISDIR(state_stat.st_mode):
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, "state home must be a real directory")
    if state_stat.st_uid != os.getuid():
        raise RunnerError(
            REPOSITORY_VALIDATION_FAILED, "state home must be owned by the current user"
        )
    if stat.S_IMODE(state_stat.st_mode) != 0o700:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, "state home must have mode 0700")
    return normalized


def snapshot_output_root(target_repo: Path | None = None) -> Path:
    return _state_home(target_repo) / "snapshot-runner" / "snapshots"


def _snapshot_sanitization_paths(extra_paths: tuple[Path, ...] = ()) -> tuple[Path, ...]:
    explicit = [Path.home(), *extra_paths]
    with contextlib.suppress(RunnerError):
        explicit.append(snapshot_output_root())
    return tuple(dict.fromkeys(explicit))


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


def _validate_owned_private_directory(path: Path, description: str) -> None:
    _validate_no_symlink_ancestors(path, description)
    try:
        path_stat = path.lstat()
    except OSError as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"unable to inspect {description}") from exc
    if not stat.S_ISDIR(path_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode):
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} must be a real directory")
    if path_stat.st_uid != os.getuid():
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, f"{description} must be owned by the current user"
        )
    if stat.S_IMODE(path_stat.st_mode) != 0o700:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} must have mode 0700")


def _ensure_private_state_directory(
    path: Path,
    description: str,
    target_repo: Path | None = None,
) -> None:
    state_home = _state_home(target_repo)
    _validate_owned_private_directory(state_home, "state home")
    controlled_root = state_home / "snapshot-runner"
    try:
        controlled_root.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "unable to initialize private Runner state"
        ) from exc
    _validate_owned_private_directory(controlled_root, "private Runner state")
    try:
        relative_parts = path.relative_to(controlled_root).parts
    except ValueError as exc:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "private state path escaped its controlled root"
        ) from exc
    current = controlled_root
    for component in relative_parts:
        current /= component
        try:
            current.mkdir(mode=0o700, exist_ok=True)
        except OSError as exc:
            raise RunnerError(
                ARTIFACT_PUBLISH_FAILED, f"unable to initialize {description}"
            ) from exc
        _validate_owned_private_directory(current, description)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_private_staging_directory(root: Path, prefix: str) -> Path:
    for _attempt in range(32):
        staging = root / f".staging-{prefix}-{uuid.uuid4().hex}"
        try:
            staging.mkdir(mode=0o700)
        except FileExistsError:
            continue
        _validate_owned_private_directory(staging, "staging directory")
        return staging
    raise RunnerError(ARTIFACT_PUBLISH_FAILED, "unable to allocate a private staging directory")


def _discard_known_staging(staging: Path, names: frozenset[str]) -> None:
    try:
        entries = list(staging.iterdir())
    except OSError as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "unable to inspect staging directory") from exc
    if any(entry.name not in names for entry in entries):
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "staging directory contains an unexpected entry")
    for entry in entries:
        try:
            entry.unlink()
        except OSError as exc:
            raise RunnerError(ARTIFACT_PUBLISH_FAILED, "unable to discard a staging file") from exc
    try:
        staging.rmdir()
    except OSError as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "unable to discard staging directory") from exc


REDACTION_CATEGORIES = frozenset(
    {
        "ABSOLUTE_PATH",
        "AUTH",
        "AWS_ACCESS_KEY",
        "BEARER",
        "CLI_SECRET",
        "CLOUD_CREDENTIAL",
        "COOKIE",
        "ENV_SECRET",
        "FILE_URI",
        "GITHUB_TOKEN",
        "GOOGLE_API_KEY",
        "HEADER_CREDENTIAL",
        "JSON_CREDENTIAL",
        "JWT",
        "OPENAI_TOKEN",
        "PEM_BLOCK",
        "QUERY_SECRET",
        "SLACK_TOKEN",
        "STRIPE_TOKEN",
        "URL_CREDENTIAL",
    }
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


def _validate_snapshot_meta_schema(
    value: object, verifier: ArtifactVerifier | None = None
) -> dict[str, object]:
    verifier = resolve_verifier(verifier)
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
        not _is_exact_version(meta.get("schema_version"), verifier.meta_schema_version)
        or not _is_exact_version(
            meta.get("producer_security_epoch"), verifier.producer_security_epoch
        )
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


def _diff_section_texts(diff: str) -> list[str]:
    if not diff:
        return []
    if not diff.startswith("diff --git "):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot diff evidence is not section-aligned"
        )
    sections: list[list[str]] = []
    for line in diff.splitlines(keepends=True):
        if line.startswith("diff --git "):
            sections.append([line])
        else:
            sections[-1].append(line)
    return ["".join(section) for section in sections]


def _matched_diff_sections(
    diff: str,
    target_path: str,
    repository_root: Path,
) -> dict[str, object]:
    sections = _diff_section_texts(diff)
    if not sections:
        return {"total": 0, "matched": 0, "sections": []}
    try:
        changes = unified_diff_path_changes(
            diff, repository_root=repository_root, verify_live_diff_text=False
        )
    except SecurityError as exc:
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot diff evidence failed targeted attribution"
        ) from exc
    if len(changes) != len(sections):
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED, "snapshot diff evidence failed targeted attribution"
        )
    matched = [
        section
        for section, (old_path, new_path) in zip(sections, changes, strict=True)
        if target_path in (old_path, new_path)
    ]
    return {"total": len(sections), "matched": len(matched), "sections": matched}


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


def _snapshot_data_scan_manifest(
    envelope: dict[str, object], verifier: ArtifactVerifier | None = None
) -> ScanModeManifest:
    verifier = resolve_verifier(verifier)
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
        verifier.scan_classifier_version,
        tuple(
            ScanModeBinding(path, mode)
            for path, mode in sorted(bindings.items(), key=lambda item: repr(item[0]))
        ),
    )


def _snapshot_scan_manifest(
    value: dict[str, object], verifier: ArtifactVerifier | None = None
) -> ScanModeManifest:
    verifier = resolve_verifier(verifier)
    bindings: dict[tuple[str | int, ...], ScanMode] = {}
    _collect_string_modes(value, bindings)
    data_manifest = _snapshot_data_scan_manifest(value, verifier)
    for binding in data_manifest.bindings:
        bindings[("data", *binding.path)] = binding.mode
    return ScanModeManifest(
        verifier.scan_classifier_version,
        tuple(
            ScanModeBinding(path, mode)
            for path, mode in sorted(bindings.items(), key=lambda item: repr(item[0]))
        ),
    )


def _sanitize_validate_snapshot(
    payload: object,
    repository_root: Path,
    *,
    extra_paths: tuple[Path, ...] = (),
    expected_scan_manifest: ScanModeManifest | None = None,
    verify_live_diff_text: bool = True,
    verifier: ArtifactVerifier | None = None,
) -> dict[str, object]:
    verifier = resolve_verifier(verifier)
    # Everything below re-derives the artifact's bytes, so every rule it consults must be the one
    # the artifact's era was written under, not the one this release happens to publish with.
    with era_rules(verifier.rules):
        envelope = _validate_snapshot_envelope(payload, verifier)
        try:
            derived_snapshot_manifest = _snapshot_data_scan_manifest(envelope, verifier)
        except SecurityError as exc:
            raise _runner_security_error(exc, "snapshot scan classifier invariant failed") from exc
        if expected_scan_manifest is not None and (
            not isinstance(expected_scan_manifest, ScanModeManifest)
            or expected_scan_manifest != derived_snapshot_manifest
        ):
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED,
                "trusted snapshot scan manifest does not match artifact schema",
            )
        protected, redactions = _protect_snapshot_redactions(envelope)
        try:
            scan_manifest = _snapshot_scan_manifest(protected, verifier)
        except SecurityError as exc:
            raise _runner_security_error(
                exc, "artifact scan classifier manifest validation failed"
            ) from exc
        explicit_paths = _snapshot_sanitization_paths(extra_paths)
        try:
            normalized = sanitize_json_value(
                protected,
                scan_manifest=scan_manifest,
                repository_root=repository_root,
                explicit_paths=explicit_paths,
                verify_live_diff_text=verify_live_diff_text,
            )
        except SecurityError as exc:
            raise _runner_security_error(exc, "artifact sanitization failed closed") from exc
        normalized = _validate_snapshot_envelope(
            _restore_snapshot_redactions(normalized, redactions), verifier
        )

        invariant_input, invariant_redactions = _protect_snapshot_redactions(normalized)
        try:
            invariant_value = sanitize_json_value(
                invariant_input,
                scan_manifest=scan_manifest,
                repository_root=repository_root,
                explicit_paths=explicit_paths,
                verify_live_diff_text=verify_live_diff_text,
            )
        except SecurityError as exc:
            raise _runner_security_error(exc, "artifact invariant scan failed closed") from exc
        invariant_value = _restore_snapshot_redactions(invariant_value, invariant_redactions)
        if invariant_value != normalized:
            raise RunnerError(
                ARTIFACT_VALIDATION_FAILED, "artifact failed final secret or path invariants"
            )
    return normalized


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


def _read_private_regular(path: Path, maximum: int, description: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"unable to inspect {description}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, f"{description} must be a regular non-symlink file"
        )
    if before.st_uid != os.getuid():
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, f"{description} must be owned by the current user"
        )
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} must have mode 0600")
    if before.st_size <= 0 or before.st_size > maximum:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} violates its size bound")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"unable to safely open {description}") from exc
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} changed during safe open")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} exceeds its size bound")
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise RunnerError(ARTIFACT_PUBLISH_FAILED, f"{description} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


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


def _validate_snapshot_envelope(
    value: object, verifier: ArtifactVerifier | None = None
) -> dict[str, object]:
    verifier = resolve_verifier(verifier)
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
        or not _is_exact_version(value.get("schema_version"), verifier.schema_version)
        or not _is_exact_version(
            value.get("producer_security_epoch"), verifier.producer_security_epoch
        )
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
        value.get("trust_boundary") != verifier.trust_boundary
        or value.get("security_notice") != verifier.security_notice
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


def _load_snapshot(
    snapshot_id: str,
    target_repo: Path | None = None,
    *,
    repository_root: Path | None = None,
) -> SnapshotArtifact:
    if SNAPSHOT_ID_RE.fullmatch(snapshot_id) is None:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED,
            "snapshot id must be exactly 64 lowercase hexadecimal characters",
        )
    effective_repo = repository_root if repository_root is not None else target_repo
    if effective_repo is None:
        effective_repo = _ACTIVE_REPOSITORY_ROOT.get()
    root = snapshot_output_root(effective_repo)
    _validate_owned_private_directory(root, "snapshot store")
    directory = root / snapshot_id
    return _load_snapshot_directory(snapshot_id, directory, repository_root=effective_repo)


def _validate_snapshot_directory_location(snapshot_id: str, directory: Path) -> None:
    root = snapshot_output_root()
    _validate_owned_private_directory(root, "snapshot store")
    if (
        not directory.is_absolute()
        or directory.parent != root
        or (directory.name != snapshot_id and not directory.name.startswith(".staging-snapshot-"))
    ):
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot directory is outside the validated snapshot store"
        )


def _load_snapshot_directory(
    snapshot_id: str,
    directory: Path,
    *,
    repository_root: Path | None = None,
) -> SnapshotArtifact:
    _validate_snapshot_directory_location(snapshot_id, directory)
    _validate_owned_private_directory(directory, "snapshot directory")
    try:
        names = {entry.name for entry in directory.iterdir()}
    except OSError as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "unable to inspect snapshot directory") from exc
    if names != SNAPSHOT_FILE_NAMES:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot directory has an invalid file manifest"
        )
    meta_bytes = _read_private_regular(directory / "meta.json", MAX_META_BYTES, "snapshot meta")
    try:
        meta = json.loads(meta_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "snapshot meta is not valid UTF-8 JSON") from exc
    if not isinstance(meta, dict):
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "snapshot meta is not a JSON object")
    verifier = verifier_for(meta.get("schema_version"), meta.get("producer_security_epoch"))
    meta = _validate_snapshot_meta_schema(meta, verifier)
    if _serialize_snapshot_meta(meta) != meta_bytes:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot meta canonical artifact validation failed"
        )

    snapshot_bytes = _read_private_regular(
        directory / "snapshot.json", MAX_SNAPSHOT_BYTES, "snapshot JSON"
    )
    snapshot_hash = hashlib.sha256(snapshot_bytes).hexdigest()
    if (
        meta.get("snapshot_id") != snapshot_id
        or meta.get("snapshot_sha256") != snapshot_hash
        or snapshot_hash != snapshot_id
        or meta.get("snapshot_bytes") != len(snapshot_bytes)
    ):
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot hash, identity, or size validation failed"
        )
    try:
        envelope_value = json.loads(snapshot_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "snapshot JSON is not valid UTF-8 JSON") from exc
    active_root = repository_root if repository_root is not None else _ACTIVE_REPOSITORY_ROOT.get()
    envelope = _sanitize_validate_snapshot(
        envelope_value,
        active_root if active_root is not None else REPOSITORY_ROOT,
        extra_paths=(directory,),
        verify_live_diff_text=False,
        verifier=verifier,
    )
    if _serialize_snapshot(envelope) != snapshot_bytes:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot hash or canonical artifact validation failed"
        )
    task = envelope["task"]
    if (
        not _is_exact_version(meta.get("schema_version"), verifier.meta_schema_version)
        or not _is_exact_version(envelope.get("schema_version"), verifier.schema_version)
        or not _is_exact_version(
            meta.get("producer_security_epoch"), verifier.producer_security_epoch
        )
        or not _is_exact_version(
            envelope.get("producer_security_epoch"), verifier.producer_security_epoch
        )
        or meta.get("producer_security_epoch") != envelope.get("producer_security_epoch")
        or meta.get("task") != task
        or meta.get("repository") != envelope.get("repository")
    ):
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot task metadata does not match its envelope"
        )
    preview = _read_private_regular(
        directory / "preview.txt", MAX_PREVIEW_BYTES, "snapshot preview"
    )
    if meta.get("preview_sha256") != hashlib.sha256(preview).hexdigest() or meta.get(
        "preview_bytes"
    ) != len(preview):
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot hash, identity, or size validation failed"
        )
    return SnapshotArtifact(snapshot_id, str(task), snapshot_bytes, envelope, directory)


def _atomic_write(path: Path, content: bytes, maximum: int) -> None:
    if path.name not in SNAPSHOT_FILE_NAMES or not isinstance(content, bytes):
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, "file sink requires snapshot artifact bytes")
    if len(content) > maximum:
        raise RunnerError(
            ARTIFACT_VALIDATION_FAILED,
            f"hard output limit exceeded: {path.name}",
        )
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
