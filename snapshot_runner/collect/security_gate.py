from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from ..budget import _json_bytes, _json_text_prefix
from ..evidence import (
    _safe_relative_path,
    _snapshot_security_error,
)
from ..git import (
    IMAGE_EVIDENCE_MAX_BYTES,
)
from ..model import (
    MAX_CONTEXT_FILES,
    REDACTION_REWRITTEN_PATH_REASON,
    SNAPSHOT_CONTENT_BUDGET,
    UV_LOCK_MAX_FILE_BYTES,
)
from ..security import (
    SNAPSHOT_COLLECTION_FAILED,
    YAML_CONTENT_REFUSED,
    RunnerError,
    ScanMode,
    SecurityError,
    classify_scan_mode,
    is_extensionless_text_candidate,
    is_raster_image_evidence,
    is_relevant_text_path,
    is_yaml_content_path,
    sanitize_text,
)
from .builder import (
    SnapshotBuilder,
)
from .readers import (
    _BoundedTextEvidence,
    _file_context_limit,
    _read_extensionless_worktree,
    _read_regular_file,
    _record_extensionless_gap,
)


@dataclass(frozen=True, slots=True)
class _PreparedContext:
    path: str
    content: str
    source: str
    executable: bool


@dataclass(frozen=True, slots=True)
class _WorkspaceExtensionlessEvidence:
    fallback_paths: frozenset[str]
    staged_diff_paths: frozenset[str]
    unstaged_diff_paths: frozenset[str]
    contexts: tuple[_PreparedContext, ...]


@dataclass(frozen=True, slots=True)
class _BranchExtensionlessEvidence:
    fallback_paths: frozenset[str]
    accepted_diff_paths: frozenset[str]
    contexts: tuple[_PreparedContext, ...]


@dataclass(frozen=True, slots=True)
class _PreparedImageEvidence:
    paths: frozenset[str]
    contexts: tuple[_PreparedContext, ...]


def _uses_extensionless_fallback(relative: str) -> bool:
    path = PurePosixPath(relative)
    return (
        _safe_relative_path(relative) == relative
        and bool(path.parts)
        and "." not in path.name
        and not is_relevant_text_path(relative)
    )


def _uses_bounded_csv_diff(relative: str) -> bool:
    return (
        _safe_relative_path(relative) == relative
        and PurePosixPath(relative).suffix.lower() == ".csv"
    )


def _redaction_stable_path(builder: SnapshotBuilder, relative: str) -> bool:
    """Return whether ``relative`` survives the redactor that later re-checks it.

    ``ABSOLUTE_PATH_RE`` anchors on any ``/`` that does not follow a word character, so an
    ordinary in-repo directory ending in punctuation — ``docs/foo(bar)/baz.py``, a name ending
    in a space or ``!``, a full-width bracket — is rewritten as if it were absolute, and the
    credential rules rewrite token-shaped segments the same way. ``SnapshotBuilder.finish``
    re-sanitises every stored field and refuses the whole snapshot when any value moves, so a
    path the redactor touches must never become an identifying value.
    """
    try:
        sanitized = sanitize_text(
            relative,
            scan_mode=ScanMode.PLAIN_TEXT,
            repository_root=builder.repo_root,
        )
    except SecurityError as exc:
        raise _snapshot_security_error(
            exc, "unable to sanitize file context path; prepare refused"
        ) from exc
    return sanitized.text == relative


def _append_context(
    builder: SnapshotBuilder,
    contexts: list[dict[str, object]],
    relative: str,
    content: str,
    omitted: int,
    *,
    source: str | None = None,
    executable: bool | None = None,
) -> None:
    if source is None:
        try:
            scan_mode = classify_scan_mode(relative)
        except SecurityError as exc:
            raise _snapshot_security_error(
                exc, "unable to classify file context; prepare refused"
            ) from exc
    else:
        if executable is None or not (
            is_extensionless_text_candidate(relative)
            or is_raster_image_evidence(
                relative,
                content,
                maximum_bytes=IMAGE_EVIDENCE_MAX_BYTES,
            )
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "versioned file context metadata is invalid",
            )
        scan_mode = ScanMode.PLAIN_TEXT
    if not _redaction_stable_path(builder, relative):
        builder.gap("file_refused", relative, REDACTION_REWRITTEN_PATH_REASON)
        return
    try:
        sanitized = sanitize_text(
            content,
            scan_mode=scan_mode,
            repository_root=builder.repo_root,
        )
    except SecurityError as exc:
        raise _snapshot_security_error(
            exc, "unable to sanitize file context; prepare refused"
        ) from exc
    for category, count in sanitized.redactions.items():
        builder.redactions[category] = builder.redactions.get(category, 0) + count
    path_overhead = len(_json_bytes(relative)) + 32
    if source is not None:
        path_overhead += len(_json_bytes(source)) + 24
    available = max(0, SNAPSHOT_CONTENT_BUDGET - builder.content_bytes - path_overhead)
    accepted, budget_omitted, encoded_length = _json_text_prefix(sanitized.text, available)
    if not accepted and sanitized.text:
        builder.gap("snapshot_limit", relative, "file context omitted at total limit")
        return
    context_index = len(contexts)
    context: dict[str, object] = {"path": relative, "content": accepted}
    if source is not None:
        context["source"] = source
        context["executable"] = executable
    contexts.append(context)
    builder._bind_mode(("file_context", context_index, "path"), ScanMode.PLAIN_TEXT)
    builder._bind_mode(("file_context", context_index, "content"), scan_mode)
    if source is not None:
        builder._bind_mode(("file_context", context_index, "source"), ScanMode.PLAIN_TEXT)
    builder.content_bytes += encoded_length + path_overhead
    if omitted:
        reason = (
            "file context truncated at 4 MiB"
            if _file_context_limit(relative) == UV_LOCK_MAX_FILE_BYTES
            else "file context truncated at 256 KiB"
        )
        builder.gap("file_limit", relative, reason, omitted)
    if budget_omitted:
        builder.gap(
            "snapshot_limit",
            relative,
            "file context truncated at total snapshot limit",
            budget_omitted,
        )


def _add_context(
    builder: SnapshotBuilder,
    paths: list[str],
    *,
    max_context_files: int = MAX_CONTEXT_FILES,
    prepared_extensionless: tuple[_PreparedContext, ...] = (),
    handled_extensionless: frozenset[str] = frozenset(),
    prepared_images: tuple[_PreparedContext, ...] = (),
    handled_images: frozenset[str] = frozenset(),
) -> None:
    contexts: list[dict[str, object]] = []
    unique_paths = list(dict.fromkeys(paths))
    prepared_by_path: dict[str, list[_PreparedContext]] = {}
    for prepared in (*prepared_extensionless, *prepared_images):
        prepared_by_path.setdefault(prepared.path, []).append(prepared)
    local_cache: dict[tuple[str, str], _BoundedTextEvidence] = {}
    if len(unique_paths) > max_context_files:
        builder.gap(
            "file_count_limit",
            "changed-file-context",
            f"context limited to {max_context_files} files",
            len(unique_paths) - max_context_files,
        )
    for relative in unique_paths[:max_context_files]:
        if is_yaml_content_path(relative):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, YAML_CONTENT_REFUSED)
        if relative in handled_images:
            for prepared in prepared_by_path.get(relative, []):
                _append_context(
                    builder,
                    contexts,
                    prepared.path,
                    prepared.content,
                    0,
                    source=prepared.source,
                    executable=prepared.executable,
                )
            continue
        if _uses_extensionless_fallback(relative):
            if relative in handled_extensionless:
                for prepared in prepared_by_path.get(relative, []):
                    _append_context(
                        builder,
                        contexts,
                        prepared.path,
                        prepared.content,
                        0,
                        source=prepared.source,
                        executable=prepared.executable,
                    )
                continue
            if not is_extensionless_text_candidate(relative):
                builder.gap(
                    "file_refused",
                    relative,
                    "sensitive or unsupported file type refused",
                )
                continue
            cache_key = ("worktree", relative)
            evidence = local_cache.get(cache_key)
            executable: bool | None = None
            if evidence is None:
                evidence, executable = _read_extensionless_worktree(builder.repo_root, relative)
                local_cache[cache_key] = evidence
            if evidence.gap_kind is not None:
                _record_extensionless_gap(builder, relative, "worktree", evidence)
                continue
            assert evidence.content is not None
            assert executable is not None
            _append_context(
                builder,
                contexts,
                relative,
                evidence.content,
                0,
                source="worktree",
                executable=executable,
            )
            continue
        if not is_relevant_text_path(relative):
            builder.gap("file_refused", relative, "sensitive or unsupported file type refused")
            continue
        content, omitted, reason = _read_regular_file(
            builder.repo_root,
            relative,
            _file_context_limit(relative),
        )
        if reason is not None:
            builder.gap("file_refused", relative, reason, omitted or None)
            continue
        assert content is not None
        _append_context(builder, contexts, relative, content, omitted)
    builder.data["file_context"] = contexts
