from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from ..evidence import (
    _bounded_path_batches,
    _BranchPathChange,
    _decode_branch_path,
    _safe_relative_path,
)
from ..git import (
    GIT_OID_RE,
    GitConversionPolicy,
    GitResult,
    GitRunner,
)
from ..model import (
    MAX_CONTEXT_FILES,
    MAX_CONVERSION_RECORDS,
    SNAPSHOT_CONTENT_BUDGET,
)
from ..security import (
    GIT_COMMAND_FAILED,
    SNAPSHOT_COLLECTION_FAILED,
    YAML_CONTENT_REFUSED,
    RunnerError,
    ScanMode,
    has_supported_raster_image_suffix,
    is_extensionless_text_candidate,
    is_relevant_text_path,
    is_yaml_content_path,
)
from .builder import (
    SnapshotBuilder,
)
from .readers import (
    _BoundedTextEvidence,
    _file_context_limit,
    _open_repo_regular,
    _read_extensionless_git_entry,
    _read_extensionless_worktree,
    _read_image_blob,
    _read_image_worktree,
    _record_extensionless_gap,
    _record_image_gap,
    _text_refusal,
)
from .security_gate import (
    _append_context,
    _BranchExtensionlessEvidence,
    _PreparedContext,
    _PreparedImageEvidence,
    _uses_extensionless_fallback,
    _WorkspaceExtensionlessEvidence,
)


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    mode: str
    object_type: str
    object_id: str
    size: int | None
    path: str


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    mode: str
    object_id: str
    stage: int


@dataclass(frozen=True, slots=True)
class _PathConversionAttributes:
    filter_driver: str | None = None
    diff_driver: str | None = None


def _decode_git(result: GitResult, subject: str, builder: SnapshotBuilder) -> str:
    if result.returncode != 0 and not result.truncated:
        operation = (
            result.operation
            if re.fullmatch(r"[a-z][a-z-]*", result.operation) is not None
            else "command"
        )
        raise RunnerError(
            GIT_COMMAND_FAILED,
            f"git {operation} collection failed (exit={result.returncode})",
        )
    if result.truncated:
        builder.gap(
            "git_output_limit",
            subject,
            "Git output truncated at the 2 MiB per-command hard limit",
        )
    try:
        return result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        builder.gap("binary_or_encoding", subject, "Git output was not valid UTF-8")
        return result.stdout.decode("utf-8", errors="replace")


def _decode_unified_diff(result: GitResult, subject: str, builder: SnapshotBuilder) -> str:
    decoded = _decode_git(result, subject, builder)
    if result.truncated:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "truncated unified diff evidence was refused")
    return decoded


def _paths_from_nul(raw: bytes, subject: str, builder: SnapshotBuilder) -> list[str]:
    del subject, builder
    paths: list[str] = []
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            decoded = entry.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "repository path evidence is not valid UTF-8"
            ) from exc
        relative = _safe_relative_path(decoded)
        if relative is None:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "repository path evidence is not a safe relative path"
            )
        paths.append(relative)
    return paths


def _tree_entry(git: GitRunner, commit: str, relative: str) -> _TreeEntry | None:
    result = git.run(
        (
            "ls-tree",
            "-z",
            "--long",
            commit,
            "--",
            f":(top,literal){relative}",
        ),
        maximum=16 * 1024,
    )
    if result.returncode != 0 or result.truncated:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "sealed Git tree metadata lookup failed")
    if not result.stdout:
        return None
    records = [record for record in result.stdout.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "sealed Git tree metadata is ambiguous")
    header, raw_path = records[0].split(b"\t", 1)
    fields = header.split()
    if len(fields) != 4:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "sealed Git tree metadata schema is invalid")
    try:
        mode = fields[0].decode("ascii", errors="strict")
        object_type = fields[1].decode("ascii", errors="strict")
        object_id = fields[2].decode("ascii", errors="strict")
        size_field = fields[3].decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "sealed Git tree metadata encoding is invalid"
        ) from exc
    path = _decode_branch_path(raw_path)
    size = None if size_field == "-" else int(size_field) if size_field.isdigit() else None
    if path != relative or GIT_OID_RE.fullmatch(object_id) is None:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "sealed Git tree metadata does not match the requested path"
        )
    return _TreeEntry(mode, object_type, object_id, size, path)


def _read_blob_prefix(
    git: GitRunner,
    entry: _TreeEntry,
    maximum: int,
) -> tuple[str | None, int, str | None]:
    if entry.object_type != "blob" or entry.size is None:
        return None, 0, "non-blob Git object refused"
    result = git.run(("cat-file", "blob", entry.object_id), maximum=maximum)
    if entry.size <= maximum:
        if result.returncode != 0 or result.truncated or len(result.stdout) != entry.size:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "sealed target blob read failed")
        omitted = 0
    else:
        if not result.truncated or len(result.stdout) != maximum:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "sealed target blob bounded read failed")
        omitted = entry.size - maximum
    if b"\0" in result.stdout:
        return None, entry.size, "binary Git blob refused"
    try:
        return result.stdout.decode("utf-8", errors="strict"), omitted, None
    except UnicodeDecodeError:
        return None, entry.size, "non-UTF-8 Git blob refused"


def _add_branch_blob_context(
    builder: SnapshotBuilder,
    git: GitRunner,
    target_head: str,
    changes: list[_BranchPathChange],
    extensionless: _BranchExtensionlessEvidence,
    images: _PreparedImageEvidence,
) -> None:
    target_paths = list(dict.fromkeys(change.path for change in changes if change.status != "D"))
    contexts: list[dict[str, object]] = []
    prepared_by_path = {prepared.path: prepared for prepared in extensionless.contexts}
    prepared_by_path.update({prepared.path: prepared for prepared in images.contexts})
    if len(target_paths) > MAX_CONTEXT_FILES:
        builder.gap(
            "file_count_limit",
            "changed-file-context",
            f"context limited to {MAX_CONTEXT_FILES} files",
            len(target_paths) - MAX_CONTEXT_FILES,
        )
    for relative in target_paths[:MAX_CONTEXT_FILES]:
        if is_yaml_content_path(relative):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, YAML_CONTENT_REFUSED)
        if relative in images.paths:
            prepared = prepared_by_path.get(relative)
            if prepared is not None:
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
        if relative in extensionless.fallback_paths:
            prepared = prepared_by_path.get(relative)
            if prepared is not None:
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
        if not is_relevant_text_path(relative):
            builder.gap("file_refused", relative, "sensitive or unsupported file type refused")
            continue
        entry = _tree_entry(git, target_head, relative)
        if entry is None:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "changed target path is absent from sealed target HEAD"
            )
        if entry.mode not in {"100644", "100755"}:
            builder.gap("file_refused", relative, "unsupported Git tree mode refused")
            continue
        content, omitted, reason = _read_blob_prefix(
            git,
            entry,
            _file_context_limit(relative),
        )
        if reason is not None:
            builder.gap("file_refused", relative, reason, omitted or None)
            continue
        assert content is not None
        _append_context(builder, contexts, relative, content, omitted)
    builder.data["file_context"] = contexts


def _deleted_file_metadata(
    builder: SnapshotBuilder,
    git: GitRunner,
    merge_base_commit: str,
    changes: list[_BranchPathChange],
) -> None:
    deleted_paths = list(dict.fromkeys(change.path for change in changes if change.status == "D"))
    if len(deleted_paths) > MAX_CONTEXT_FILES:
        builder.gap(
            "file_count_limit",
            "deleted-file-metadata",
            f"deletion metadata limited to {MAX_CONTEXT_FILES} files",
            len(deleted_paths) - MAX_CONTEXT_FILES,
        )
    deleted_files: list[dict[str, object]] = []
    for relative in deleted_paths[:MAX_CONTEXT_FILES]:
        if is_yaml_content_path(relative):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, YAML_CONTENT_REFUSED)
        entry = _tree_entry(git, merge_base_commit, relative)
        if entry is None or entry.object_type != "blob" or entry.size is None:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "deleted path is not a sealed merge-base blob"
            )
        deleted_files.append(
            {
                "path": relative,
                "status": "deleted",
                "blob_oid": entry.object_id,
                "blob_size": entry.size,
                "blob_commit": merge_base_commit,
            }
        )
    builder.add_value("deleted_files", deleted_files, scan_mode=ScanMode.PLAIN_TEXT)


def _changed_paths(
    git: GitRunner, builder: SnapshotBuilder, arguments: tuple[str, ...]
) -> list[str]:
    result = git.run(arguments)
    if result.returncode != 0:
        _decode_git(result, "changed-paths", builder)
    if result.truncated:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "changed path evidence exceeded its hard limit"
        )
    return _paths_from_nul(result.stdout, "changed-paths", builder)


def _refuse_yaml_paths(paths: list[str]) -> None:
    if any(is_yaml_content_path(path) for path in paths):
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, YAML_CONTENT_REFUSED)


def _conversion_attributes(
    git: GitRunner,
    paths: list[str],
    *,
    attribute_source: str | None = None,
) -> dict[str, _PathConversionAttributes]:
    if attribute_source is not None and GIT_OID_RE.fullmatch(attribute_source) is None:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "conversion attribute source is not a canonical object id"
        )
    values_by_path: dict[str, dict[str, str]] = {path: {} for path in dict.fromkeys(paths)}
    global_arguments = (f"--attr-source={attribute_source}",) if attribute_source else ()
    for batch in _bounded_path_batches(paths):
        result = git.run(
            (
                *global_arguments,
                "check-attr",
                "-z",
                "filter",
                "diff",
                "--",
                *batch,
            )
        )
        if result.returncode != 0 or result.truncated or result.stderr:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "Git conversion attribute inspection failed closed"
            )
        fields = result.stdout.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        if len(fields) != len(batch) * 6:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "Git conversion attribute evidence is incomplete"
            )
        for offset in range(0, len(fields), 3):
            try:
                raw_path = fields[offset].decode("utf-8", errors="strict")
                attribute = fields[offset + 1].decode("ascii", errors="strict")
                value = fields[offset + 2].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED,
                    "Git conversion attribute evidence is not valid UTF-8",
                ) from exc
            relative = _safe_relative_path(raw_path)
            if relative not in values_by_path or attribute not in {"filter", "diff"}:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "Git conversion attribute evidence is out of scope"
                )
            path_values = values_by_path[relative]
            if attribute in path_values:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "Git conversion attribute evidence is ambiguous"
                )
            path_values[attribute] = value

    def driver_value(value: str | None) -> str | None:
        if value is None or value in {"set", "unset", "unspecified"}:
            return None
        if len(value.encode("utf-8")) > 255 or any(
            character in value for character in ("\x00", "\r", "\n")
        ):
            return "unsupported-attribute-value"
        return value

    return {
        path: _PathConversionAttributes(
            driver_value(attributes.get("filter")),
            driver_value(attributes.get("diff")),
        )
        for path, attributes in values_by_path.items()
    }


def _index_entries(
    git: GitRunner,
    paths: list[str],
) -> dict[str, list[_IndexEntry]]:
    entries: dict[str, list[_IndexEntry]] = {path: [] for path in dict.fromkeys(paths)}
    for batch in _bounded_path_batches(paths):
        result = git.run(
            (
                "ls-files",
                "--stage",
                "-z",
                "--",
                *(f":(top,literal){path}" for path in batch),
            )
        )
        if result.returncode != 0 or result.truncated or result.stderr:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "Git index conversion metadata lookup failed"
            )
        for record in (item for item in result.stdout.split(b"\0") if item):
            if b"\t" not in record:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "Git index conversion metadata schema is invalid"
                )
            header, raw_path = record.split(b"\t", 1)
            fields = header.split()
            if len(fields) != 3:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "Git index conversion metadata schema is invalid"
                )
            try:
                mode = fields[0].decode("ascii", errors="strict")
                object_id = fields[1].decode("ascii", errors="strict")
                stage_text = fields[2].decode("ascii", errors="strict")
                decoded_path = raw_path.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "Git index conversion metadata encoding is invalid"
                ) from exc
            relative = _safe_relative_path(decoded_path)
            if (
                relative not in entries
                or GIT_OID_RE.fullmatch(object_id) is None
                or not stage_text.isdigit()
                or int(stage_text) not in {0, 1, 2, 3}
            ):
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "Git index conversion metadata is out of scope"
                )
            entries[relative].append(_IndexEntry(mode, object_id, int(stage_text)))
    return entries


def _prepare_workspace_images(
    builder: SnapshotBuilder,
    git: GitRunner,
    staged_paths: list[str],
    unstaged_paths: list[str],
    untracked_paths: list[str],
) -> _PreparedImageEvidence:
    all_paths = list(dict.fromkeys([*staged_paths, *unstaged_paths, *untracked_paths]))
    image_paths = [path for path in all_paths if has_supported_raster_image_suffix(path)]
    selected_paths = image_paths[:MAX_CONTEXT_FILES]
    if len(image_paths) > MAX_CONTEXT_FILES:
        builder.gap(
            "file_count_limit",
            "raster-image-evidence",
            f"raster image evidence limited to {MAX_CONTEXT_FILES} files",
            len(image_paths) - MAX_CONTEXT_FILES,
        )
    index_paths = [
        path for path in selected_paths if path in staged_paths or path in unstaged_paths
    ]
    index_entries = _index_entries(git, index_paths)
    blob_cache: dict[tuple[str, str], _BoundedTextEvidence] = {}
    worktree_cache: dict[str, tuple[_BoundedTextEvidence, bool | None]] = {}
    contexts: list[_PreparedContext] = []

    def stage_zero(relative: str) -> _IndexEntry | None:
        entries = index_entries.get(relative, [])
        candidates = [entry for entry in entries if entry.stage == 0]
        if len(candidates) > 1:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "Git index has duplicate stage-zero image entries",
            )
        return candidates[0] if candidates else None

    def read_worktree(relative: str) -> tuple[_BoundedTextEvidence, bool | None]:
        if relative not in worktree_cache:
            worktree_cache[relative] = _read_image_worktree(builder.repo_root, relative)
        return worktree_cache[relative]

    for relative in selected_paths:
        index_entry = stage_zero(relative)
        if relative in staged_paths:
            if index_entry is not None:
                evidence, executable = _read_image_blob(
                    git,
                    relative,
                    index_entry.mode,
                    index_entry.object_id,
                    None,
                    blob_cache,
                )
                if evidence.gap_kind is None:
                    assert evidence.content is not None
                    assert executable is not None
                    contexts.append(
                        _PreparedContext(relative, evidence.content, "index", executable)
                    )
                else:
                    _record_image_gap(builder, relative, "index", evidence)
            elif index_entries.get(relative):
                _record_image_gap(
                    builder,
                    relative,
                    "index",
                    _text_refusal("unmerged index version refused"),
                )
        if relative in unstaged_paths:
            evidence, executable = read_worktree(relative)
            if evidence.reason == "file missing" and index_entry is not None:
                continue
            if evidence.gap_kind is None:
                assert evidence.content is not None
                assert executable is not None
                contexts.append(
                    _PreparedContext(relative, evidence.content, "worktree", executable)
                )
            else:
                _record_image_gap(builder, relative, "worktree", evidence)
        if relative in untracked_paths:
            evidence, executable = read_worktree(relative)
            if evidence.gap_kind is None:
                assert evidence.content is not None
                assert executable is not None
                contexts.append(
                    _PreparedContext(relative, evidence.content, "untracked", executable)
                )
            else:
                _record_image_gap(builder, relative, "untracked", evidence)
    return _PreparedImageEvidence(frozenset(image_paths), tuple(contexts))


def _prepare_branch_images(
    builder: SnapshotBuilder,
    git: GitRunner,
    target_head: str,
    changes: list[_BranchPathChange],
) -> _PreparedImageEvidence:
    target_paths = list(
        dict.fromkeys(
            change.path
            for change in changes
            if change.status != "D" and has_supported_raster_image_suffix(change.path)
        )
    )
    selected_paths = target_paths[:MAX_CONTEXT_FILES]
    if len(target_paths) > MAX_CONTEXT_FILES:
        builder.gap(
            "file_count_limit",
            "raster-image-evidence",
            f"raster image evidence limited to {MAX_CONTEXT_FILES} files",
            len(target_paths) - MAX_CONTEXT_FILES,
        )
    blob_cache: dict[tuple[str, str], _BoundedTextEvidence] = {}
    contexts: list[_PreparedContext] = []
    for relative in selected_paths:
        entry = _tree_entry(git, target_head, relative)
        if entry is None:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "changed image path is absent from sealed target HEAD",
            )
        evidence, executable = _read_image_blob(
            git,
            relative,
            entry.mode,
            entry.object_id,
            entry.size,
            blob_cache,
        )
        if evidence.gap_kind is None:
            assert evidence.content is not None
            assert executable is not None
            contexts.append(_PreparedContext(relative, evidence.content, "target", executable))
        else:
            _record_image_gap(builder, relative, "target", evidence)
    return _PreparedImageEvidence(frozenset(target_paths), tuple(contexts))


def _prepare_workspace_extensionless(
    builder: SnapshotBuilder,
    git: GitRunner,
    head: str | None,
    staged_paths: list[str],
    unstaged_paths: list[str],
    untracked_paths: list[str],
) -> _WorkspaceExtensionlessEvidence:
    all_paths = list(dict.fromkeys([*staged_paths, *unstaged_paths, *untracked_paths]))
    fallback_paths = [path for path in all_paths if _uses_extensionless_fallback(path)]
    selected_paths = fallback_paths[:MAX_CONTEXT_FILES]
    if len(fallback_paths) > MAX_CONTEXT_FILES:
        builder.gap(
            "file_count_limit",
            "extensionless-file-evidence",
            f"extensionless evidence limited to {MAX_CONTEXT_FILES} files",
            len(fallback_paths) - MAX_CONTEXT_FILES,
        )
    index_paths = [
        path for path in selected_paths if path in staged_paths or path in unstaged_paths
    ]
    index_entries = _index_entries(git, index_paths)
    blob_cache: dict[tuple[str, str], _BoundedTextEvidence] = {}
    worktree_cache: dict[tuple[str, str], tuple[_BoundedTextEvidence, bool | None]] = {}
    accepted_staged: set[str] = set()
    accepted_unstaged: set[str] = set()
    contexts: list[_PreparedContext] = []

    def stage_zero(relative: str) -> _IndexEntry | None:
        entries = index_entries.get(relative, [])
        candidates = [entry for entry in entries if entry.stage == 0]
        if len(candidates) > 1:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "Git index has duplicate stage-zero extensionless entries",
            )
        return candidates[0] if candidates else None

    def read_worktree(relative: str) -> tuple[_BoundedTextEvidence, bool | None]:
        key = ("worktree", relative)
        if key not in worktree_cache:
            worktree_cache[key] = _read_extensionless_worktree(builder.repo_root, relative)
        return worktree_cache[key]

    def read_index(relative: str) -> tuple[_BoundedTextEvidence, bool | None]:
        entry = stage_zero(relative)
        if entry is None:
            return (
                _text_refusal("index stage-zero version unavailable"),
                None,
            )
        return _read_extensionless_git_entry(
            git,
            entry.mode,
            entry.object_id,
            None,
            blob_cache,
        )

    def read_head(relative: str) -> tuple[_BoundedTextEvidence, bool | None]:
        if head is None:
            return (
                _text_refusal("historical version unavailable"),
                None,
            )
        entry = _tree_entry(git, head, relative)
        if entry is None:
            return (
                _text_refusal("historical version unavailable"),
                None,
            )
        return _read_extensionless_git_entry(
            git,
            entry.mode,
            entry.object_id,
            entry.size,
            blob_cache,
        )

    for relative in selected_paths:
        if not is_extensionless_text_candidate(relative):
            builder.gap(
                "file_refused",
                relative,
                "sensitive or unsupported extensionless file refused",
            )
            continue
        if relative in staged_paths:
            index_entry = stage_zero(relative)
            if index_entry is not None:
                evidence, executable = read_index(relative)
                staged_complete = evidence.gap_kind is None
                if staged_complete:
                    assert evidence.content is not None
                    assert executable is not None
                    contexts.append(
                        _PreparedContext(relative, evidence.content, "index", executable)
                    )
                    if head is not None:
                        head_entry = _tree_entry(git, head, relative)
                        if head_entry is not None:
                            old_evidence, _old_executable = _read_extensionless_git_entry(
                                git,
                                head_entry.mode,
                                head_entry.object_id,
                                head_entry.size,
                                blob_cache,
                            )
                            if old_evidence.gap_kind is not None:
                                _record_extensionless_gap(
                                    builder,
                                    relative,
                                    "historical",
                                    old_evidence,
                                )
                                staged_complete = False
                else:
                    _record_extensionless_gap(builder, relative, "index", evidence)
            elif index_entries.get(relative):
                evidence = _text_refusal("unmerged index version refused")
                staged_complete = False
                _record_extensionless_gap(builder, relative, "index", evidence)
            else:
                evidence, _executable = read_head(relative)
                staged_complete = evidence.gap_kind is None
                if not staged_complete:
                    _record_extensionless_gap(builder, relative, "historical", evidence)
            if staged_complete:
                accepted_staged.add(relative)
        if relative in unstaged_paths:
            evidence, executable = read_worktree(relative)
            include_context = True
            source = "worktree"
            if evidence.reason == "file missing" and stage_zero(relative) is not None:
                evidence, executable = read_index(relative)
                include_context = False
                source = "index"
            if evidence.gap_kind is None:
                if include_context:
                    assert evidence.content is not None
                    assert executable is not None
                    contexts.append(
                        _PreparedContext(relative, evidence.content, "worktree", executable)
                    )
                unstaged_complete = True
                index_entry = stage_zero(relative)
                if include_context and index_entry is not None:
                    old_evidence, _old_executable = read_index(relative)
                    if old_evidence.gap_kind is not None:
                        _record_extensionless_gap(
                            builder,
                            relative,
                            "index",
                            old_evidence,
                        )
                        unstaged_complete = False
                if unstaged_complete:
                    accepted_unstaged.add(relative)
            else:
                _record_extensionless_gap(builder, relative, source, evidence)
        if relative in untracked_paths:
            evidence, executable = read_worktree(relative)
            if evidence.gap_kind is None:
                assert evidence.content is not None
                assert executable is not None
                contexts.append(
                    _PreparedContext(relative, evidence.content, "untracked", executable)
                )
            else:
                _record_extensionless_gap(builder, relative, "untracked", evidence)

    return _WorkspaceExtensionlessEvidence(
        frozenset(fallback_paths),
        frozenset(accepted_staged),
        frozenset(accepted_unstaged),
        tuple(contexts),
    )


def _prepare_branch_extensionless(
    builder: SnapshotBuilder,
    git: GitRunner,
    merge_base_commit: str,
    target_head: str,
    changes: list[_BranchPathChange],
) -> _BranchExtensionlessEvidence:
    requests: dict[str, list[tuple[str, str]]] = {}
    target_context_paths: set[str] = set()
    for change in changes:
        if change.status == "D":
            continue
        requests.setdefault(change.path, []).append(("target", target_head))
        target_context_paths.add(change.path)
        if change.old_path is not None:
            requests.setdefault(change.old_path, []).append(("historical", merge_base_commit))
        elif change.status in {"M", "T"}:
            requests.setdefault(change.path, []).append(("historical", merge_base_commit))
    fallback_paths = [path for path in requests if _uses_extensionless_fallback(path)]
    selected_paths = fallback_paths[:MAX_CONTEXT_FILES]
    if len(fallback_paths) > MAX_CONTEXT_FILES:
        builder.gap(
            "file_count_limit",
            "extensionless-file-evidence",
            f"extensionless evidence limited to {MAX_CONTEXT_FILES} files",
            len(fallback_paths) - MAX_CONTEXT_FILES,
        )
    blob_cache: dict[tuple[str, str], _BoundedTextEvidence] = {}
    accepted_diff_paths: set[str] = set()
    contexts: list[_PreparedContext] = []
    for relative in selected_paths:
        if not is_extensionless_text_candidate(relative):
            builder.gap(
                "file_refused",
                relative,
                "sensitive or unsupported extensionless file refused",
            )
            continue
        path_complete = True
        target_context: _PreparedContext | None = None
        for source, commit in dict.fromkeys(requests[relative]):
            entry = _tree_entry(git, commit, relative)
            if entry is None:
                evidence = _text_refusal("sealed Git version unavailable")
                executable = None
            else:
                evidence, executable = _read_extensionless_git_entry(
                    git,
                    entry.mode,
                    entry.object_id,
                    entry.size,
                    blob_cache,
                )
            if evidence.gap_kind is not None:
                _record_extensionless_gap(builder, relative, source, evidence)
                path_complete = False
                continue
            if source == "target" and relative in target_context_paths:
                assert evidence.content is not None
                assert executable is not None
                target_context = _PreparedContext(
                    relative,
                    evidence.content,
                    "target",
                    executable,
                )
        if path_complete:
            accepted_diff_paths.add(relative)
        if target_context is not None:
            contexts.append(target_context)
    return _BranchExtensionlessEvidence(
        frozenset(fallback_paths),
        frozenset(accepted_diff_paths),
        tuple(contexts),
    )


def _worktree_conversion_metadata(repo_root: Path, relative: str) -> dict[str, object]:
    descriptor, opened, reason = _open_repo_regular(repo_root, relative)
    if descriptor is not None:
        os.close(descriptor)
    if opened is None:
        return {"worktree_state": "missing_or_unavailable", "worktree_size": None}
    if descriptor is not None:
        state = "regular"
    elif stat.S_ISLNK(opened.st_mode):
        state = "symlink"
    elif stat.S_ISDIR(opened.st_mode):
        state = "directory"
    else:
        state = reason or "non_regular"
    return {"worktree_state": state, "worktree_size": opened.st_size}


def _workspace_conversion_paths(
    git: GitRunner,
    policy: GitConversionPolicy,
    tracked_paths: list[str],
    staged_paths: list[str],
    unstaged_paths: list[str],
    untracked_paths: list[str],
) -> list[tuple[str, tuple[str, ...], bool]]:
    all_paths = list(dict.fromkeys([*tracked_paths, *untracked_paths]))
    attributes = _conversion_attributes(git, all_paths)
    filter_drivers = {driver.name: driver.disabled_types for driver in policy.filter_drivers}
    diff_drivers = {driver.name: driver.disabled_types for driver in policy.diff_drivers}
    changed_paths = set((*staged_paths, *unstaged_paths))
    conversion_paths: list[tuple[str, tuple[str, ...], bool]] = []
    for path in all_paths:
        path_attributes = attributes[path]
        disabled_types: set[str] = set()
        content_filter = path_attributes.filter_driver is not None
        if path_attributes.filter_driver is not None:
            disabled_types.add("content_filter_attribute")
            disabled_types.update(filter_drivers.get(path_attributes.filter_driver, ()))
        if path in changed_paths and path_attributes.diff_driver in diff_drivers:
            disabled_types.update(diff_drivers[path_attributes.diff_driver])
        if path in changed_paths and policy.external_diff:
            disabled_types.add("external_diff")
        if disabled_types:
            conversion_paths.append((path, tuple(sorted(disabled_types)), content_filter))
    return conversion_paths


def _store_conversion_safety(
    builder: SnapshotBuilder,
    observed_types: set[str],
    files: list[dict[str, object]],
    *,
    incomplete: bool,
) -> None:
    builder.add_value(
        "conversion_safety",
        {
            "external_commands_executed": False,
            "content_diff_complete": not incomplete,
            "disabled_config_types": sorted(observed_types),
            "files": files,
        },
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    if builder.data.get("conversion_safety") == {}:
        del builder.data["conversion_safety"]


def _add_workspace_conversion_safety(
    builder: SnapshotBuilder,
    git: GitRunner,
    policy: GitConversionPolicy,
    head: str | None,
    tracked_paths: list[str],
    staged_paths: list[str],
    unstaged_paths: list[str],
    untracked_paths: list[str],
    conversion_paths: list[tuple[str, tuple[str, ...], bool]],
) -> None:
    if not conversion_paths and not policy.disabled_config_types:
        return
    selected = conversion_paths[:MAX_CONVERSION_RECORDS]
    selected_paths = [path for path, _types, _filter in selected]
    index_entries = _index_entries(git, selected_paths)
    tracked = set(tracked_paths)
    staged = set(staged_paths)
    unstaged = set(unstaged_paths)
    untracked = set(untracked_paths)
    files: list[dict[str, object]] = []
    observed_types = set(policy.disabled_config_types)
    for path, disabled_types, content_filter in selected:
        observed_types.update(disabled_types)
        head_entry = _tree_entry(git, head, path) if head is not None else None
        path_index_entries = index_entries[path]
        stage_zero = [entry for entry in path_index_entries if entry.stage == 0]
        if len(stage_zero) > 1:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "Git index conversion metadata has duplicate stage-zero entries",
            )
        index_entry = stage_zero[0] if stage_zero else None
        if content_filter:
            unstaged_status = "raw_changed" if path in unstaged else "unknown_conversion_required"
            context_reason = "content filter disabled; worktree comparison is raw and converted context is unavailable"
        else:
            unstaged_status = "raw_changed" if path in unstaged else "raw_unchanged"
            context_reason = "external diff or textconv disabled; converted display is unavailable"
        record: dict[str, object] = {
            "path": path,
            "tracked": path in tracked,
            "untracked": path in untracked,
            "staged_status": "changed" if path in staged else "unchanged",
            "unstaged_status": unstaged_status,
            "old_blob_oid": (
                head_entry.object_id
                if head_entry is not None and head_entry.object_type == "blob"
                else None
            ),
            "old_blob_size": (
                head_entry.size
                if head_entry is not None and head_entry.object_type == "blob"
                else None
            ),
            "new_blob_oid": index_entry.object_id if index_entry is not None else None,
            "new_blob_size": None,
            "index_stages": [
                {"stage": entry.stage, "object_id": entry.object_id, "mode": entry.mode}
                for entry in path_index_entries
            ],
            "conversion_required": True,
            "disabled_types": list(disabled_types),
            "raw_content_captured": (path in staged or path in unstaged or path in untracked)
            and is_relevant_text_path(path),
            "converted_content_unavailable_reason": context_reason,
            **_worktree_conversion_metadata(builder.repo_root, path),
        }
        files.append(record)
        builder.gap("external_conversion_disabled", path, context_reason)
    if len(conversion_paths) > MAX_CONVERSION_RECORDS:
        builder.gap(
            "conversion_record_limit",
            "conversion-required-files",
            f"conversion metadata limited to {MAX_CONVERSION_RECORDS} files",
            len(conversion_paths) - MAX_CONVERSION_RECORDS,
        )
    _store_conversion_safety(
        builder,
        observed_types,
        files,
        incomplete=bool(conversion_paths),
    )


def _add_branch_conversion_safety(
    builder: SnapshotBuilder,
    git: GitRunner,
    policy: GitConversionPolicy,
    merge_base_commit: str,
    target_head: str,
    changed_paths: list[str],
    raw_diff_paths: list[str],
) -> None:
    if not policy.external_diff and not policy.diff_drivers:
        if policy.disabled_config_types:
            _store_conversion_safety(
                builder,
                set(policy.disabled_config_types),
                [],
                incomplete=False,
            )
        return
    unique_paths = list(dict.fromkeys(changed_paths))
    attributes_by_source = (
        _conversion_attributes(git, unique_paths, attribute_source=merge_base_commit),
        _conversion_attributes(git, unique_paths, attribute_source=target_head),
    )
    diff_drivers = {driver.name: driver.disabled_types for driver in policy.diff_drivers}
    conversion_paths: list[tuple[str, tuple[str, ...]]] = []
    for path in unique_paths:
        disabled_types: set[str] = set()
        for attributes in attributes_by_source:
            driver = attributes[path].diff_driver
            if driver in diff_drivers:
                disabled_types.update(diff_drivers[driver])
        if policy.external_diff:
            disabled_types.add("external_diff")
        if disabled_types:
            conversion_paths.append((path, tuple(sorted(disabled_types))))
    if not conversion_paths and not policy.disabled_config_types:
        return

    files: list[dict[str, object]] = []
    observed_types = set(policy.disabled_config_types)
    raw_paths = set(raw_diff_paths)
    for path, disabled_types in conversion_paths[:MAX_CONVERSION_RECORDS]:
        observed_types.update(disabled_types)
        old_entry = _tree_entry(git, merge_base_commit, path)
        new_entry = _tree_entry(git, target_head, path)
        reason = "external diff or textconv disabled; converted branch display is unavailable"
        files.append(
            {
                "path": path,
                "tracked": True,
                "untracked": False,
                "staged_status": "not_applicable",
                "unstaged_status": "not_applicable",
                "old_blob_oid": (
                    old_entry.object_id
                    if old_entry is not None and old_entry.object_type == "blob"
                    else None
                ),
                "old_blob_size": (
                    old_entry.size
                    if old_entry is not None and old_entry.object_type == "blob"
                    else None
                ),
                "new_blob_oid": (
                    new_entry.object_id
                    if new_entry is not None and new_entry.object_type == "blob"
                    else None
                ),
                "new_blob_size": (
                    new_entry.size
                    if new_entry is not None and new_entry.object_type == "blob"
                    else None
                ),
                "index_stages": [],
                "conversion_required": True,
                "disabled_types": list(disabled_types),
                "raw_content_captured": path in raw_paths,
                "converted_content_unavailable_reason": reason,
                "worktree_state": "not_applicable",
                "worktree_size": None,
            }
        )
        builder.gap("external_conversion_disabled", path, reason)
    if len(conversion_paths) > MAX_CONVERSION_RECORDS:
        builder.gap(
            "conversion_record_limit",
            "conversion-required-files",
            f"conversion metadata limited to {MAX_CONVERSION_RECORDS} files",
            len(conversion_paths) - MAX_CONVERSION_RECORDS,
        )
    _store_conversion_safety(
        builder,
        observed_types,
        files,
        incomplete=bool(conversion_paths),
    )


def _workspace_changed_paths(
    git: GitRunner,
    builder: SnapshotBuilder,
) -> tuple[list[str], list[str], list[str]]:
    staged = _changed_paths(
        git,
        builder,
        (
            "diff",
            "--cached",
            "--no-renames",
            "--name-only",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--",
        ),
    )
    unstaged = _changed_paths(
        git,
        builder,
        (
            "diff",
            "--no-renames",
            "--name-only",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
            "--",
        ),
    )
    untracked = _changed_paths(
        git,
        builder,
        ("ls-files", "--others", "--exclude-standard", "-z", "--"),
    )
    _refuse_yaml_paths([*staged, *unstaged, *untracked])
    return staged, unstaged, untracked


def _batch_unified_diff(
    git: GitRunner,
    builder: SnapshotBuilder,
    subject: str,
    batch: tuple[str, ...],
    *,
    cached: bool,
    divisible: bool,
) -> str:
    cached_argument = ("--cached",) if cached else ()
    result = git.run(
        (
            "-c",
            "core.quotePath=true",
            "diff",
            *cached_argument,
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--",
            *(f":(top,literal){path}" for path in batch),
        )
    )
    if result.truncated and divisible and len(batch) > 1:
        # Only escaped diff bodies can push an in-limits batch past the per-command
        # bound; halving keeps every path in order instead of refusing the whole diff.
        middle = len(batch) // 2
        return "".join(
            (
                _batch_unified_diff(
                    git, builder, subject, batch[:middle], cached=cached, divisible=True
                ),
                _batch_unified_diff(
                    git, builder, subject, batch[middle:], cached=cached, divisible=True
                ),
            )
        )
    return _decode_unified_diff(result, subject, builder)


def _workspace_unified_diff(
    git: GitRunner,
    builder: SnapshotBuilder,
    subject: str,
    paths: list[str],
    *,
    cached: bool,
) -> str:
    # A per-command bound limits one batch, not the snapshot: keep dividing only while the
    # artifact can still carry what was collected, so an over-budget tree is refused at the
    # command bound instead of accumulating a diff that no longer fits.
    budget = max(0, SNAPSHOT_CONTENT_BUDGET - builder.content_bytes)
    chunks: list[str] = []
    collected = 0
    for batch in _bounded_path_batches(paths):
        chunk = _batch_unified_diff(
            git,
            builder,
            subject,
            batch,
            cached=cached,
            divisible=collected < budget,
        )
        chunks.append(chunk)
        collected += len(chunk.encode("utf-8"))
    return "".join(chunks)
