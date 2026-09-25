"""Where repository evidence lives and how a unified diff is shaped by path."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .git import GitResult
from .security import (
    ARTIFACT_VALIDATION_FAILED,
    SNAPSHOT_COLLECTION_FAILED,
    YAML_CONTENT_REFUSED,
    RunnerError,
    SecurityError,
    unified_diff_path_changes,
)


def _snapshot_security_error(error: SecurityError, fallback: str) -> RunnerError:
    if str(error) == YAML_CONTENT_REFUSED:
        return RunnerError(SNAPSHOT_COLLECTION_FAILED, YAML_CONTENT_REFUSED)
    return RunnerError(SNAPSHOT_COLLECTION_FAILED, fallback)


@dataclass(frozen=True, slots=True)
class _BranchPathChange:
    status: str
    path: str
    old_path: str | None = None


def _parsed_unified_diff_changes(
    raw: str,
    repository_root: Path,
    source: str,
) -> tuple[tuple[str | None, str | None], ...]:
    try:
        return unified_diff_path_changes(raw, repository_root=repository_root)
    except SecurityError as exc:
        raise _snapshot_security_error(
            exc,
            f"unable to sanitize {source}; prepare refused",
        ) from exc


def _validate_workspace_diff_paths(
    raw: str,
    expected_paths: list[str],
    repository_root: Path,
    source: str,
) -> tuple[tuple[str | None, str | None], ...]:
    changes = _parsed_unified_diff_changes(raw, repository_root, source)
    expected = list(dict.fromkeys(expected_paths))
    observed: list[str] = []
    for old_path, new_path in changes:
        for path in (old_path, new_path):
            if path is not None and path not in observed:
                observed.append(path)
    if (
        len(changes) != len(expected)
        or len(observed) != len(expected)
        or set(observed) != set(expected)
    ):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "unified diff paths do not match Git workspace metadata",
        )
    return changes


def _validate_branch_diff_paths(
    raw: str,
    expected_changes: list[_BranchPathChange],
    repository_root: Path,
    source: str,
) -> None:
    observed = _parsed_unified_diff_changes(raw, repository_root, source)
    expected: list[tuple[str | None, str | None]] = []
    for change in expected_changes:
        kind = change.status[:1]
        if kind == "A":
            expected.append((None, change.path))
        elif kind == "D":
            expected.append((change.path, None))
        elif kind == "R":
            expected.append((change.old_path, change.path))
        else:
            expected.append((change.path, change.path))
    if len(observed) != len(expected) or sorted(observed, key=repr) != sorted(expected, key=repr):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "unified diff paths do not match Git branch metadata",
        )


def _safe_relative_path(raw: str) -> str | None:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def _decode_branch_path(raw: bytes) -> str:
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "branch-review path evidence is not valid UTF-8"
        ) from exc
    relative = _safe_relative_path(decoded)
    if relative is None or any(character in relative for character in ("\r", "\n")):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "branch-review path evidence is not a safe relative path"
        )
    return relative


def _branch_changes(result: GitResult) -> list[_BranchPathChange]:
    if result.returncode != 0 or result.truncated:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "branch-review changed path evidence failed closed"
        )
    fields = result.stdout.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    changes: list[_BranchPathChange] = []
    index = 0
    while index < len(fields):
        try:
            status = fields[index].decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "branch-review change status is invalid"
            ) from exc
        index += 1
        kind = status[:1]
        if kind == "R" and status[1:].isdigit():
            if index + 1 >= len(fields):
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED, "branch-review rename evidence is incomplete"
                )
            old_path = _decode_branch_path(fields[index])
            path = _decode_branch_path(fields[index + 1])
            index += 2
            changes.append(_BranchPathChange(status, path, old_path))
            continue
        if status not in {"A", "D", "M", "T"} or index >= len(fields):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "branch-review change status is unsupported"
            )
        path = _decode_branch_path(fields[index])
        index += 1
        changes.append(_BranchPathChange(status, path))
    return changes


def _bounded_path_batches(paths: list[str]) -> list[tuple[str, ...]]:
    """Split ``paths`` into duplicate-free runs of at most 256 paths and 32 KiB each."""
    batches: list[tuple[str, ...]] = []
    current: list[str] = []
    current_bytes = 0
    for path in dict.fromkeys(paths):
        encoded_bytes = len(path.encode("utf-8")) + 1
        if encoded_bytes > 32 * 1024:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "repository path exceeds the conversion inspection limit",
            )
        if current and (len(current) >= 256 or current_bytes + encoded_bytes > 32 * 1024):
            batches.append(tuple(current))
            current = []
            current_bytes = 0
        current.append(path)
        current_bytes += encoded_bytes
    if current:
        batches.append(tuple(current))
    return batches


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
