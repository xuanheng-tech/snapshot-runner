from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..evidence import (
    _safe_relative_path,
)
from ..git import (
    IMAGE_EVIDENCE_MAX_BYTES,
    GitRunner,
)
from ..model import (
    MAX_FILE_BYTES,
    MAX_TEST_LOG_BYTES,
    UV_LOCK_MAX_FILE_BYTES,
)
from ..security import (
    MAX_EXTENSIONLESS_TEXT_BYTES,
    SNAPSHOT_COLLECTION_FAILED,
    YAML_CONTENT_REFUSED,
    RunnerError,
    is_sensitive_repository_path,
    is_yaml_content_path,
    raster_image_magic_matches,
    raster_image_media_type,
)
from .builder import (
    SnapshotBuilder,
)


@dataclass(frozen=True, slots=True)
class _BoundedTextEvidence:
    content: str | None
    gap_kind: str | None
    reason: str | None
    omitted_bytes: int | None


@dataclass(frozen=True, slots=True)
class _RawFileEvidence:
    content: bytes
    byte_size: int
    sha256: str
    executable: bool


def _text_refusal(
    reason: str,
    omitted_bytes: int | None = None,
    *,
    kind: str = "file_refused",
) -> _BoundedTextEvidence:
    return _BoundedTextEvidence(None, kind, reason, omitted_bytes)


def _complete_text(content: str) -> _BoundedTextEvidence:
    return _BoundedTextEvidence(content, None, None, None)


def _open_repo_regular(
    repo_root: Path, relative_path: str
) -> tuple[int | None, os.stat_result | None, str | None]:
    relative = _safe_relative_path(relative_path)
    if relative is None:
        return None, None, "unsafe repository path"
    parts = PurePosixPath(relative).parts
    if not parts:
        return None, None, "unsafe repository path"
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_descriptor = os.open(repo_root, directory_flags)
    except OSError:
        return None, None, "repository root unavailable"
    try:
        for component in parts[:-1]:
            try:
                component_stat = os.stat(
                    component,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(component_stat.st_mode):
                    return None, None, "symlink path component refused"
                if not stat.S_ISDIR(component_stat.st_mode):
                    return None, None, "non-directory path component refused"
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            except OSError:
                return None, None, "race-safe directory open failed"
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        try:
            final_stat = os.stat(parts[-1], dir_fd=directory_descriptor, follow_symlinks=False)
            if stat.S_ISLNK(final_stat.st_mode):
                return None, final_stat, "symlink refused"
            if not stat.S_ISREG(final_stat.st_mode):
                return None, final_stat, "non-regular file refused"
            file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(parts[-1], file_flags, dir_fd=directory_descriptor)
            opened = os.fstat(descriptor)
        except FileNotFoundError:
            return None, None, "file missing"
        except OSError:
            return None, None, "race-safe file open failed"
        if (opened.st_dev, opened.st_ino) != (final_stat.st_dev, final_stat.st_ino):
            os.close(descriptor)
            return None, final_stat, "file changed during safe open"
        return descriptor, opened, None
    finally:
        os.close(directory_descriptor)


def _read_regular_file(
    repo_root: Path,
    relative_path: str,
    maximum: int,
) -> tuple[str | None, int, str | None]:
    relative = _safe_relative_path(relative_path)
    if relative is None:
        return None, 0, "unsafe repository path"
    if is_sensitive_repository_path(relative):
        return None, 0, "sensitive path refused"
    descriptor, opened, reason = _open_repo_regular(repo_root, relative)
    if reason is not None:
        size = opened.st_size if opened is not None else 0
        legacy_reason = "race-safe file open failed" if reason == "file missing" else reason
        return None, size, legacy_reason
    assert descriptor is not None
    assert opened is not None
    try:
        raw = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            return None, after.st_size, "file changed while reading"
    finally:
        os.close(descriptor)
    if b"\0" in raw:
        return None, opened.st_size, "binary file refused"
    truncated = max(0, opened.st_size - maximum)
    raw = raw[:maximum]
    try:
        return raw.decode("utf-8", errors="strict"), truncated, None
    except UnicodeDecodeError:
        return None, opened.st_size, "non-UTF-8 file refused"


def _read_complete_regular(
    repo_root: Path,
    relative_path: str,
    maximum: int,
) -> _RawFileEvidence:
    relative = _safe_relative_path(relative_path)
    if relative is None or is_sensitive_repository_path(relative):
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "publication evidence path is unsafe")
    descriptor, opened, reason = _open_repo_regular(repo_root, relative)
    if reason is not None or descriptor is None or opened is None:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "publication evidence requires a stable regular file",
        )
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    byte_size = 0
    try:
        if opened.st_size > maximum:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "publication evidence file exceeds its hard read limit",
            )
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - byte_size))
            if not chunk:
                break
            byte_size += len(chunk)
            if byte_size > maximum:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED,
                    "publication evidence file exceeds its hard read limit",
                )
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_size,
        opened.st_mtime_ns,
    ) or byte_size != opened.st_size:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "publication evidence file changed while reading",
        )
    return _RawFileEvidence(
        b"".join(chunks),
        byte_size,
        digest.hexdigest(),
        bool(opened.st_mode & 0o111),
    )


def _image_summary(media_type: str, byte_size: int, sha256: str) -> str:
    return (
        "binary image evidence\n"
        f"media_type: {media_type}\n"
        f"byte_size: {byte_size}\n"
        f"sha256: {sha256}\n"
    )


def _read_image_worktree(
    repo_root: Path,
    relative: str,
) -> tuple[_BoundedTextEvidence, bool | None]:
    media_type = raster_image_media_type(relative)
    if media_type is None:
        return _text_refusal("sensitive or unsafe image path refused"), None
    descriptor, opened, reason = _open_repo_regular(repo_root, relative)
    if reason is not None:
        size = opened.st_size if opened is not None else None
        return _text_refusal(reason, size if size else None), None
    assert descriptor is not None
    assert opened is not None
    executable = bool(opened.st_mode & 0o111)
    if opened.st_size > IMAGE_EVIDENCE_MAX_BYTES:
        os.close(descriptor)
        return (
            _text_refusal(
                "image evidence exceeds the existing 2 MiB Git output limit",
                opened.st_size,
                kind="file_limit",
            ),
            executable,
        )
    digest = hashlib.sha256()
    prefix = bytearray()
    byte_size = 0
    exceeded = False
    try:
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            byte_size += len(chunk)
            if byte_size > IMAGE_EVIDENCE_MAX_BYTES:
                exceeded = True
                break
            digest.update(chunk)
            if len(prefix) < 16:
                prefix.extend(chunk[: 16 - len(prefix)])
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ) != (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_size,
        opened.st_mtime_ns,
    ) or byte_size != opened.st_size:
        return _text_refusal("file changed while reading"), None
    if exceeded:
        return (
            _text_refusal(
                "image evidence exceeds the existing 2 MiB Git output limit",
                opened.st_size,
                kind="file_limit",
            ),
            executable,
        )
    if not raster_image_magic_matches(media_type, bytes(prefix), byte_size):
        return (
            _text_refusal("image extension and magic bytes do not match", byte_size),
            executable,
        )
    return _complete_text(_image_summary(media_type, byte_size, digest.hexdigest())), executable


def _git_blob_size(git: GitRunner, object_id: str) -> int | None:
    result = git.run(("cat-file", "-s", object_id), maximum=4096)
    try:
        size_text = result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError:
        return None
    if result.returncode != 0 or result.truncated or result.stderr or not size_text.isdigit():
        return None
    return int(size_text)


def _read_image_blob(
    git: GitRunner,
    relative: str,
    mode: str,
    object_id: str,
    size_hint: int | None,
    cache: dict[tuple[str, str], _BoundedTextEvidence],
) -> tuple[_BoundedTextEvidence, bool | None]:
    if mode not in {"100644", "100755"}:
        return _text_refusal("symlink or non-regular Git entry refused"), None
    media_type = raster_image_media_type(relative)
    if media_type is None:
        return _text_refusal("sensitive or unsafe image path refused"), None
    key = (object_id, media_type)
    cached = cache.get(key)
    if cached is not None:
        return cached, mode == "100755"
    byte_size = size_hint if size_hint is not None else _git_blob_size(git, object_id)
    if byte_size is None:
        evidence = _text_refusal("Git blob size unavailable")
    elif byte_size > IMAGE_EVIDENCE_MAX_BYTES:
        evidence = _text_refusal(
            "image evidence exceeds the existing 2 MiB Git output limit",
            byte_size,
            kind="file_limit",
        )
    else:
        blob = git.hash_blob(object_id, byte_size, maximum=IMAGE_EVIDENCE_MAX_BYTES)
        if not raster_image_magic_matches(media_type, blob.prefix, blob.byte_size):
            evidence = _text_refusal(
                "image extension and magic bytes do not match",
                blob.byte_size,
            )
        else:
            evidence = _complete_text(_image_summary(media_type, blob.byte_size, blob.sha256))
    cache[key] = evidence
    return evidence, mode == "100755"


def _record_image_gap(
    builder: SnapshotBuilder,
    relative: str,
    source: str,
    evidence: _BoundedTextEvidence,
) -> None:
    assert evidence.gap_kind is not None
    assert evidence.reason is not None
    builder.gap(
        evidence.gap_kind,
        relative,
        f"{source} image evidence refused: {evidence.reason}",
        evidence.omitted_bytes,
    )


def _read_test_log(repo_root: Path, supplied: str) -> tuple[str, int, str]:
    relative = _safe_relative_path(supplied)
    if relative is None:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "test log refused: unsafe repository path")
    if is_yaml_content_path(relative):
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, YAML_CONTENT_REFUSED)
    if is_sensitive_repository_path(relative):
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "test log path is classified as sensitive")
    descriptor, opened, reason = _open_repo_regular(repo_root, relative)
    if reason is not None:
        if reason == "file missing":
            reason = "race-safe file open failed"
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, f"test log refused: {reason}")
    assert descriptor is not None
    assert opened is not None
    try:
        size = opened.st_size
        if size <= MAX_TEST_LOG_BYTES:
            raw = os.read(descriptor, MAX_TEST_LOG_BYTES + 1)
            omitted = 0
        else:
            marker = b"\n[...TEST_LOG_MIDDLE_OMITTED...]\n"
            half = (MAX_TEST_LOG_BYTES - len(marker)) // 2
            head = os.read(descriptor, half)
            os.lseek(descriptor, max(0, size - half), os.SEEK_SET)
            tail = os.read(descriptor, half)
            raw = head + marker + tail
            omitted = size - len(head) - len(tail)
        after = os.fstat(descriptor)
        if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "test log changed while reading")
    finally:
        os.close(descriptor)
    if b"\0" in raw:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "binary test log refused")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "non-UTF-8 test log refused") from exc
    return text, omitted, "test-output.log"


def _file_context_limit(relative: str) -> int:
    if PurePosixPath(relative).name == "uv.lock":
        return UV_LOCK_MAX_FILE_BYTES
    return MAX_FILE_BYTES


def _read_extensionless_worktree(
    repo_root: Path,
    relative: str,
) -> tuple[_BoundedTextEvidence, bool | None]:
    descriptor, opened, reason = _open_repo_regular(repo_root, relative)
    if reason is not None:
        size = opened.st_size if opened is not None else None
        return (
            _text_refusal(reason, size if size else None),
            None,
        )
    assert descriptor is not None
    assert opened is not None
    executable = bool(opened.st_mode & 0o111)
    try:
        if opened.st_size > MAX_EXTENSIONLESS_TEXT_BYTES:
            after = os.fstat(descriptor)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ):
                return (
                    _text_refusal("file changed while reading"),
                    None,
                )
            return (
                _text_refusal(
                    "extensionless text exceeds 64 KiB",
                    opened.st_size,
                    kind="file_limit",
                ),
                executable,
            )
        chunks: list[bytes] = []
        remaining = MAX_EXTENSIONLESS_TEXT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) or len(raw) != opened.st_size:
            return (
                _text_refusal("file changed while reading"),
                None,
            )
    finally:
        os.close(descriptor)
    if b"\0" in raw:
        return (
            _text_refusal("binary file refused", len(raw)),
            executable,
        )
    try:
        content = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return (
            _text_refusal("non-UTF-8 file refused", len(raw)),
            executable,
        )
    return _complete_text(content), executable


def _read_extensionless_blob(
    git: GitRunner,
    object_id: str,
    size_hint: int | None,
    cache: dict[tuple[str, str], _BoundedTextEvidence],
) -> _BoundedTextEvidence:
    key = ("blob", object_id)
    cached = cache.get(key)
    if cached is not None:
        return cached
    size = size_hint
    if size is None:
        size_result = git.run(("cat-file", "-s", object_id), maximum=4096)
        try:
            size_text = size_result.stdout.decode("ascii", errors="strict").strip()
        except UnicodeDecodeError:
            size_text = ""
        if (
            size_result.returncode != 0
            or size_result.truncated
            or size_result.stderr
            or not size_text.isdigit()
        ):
            evidence = _text_refusal("Git blob size unavailable")
            cache[key] = evidence
            return evidence
        size = int(size_text)
    if size > MAX_EXTENSIONLESS_TEXT_BYTES:
        evidence = _text_refusal(
            "extensionless text exceeds 64 KiB",
            size,
            kind="file_limit",
        )
        cache[key] = evidence
        return evidence
    result = git.run(
        ("cat-file", "blob", object_id),
        maximum=MAX_EXTENSIONLESS_TEXT_BYTES + 1,
    )
    if result.returncode != 0 or result.truncated or result.stderr or len(result.stdout) != size:
        evidence = _text_refusal("Git blob content unavailable")
        cache[key] = evidence
        return evidence
    if b"\0" in result.stdout:
        evidence = _text_refusal("binary Git blob refused", size if size else None)
        cache[key] = evidence
        return evidence
    try:
        content = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        evidence = _text_refusal("non-UTF-8 Git blob refused", size if size else None)
        cache[key] = evidence
        return evidence
    evidence = _complete_text(content)
    cache[key] = evidence
    return evidence


def _record_extensionless_gap(
    builder: SnapshotBuilder,
    relative: str,
    source: str,
    evidence: _BoundedTextEvidence,
) -> None:
    assert evidence.gap_kind is not None
    assert evidence.reason is not None
    builder.gap(
        evidence.gap_kind,
        relative,
        f"{source} evidence refused: {evidence.reason}",
        evidence.omitted_bytes,
    )


def _read_extensionless_git_entry(
    git: GitRunner,
    mode: str,
    object_id: str,
    size: int | None,
    cache: dict[tuple[str, str], _BoundedTextEvidence],
) -> tuple[_BoundedTextEvidence, bool | None]:
    if mode not in {"100644", "100755"}:
        return (
            _text_refusal("symlink or non-regular Git entry refused"),
            None,
        )
    return _read_extensionless_blob(git, object_id, size, cache), mode == "100755"
