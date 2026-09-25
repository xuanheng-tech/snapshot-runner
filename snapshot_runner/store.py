"""Filesystem state home, private staging, atomic writes and stored-snapshot loading."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path

from .artifact import (
    _protect_snapshot_redactions,
    _restore_snapshot_redactions,
    _runner_security_error,
    _serialize_snapshot,
    _serialize_snapshot_meta,
    _snapshot_data_scan_manifest,
    _snapshot_scan_manifest,
)
from .legacy_v2 import (
    _is_exact_version,
    _validate_snapshot_envelope,
    _validate_snapshot_meta_schema,
)
from .model import (
    MAX_META_BYTES,
    MAX_PREVIEW_BYTES,
    MAX_SNAPSHOT_BYTES,
    PRODUCER_SECURITY_EPOCH,
    REPOSITORY_ROOT,
    SNAPSHOT_FILE_NAMES,
    SNAPSHOT_ID_RE,
    SNAPSHOT_META_SCHEMA_VERSION,
    SNAPSHOT_SCHEMA_VERSION,
    SNAPSHOT_SECURITY_EPOCH_ERROR,
    STATE_HOME_MISSING_ERROR,
    SnapshotArtifact,
)
from .security import (
    ARTIFACT_PUBLISH_FAILED,
    ARTIFACT_VALIDATION_FAILED,
    REPOSITORY_VALIDATION_FAILED,
    RunnerError,
    ScanModeManifest,
    SecurityError,
    sanitize_json_value,
)
from .security import (
    paths_overlap as _paths_overlap,
)
from .security import (
    validate_no_symlink_ancestors as _validate_no_symlink_ancestors,
)

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


def _sanitize_validate_snapshot(
    payload: object,
    repository_root: Path,
    *,
    extra_paths: tuple[Path, ...] = (),
    expected_scan_manifest: ScanModeManifest | None = None,
    verify_live_diff_text: bool = True,
) -> dict[str, object]:
    envelope = _validate_snapshot_envelope(payload)
    try:
        derived_snapshot_manifest = _snapshot_data_scan_manifest(envelope)
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
        scan_manifest = _snapshot_scan_manifest(protected)
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
    normalized = _validate_snapshot_envelope(_restore_snapshot_redactions(normalized, redactions))

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
    if not isinstance(meta, dict) or not _is_exact_version(
        meta.get("producer_security_epoch"), PRODUCER_SECURITY_EPOCH
    ):
        raise RunnerError(ARTIFACT_PUBLISH_FAILED, SNAPSHOT_SECURITY_EPOCH_ERROR)
    meta = _validate_snapshot_meta_schema(meta)
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
    )
    if _serialize_snapshot(envelope) != snapshot_bytes:
        raise RunnerError(
            ARTIFACT_PUBLISH_FAILED, "snapshot hash or canonical artifact validation failed"
        )
    task = envelope["task"]
    if (
        not _is_exact_version(meta.get("schema_version"), SNAPSHOT_META_SCHEMA_VERSION)
        or not _is_exact_version(envelope.get("schema_version"), SNAPSHOT_SCHEMA_VERSION)
        or not _is_exact_version(meta.get("producer_security_epoch"), PRODUCER_SECURITY_EPOCH)
        or not _is_exact_version(envelope.get("producer_security_epoch"), PRODUCER_SECURITY_EPOCH)
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
