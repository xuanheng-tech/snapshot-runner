"""Bounded temporary clone lifecycle for exact-path diff audits."""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .git import GIT_OID_RE, GitRunner
from .security import SNAPSHOT_COLLECTION_FAILED, RunnerError, is_sensitive_repository_path

MAX_SCOPE_PATHS = 128
MAX_SCOPE_PATH_BYTES = 32 * 1024
MAX_SCOPE_FILE_BYTES = 8 * 1024 * 1024
REVIEW_SCOPE_MODE = "isolated-clone"
TEMP_ROOT = Path("/tmp") / f"codex-snapshot-runner-{os.getuid()}"


@dataclass(frozen=True, slots=True)
class _FileEvidence:
    content: bytes
    byte_size: int
    sha256: str
    executable: bool


@dataclass(frozen=True, slots=True)
class _IndexEvidence:
    mode: str
    oid: str
    content: bytes


@dataclass(frozen=True, slots=True)
class _ScopeEvidence:
    index: _IndexEvidence | None
    worktree: _FileEvidence | None


def _fail(message: str) -> RunnerError:
    return RunnerError(SNAPSHOT_COLLECTION_FAILED, message)


def validate_scope_paths(raw_paths: Sequence[str]) -> tuple[str, ...]:
    if not raw_paths or len(raw_paths) > MAX_SCOPE_PATHS:
        raise _fail("isolated diff-audit requires a bounded non-empty exact path scope")
    paths: list[str] = []
    encoded_bytes = 0
    for raw in raw_paths:
        candidate = PurePosixPath(raw)
        if (
            not raw
            or raw in {".", "..", ".git"}
            or raw.startswith(".git/")
            or candidate.is_absolute()
            or ".." in candidate.parts
            or candidate.as_posix() != raw
            or any(character in raw for character in ("\x00", "\n", "\r", "\t"))
            or is_sensitive_repository_path(raw)
        ):
            raise _fail("isolated diff-audit path scope is unsafe")
        encoded_bytes += len(raw.encode("utf-8")) + 1
        if encoded_bytes > MAX_SCOPE_PATH_BYTES:
            raise _fail("isolated diff-audit path scope exceeds its hard limit")
        paths.append(raw)
    if len(set(paths)) != len(paths):
        raise _fail("isolated diff-audit path scope contains duplicates")
    return tuple(sorted(paths))


def _validate_real_directory(path: Path, description: str, *, private: bool) -> None:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _fail(f"{description} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or resolved != path:
        raise _fail(f"{description} is not a real directory")
    if private and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise _fail(f"{description} is not a private owned directory")


def _refuse_nested_git_root(root_parent: Path, git_executable: str) -> None:
    result = GitRunner(root_parent, git_executable).run(
        ("rev-parse", "--is-inside-work-tree"), maximum=4096
    )
    if result.truncated:
        raise _fail("temporary root Git-boundary probe exceeded its hard limit")
    if result.returncode == 0 and result.stdout.strip() == b"true":
        raise _fail("temporary review clones cannot be nested in another Git worktree")


def _ensure_temp_root(root: Path, git_executable: str) -> None:
    if not root.is_absolute() or root.name in {"", ".", ".."}:
        raise _fail("temporary review root is invalid")
    _validate_real_directory(root.parent, "temporary root parent", private=False)
    _refuse_nested_git_root(root.parent, git_executable)
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise _fail("temporary review root could not be created") from exc
    _validate_real_directory(root, "temporary review root", private=True)


def remove_owned_temp_directory(root: Path, target: Path) -> None:
    """Remove one exact owned child without following symlinks or deleting the root."""

    _validate_real_directory(root, "temporary review root", private=True)
    if target == root or target.parent != root or target.name in {"", ".", ".."}:
        raise _fail("temporary cleanup target is outside the owned root")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise _fail("platform does not provide symlink-safe recursive cleanup")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open(root, flags)
    except OSError as exc:
        raise _fail("temporary review root could not be safely opened") from exc
    try:
        try:
            metadata = os.stat(target.name, dir_fd=root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise _fail("temporary cleanup target could not be inspected") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise _fail("temporary cleanup target is not an owned real directory")
        try:
            shutil.rmtree(target.name, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
        except OSError as exc:
            raise _fail("temporary review directory could not be safely removed") from exc
    finally:
        os.close(root_descriptor)


def _open_directory(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return os.open(path, flags)


def _read_source_file(repo_root: Path, relative: str) -> _FileEvidence | None:
    parts = PurePosixPath(relative).parts
    try:
        directory_descriptor = _open_directory(repo_root)
    except OSError as exc:
        raise _fail("source repository could not be safely opened") from exc
    try:
        for component in parts[:-1]:
            try:
                metadata = os.stat(component, dir_fd=directory_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise _fail("source scope directory could not be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise _fail("source scope contains a symlink or non-directory ancestor")
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise _fail("source scope directory could not be safely opened") from exc
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        try:
            before = os.stat(parts[-1], dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise _fail("source scope path could not be inspected") from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise _fail("source scope path must be a regular non-symlink file or a deletion")
        if before.st_size > MAX_SCOPE_FILE_BYTES:
            raise _fail("source scope file exceeds its hard copy limit")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(parts[-1], flags, dir_fd=directory_descriptor)
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise _fail("source scope file could not be safely opened") from exc
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            os.close(descriptor)
            raise _fail("source scope file changed during safe open")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        byte_size = 0
        try:
            while True:
                chunk = os.read(descriptor, min(64 * 1024, MAX_SCOPE_FILE_BYTES + 1 - byte_size))
                if not chunk:
                    break
                byte_size += len(chunk)
                if byte_size > MAX_SCOPE_FILE_BYTES:
                    raise _fail("source scope file exceeds its hard copy limit")
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
            raise _fail("source scope file changed while reading")
        return _FileEvidence(
            b"".join(chunks),
            byte_size,
            digest.hexdigest(),
            bool(opened.st_mode & 0o111),
        )
    finally:
        os.close(directory_descriptor)


def _destination_parent_descriptor(
    repo_root: Path,
    relative: str,
    *,
    create: bool,
) -> int | None:
    parts = PurePosixPath(relative).parts
    try:
        directory_descriptor = _open_directory(repo_root)
    except OSError as exc:
        raise _fail("temporary clone could not be safely opened") from exc
    try:
        for component in parts[:-1]:
            try:
                metadata = os.stat(component, dir_fd=directory_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    os.close(directory_descriptor)
                    return None
                try:
                    os.mkdir(component, mode=0o700, dir_fd=directory_descriptor)
                    metadata = os.stat(
                        component, dir_fd=directory_descriptor, follow_symlinks=False
                    )
                except OSError as exc:
                    raise _fail("temporary clone scope directory could not be created") from exc
            except OSError as exc:
                raise _fail("temporary clone scope directory could not be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise _fail("temporary clone scope contains a symlink or non-directory ancestor")
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_descriptor,
                )
            except OSError as exc:
                raise _fail("temporary clone scope directory could not be safely opened") from exc
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return directory_descriptor
    except Exception:
        with contextlib.suppress(OSError):
            os.close(directory_descriptor)
        raise


def _materialize_destination_file(
    repo_root: Path,
    relative: str,
    content: bytes,
    *,
    executable: bool,
) -> None:
    directory_descriptor = _destination_parent_descriptor(repo_root, relative, create=True)
    assert directory_descriptor is not None
    name = PurePosixPath(relative).name
    try:
        before: os.stat_result | None
        try:
            before = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        except OSError as exc:
            raise _fail("temporary clone scope path could not be inspected") from exc
        if before is not None and (
            stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
        ):
            raise _fail("temporary clone scope path is not a regular non-symlink file")
        flags = (
            os.O_WRONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | (os.O_TRUNC if before is not None else os.O_CREAT | os.O_EXCL)
        )
        mode = 0o755 if executable else 0o644
        try:
            descriptor = os.open(name, flags, mode, dir_fd=directory_descriptor)
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise _fail("temporary clone scope file could not be safely opened") from exc
        if not stat.S_ISREG(opened.st_mode) or (
            before is not None and (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            os.close(descriptor)
            raise _fail("temporary clone scope file changed during safe open")
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise _fail("temporary clone scope file could not be completely written")
                offset += written
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_descriptor)


def _delete_destination_file(repo_root: Path, relative: str) -> None:
    directory_descriptor = _destination_parent_descriptor(repo_root, relative, create=False)
    if directory_descriptor is None:
        raise _fail("deleted scope path is not present in the temporary clone baseline")
    name = PurePosixPath(relative).name
    try:
        try:
            metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise _fail(
                "deleted scope path is not present in the temporary clone baseline"
            ) from exc
        except OSError as exc:
            raise _fail("deleted scope path could not be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise _fail("deleted scope path is not a regular non-symlink baseline file")
        try:
            os.unlink(name, dir_fd=directory_descriptor)
        except OSError as exc:
            raise _fail("deleted scope path could not be removed from the temporary clone") from exc
    finally:
        os.close(directory_descriptor)


def _git_head(repo: Path, git_executable: str) -> str:
    result = GitRunner(repo, git_executable).run(("rev-parse", "--verify", "HEAD"), maximum=4096)
    if result.returncode != 0 or result.truncated or result.stderr:
        raise _fail("isolated diff-audit requires one stable source HEAD")
    try:
        head = result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise _fail("isolated diff-audit source HEAD is invalid") from exc
    if GIT_OID_RE.fullmatch(head) is None:
        raise _fail("isolated diff-audit source HEAD is invalid")
    return head


def _require_exact_change(repo: Path, relative: str, git_executable: str) -> None:
    result = GitRunner(repo, git_executable).run(
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            f":(top,literal){relative}",
        )
    )
    if result.returncode != 0 or result.truncated or result.stderr:
        raise _fail("temporary clone scope status could not be verified")
    entries = [entry for entry in result.stdout.split(b"\0") if entry]
    try:
        observed = [entry[3:].decode("utf-8", errors="strict") for entry in entries]
        codes = [entry[:2].decode("utf-8", errors="strict") for entry in entries]
    except UnicodeDecodeError as exc:
        raise _fail("temporary clone scope status is not valid UTF-8") from exc
    # A staged deletion whose path is re-created outside the index legitimately reports one
    # tracked entry plus one untracked entry for the same path; every other shape is ambiguous.
    if (
        not entries
        or len(entries) > 2
        or any(len(entry) < 4 for entry in entries)
        or observed != [relative] * len(entries)
        or len(set(codes)) != len(codes)
        or (len(entries) == 2 and "??" not in codes)
    ):
        raise _fail("isolated diff-audit scope path is unchanged or ambiguous")


def _clone_repository(
    source: Path,
    destination: Path,
    expected_head: str,
    git_executable: str,
) -> None:
    result = GitRunner(source, git_executable).run(
        (
            "clone",
            "--quiet",
            "--no-local",
            "--no-hardlinks",
            "--no-tags",
            os.fspath(source),
            os.fspath(destination),
        )
    )
    if result.returncode != 0 or result.truncated:
        raise _fail("temporary review clone failed")
    if _git_head(destination, git_executable) != expected_head:
        raise _fail("temporary review clone HEAD does not match the source")


def _read_source_index_entry(
    repo: Path,
    relative: str,
    git_executable: str,
) -> _IndexEvidence | None:
    """Read the exact stage-0 index entry for one scope path, or None when unstaged."""

    runner = GitRunner(repo, git_executable)
    listing = runner.run(
        ("ls-files", "--stage", "-z", "--", f":(top,literal){relative}"),
        maximum=4096,
    )
    if listing.returncode != 0 or listing.truncated or listing.stderr:
        raise _fail("source scope index entry could not be read")
    records = [record for record in listing.stdout.split(b"\0") if record]
    if not records:
        return None
    if len(records) != 1:
        raise _fail("source scope path has an unmerged or ambiguous index entry")
    try:
        header, path = records[0].decode("utf-8", errors="strict").split("\t", 1)
    except (UnicodeDecodeError, ValueError) as exc:
        raise _fail("source scope index entry is not valid UTF-8") from exc
    fields = header.split(" ")
    if len(fields) != 3 or path != relative:
        raise _fail("source scope index entry is malformed")
    mode, oid, stage = fields
    if stage != "0":
        raise _fail("source scope path has an unmerged index entry")
    if mode not in {"100644", "100755"}:
        raise _fail("source scope index entry is not a regular non-symlink blob")
    if GIT_OID_RE.fullmatch(oid) is None:
        raise _fail("source scope index entry has an invalid object name")
    size_result = runner.run(("cat-file", "-s", oid), maximum=4096)
    size_text = size_result.stdout.decode("ascii", errors="replace").strip()
    if (
        size_result.returncode != 0
        or size_result.truncated
        or size_result.stderr
        or not size_text.isdigit()
    ):
        raise _fail("source scope index blob size could not be read")
    byte_size = int(size_text)
    if byte_size > MAX_SCOPE_FILE_BYTES:
        raise _fail("source scope index blob exceeds its hard copy limit")
    blob = runner.run(("cat-file", "blob", oid), maximum=MAX_SCOPE_FILE_BYTES + 1)
    if blob.returncode != 0 or blob.truncated or blob.stderr or len(blob.stdout) != byte_size:
        raise _fail("source scope index blob could not be read")
    return _IndexEvidence(mode, oid, blob.stdout)


def _apply_index_state(
    destination: Path,
    relative: str,
    entry: _IndexEvidence | None,
    git_executable: str,
) -> None:
    """Reproduce the source index state for one scope path inside the clone."""

    runner = GitRunner(destination, git_executable)
    if entry is None:
        removal = runner.run(("update-index", "--force-remove", "--", relative))
        if removal.returncode != 0 or removal.truncated or removal.stderr:
            raise _fail("temporary clone scope index entry could not be removed")
        return
    _materialize_destination_file(
        destination, relative, entry.content, executable=entry.mode == "100755"
    )
    staged = runner.run(("update-index", "--add", "--", relative))
    if staged.returncode != 0 or staged.truncated or staged.stderr:
        raise _fail("temporary clone scope index entry could not be staged")
    observed = _read_source_index_entry(destination, relative, git_executable)
    if observed is None or (observed.mode, observed.oid) != (entry.mode, entry.oid):
        raise _fail("temporary clone scope index entry does not match the source index")


def _apply_worktree_state(
    destination: Path,
    relative: str,
    evidence: _FileEvidence | None,
) -> None:
    if evidence is None:
        _delete_destination_file(destination, relative)
        return
    _materialize_destination_file(
        destination, relative, evidence.content, executable=evidence.executable
    )


def _overlay_scope(
    source: Path,
    destination: Path,
    paths: tuple[str, ...],
    git_executable: str,
) -> None:
    evidence: dict[str, _ScopeEvidence] = {}
    for relative in paths:
        source_evidence = _ScopeEvidence(
            _read_source_index_entry(source, relative, git_executable),
            _read_source_file(source, relative),
        )
        evidence[relative] = source_evidence
        _apply_index_state(destination, relative, source_evidence.index, git_executable)
        _apply_worktree_state(destination, relative, source_evidence.worktree)
        _require_exact_change(destination, relative, git_executable)
    for relative, expected in evidence.items():
        observed = _ScopeEvidence(
            _read_source_index_entry(source, relative, git_executable),
            _read_source_file(source, relative),
        )
        if observed != expected:
            raise _fail("source scope changed while the temporary review clone was prepared")


@contextlib.contextmanager
def isolated_diff_repository(
    source: Path,
    repository_name: str,
    expected_head: str,
    scope_paths: tuple[str, ...],
    git_executable: str,
) -> Iterator[Path]:
    """Yield a scoped clone and always remove its exact owned task directory."""

    if GIT_OID_RE.fullmatch(expected_head) is None:
        raise _fail("isolated diff-audit requires one stable source HEAD")
    root = TEMP_ROOT
    _ensure_temp_root(root, git_executable)
    try:
        task_directory = Path(tempfile.mkdtemp(prefix=f"{repository_name}-review-", dir=root))
    except OSError as exc:
        raise _fail("temporary review directory could not be created") from exc
    try:
        _validate_real_directory(task_directory, "temporary review directory", private=True)
        destination = task_directory / repository_name
        _clone_repository(source, destination, expected_head, git_executable)
        _overlay_scope(source, destination, scope_paths, git_executable)
        if _git_head(source, git_executable) != expected_head:
            raise _fail("source HEAD changed while the temporary review clone was prepared")
        yield destination
    finally:
        remove_owned_temp_directory(root, task_directory)
