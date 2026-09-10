"""Fixed Git execution, repository identity, and capability validation."""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import stat
import subprocess
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType

from .security import (
    GIT_COMMAND_FAILED,
    GIT_PREFLIGHT_FAILED,
    REPOSITORY_VALIDATION_FAILED,
    SNAPSHOT_COLLECTION_FAILED,
    RunnerError,
)
from .security import (
    canonical_owned_directory as _canonical_owned_directory,
)
from .security import (
    paths_overlap as _paths_overlap,
)

MAX_GIT_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_GIT_CONVERSION_OVERRIDES = 256
GIT_TIMEOUT_SECONDS = 30.0
MAX_GIT_PREFLIGHT_ENTRIES = 200_000
GIT_CAPABILITY_REFUSED_ERROR = "unsupported Git attributes or external conversion capability"
GIT_REPLACEMENT_REFUSED_ERROR = "unsupported Git replacement or graft capability"
GIT_PROMISOR_REFUSED_ERROR = "unsupported Git partial-clone or promisor capability"
GIT_ALTERNATE_OBJECTS_REFUSED_ERROR = "unsupported Git alternate object database capability"
GIT_SHALLOW_REFUSED_ERROR = "unsupported shallow repository or shallow ancestry capability"
GIT_CAPABILITY_STATE_CHANGED_ERROR = "sealed Git capability state changed"
BRANCH_REVIEW_STATE_CHANGED_ERROR = "branch-review sealed Git state changed"
BRANCH_REVIEW_RANGE_SEMANTICS = "merge-base-to-target-head"
TARGET_REPOSITORY_INVALID_ERROR = "target repository validation failed"
RUNNER_REPOSITORY_INVALID_ERROR = "Runner repository validation failed"
STATE_GIT_BOUNDARY_ERROR = "state home must be outside and separate from Git administration"
TRUSTED_EXECUTABLES = {"git": Path("/usr/bin/git")}

_VALIDATED_REPOSITORY_SEAL = object()


@dataclass(frozen=True, slots=True)
class GitResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    truncated: bool
    operation: str = "git"


@dataclass(frozen=True, slots=True)
class GitBlobDigest:
    byte_size: int
    prefix: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class GitPathIdentity:
    path: str
    device: int
    inode: int
    mode: int


@dataclass(frozen=True, slots=True)
class GitShallowPathFingerprint:
    path: str
    parent: GitPathIdentity
    state: str


@dataclass(frozen=True, slots=True)
class GitShallowFingerprint:
    is_shallow_repository: bool
    actual_path: str
    candidate_paths: tuple[GitShallowPathFingerprint, ...]
    boundary_directories: tuple[GitPathIdentity, ...]


@dataclass(frozen=True, slots=True)
class GitConversionDriver:
    name: str
    disabled_types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GitConversionPolicy:
    config_overrides: tuple[str, ...] = ()
    filter_drivers: tuple[GitConversionDriver, ...] = ()
    diff_drivers: tuple[GitConversionDriver, ...] = ()
    external_diff: bool = False
    attributes_file_disabled: bool = False

    @property
    def disabled_config_types(self) -> tuple[str, ...]:
        types = {
            disabled_type
            for driver in (*self.filter_drivers, *self.diff_drivers)
            for disabled_type in driver.disabled_types
        }
        if self.external_diff:
            types.add("external_diff")
        if self.attributes_file_disabled:
            types.add("external_attributes_file")
        return tuple(sorted(types))


@dataclass(frozen=True, slots=True)
class GitCapabilityFingerprint:
    repository_root: GitPathIdentity
    git_dir: GitPathIdentity
    git_common_dir: GitPathIdentity
    graft_paths: tuple[str, ...]
    object_directory_paths: tuple[str, ...]
    object_directories: tuple[GitPathIdentity, ...]
    shallow: GitShallowFingerprint
    conversion_policy: GitConversionPolicy = GitConversionPolicy()


GIT_OID_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
HEAD_STATE_ATTACHED = "attached"
HEAD_STATE_DETACHED = "detached"
HEAD_STATE_UNBORN = "unborn"
HEAD_STATES = frozenset({HEAD_STATE_ATTACHED, HEAD_STATE_DETACHED, HEAD_STATE_UNBORN})
OBJECT_FORMAT_OID_LENGTHS = MappingProxyType({"sha1": 40, "sha256": 64})


def _is_canonical_local_ref(value: str, prefixes: tuple[str, ...]) -> bool:
    return (
        value.startswith(prefixes)
        and len(value.encode("utf-8")) <= 4096
        and not any(character in value for character in ("\x00", "\r", "\n", " "))
        and not any(fragment in value for fragment in ("..", "@{", "//"))
        and not value.endswith((".", "/"))
        and not any(character in value for character in "~^:?*[\\")
    )


@dataclass(frozen=True, slots=True)
class TargetGitEvidence:
    """Target-only Git identity captured after repository-boundary validation."""

    current_ref: str | None
    head_state: str
    head: str | None
    empty_tree_oid: str | None = None

    def __post_init__(self) -> None:
        if self.head_state not in HEAD_STATES:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "target HEAD state evidence is invalid")
        if self.current_ref is not None and not _is_canonical_local_ref(
            self.current_ref, ("refs/heads/",)
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "target current ref evidence is not canonical"
            )
        if self.head_state == HEAD_STATE_UNBORN:
            if (
                self.current_ref is None
                or self.head is not None
                or self.empty_tree_oid is None
                or GIT_OID_RE.fullmatch(self.empty_tree_oid) is None
            ):
                raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "target unborn evidence is invalid")
            return
        if (
            self.head is None
            or GIT_OID_RE.fullmatch(self.head) is None
            or self.empty_tree_oid is not None
            or (self.head_state == HEAD_STATE_ATTACHED and self.current_ref is None)
            or (self.head_state == HEAD_STATE_DETACHED and self.current_ref is not None)
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "target HEAD evidence is not a canonical object id"
            )


@dataclass(frozen=True, slots=True)
class BranchReviewSeal:
    base_ref: str
    base_commit: str
    target_ref: str
    target_head: str
    merge_base_commit: str

    def __post_init__(self) -> None:
        if not _is_canonical_local_ref(self.base_ref, ("refs/heads/", "refs/tags/")):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "branch-review base ref is not canonical")
        if not _is_canonical_local_ref(self.target_ref, ("refs/heads/",)):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "branch-review target ref is not canonical"
            )
        if any(
            GIT_OID_RE.fullmatch(value) is None
            for value in (self.base_commit, self.target_head, self.merge_base_commit)
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "branch-review sealed commit is not canonical"
            )


@dataclass(frozen=True, slots=True)
class RepositoryGitPaths:
    worktree_root: Path
    git_dir: Path
    git_common_dir: Path


@dataclass(frozen=True, slots=True)
class RepositoryGitIdentity:
    paths: RepositoryGitPaths
    current_ref: str | None
    head_state: str
    head: str | None
    empty_tree_oid: str | None = None


@dataclass(frozen=True, slots=True)
class ValidatedTargetRepository:
    path: Path
    name: str
    target_identity: RepositoryGitIdentity
    runner_root: Path
    runner_identity: RepositoryGitIdentity | None
    capability_fingerprint: GitCapabilityFingerprint | None
    shared_common_dir: bool
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _VALIDATED_REPOSITORY_SEAL:
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, TARGET_REPOSITORY_INVALID_ERROR)


class GitRunner:
    """Execute only runner-owned Git argv and capture bounded output."""

    _PREFIX = (
        "--no-pager",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "color.ui=false",
        "-c",
        "diff.external=",
        "-c",
        "diff.trustExitCode=false",
        "-c",
        "log.showSignature=false",
    )
    _ENVIRONMENT = MappingProxyType(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PAGER": "cat",
            "TERM": "dumb",
            "XDG_CONFIG_HOME": "/nonexistent",
        }
    )

    def __init__(
        self,
        repo_root: Path,
        executable: str = "/usr/bin/git",
        *,
        conversion_policy: GitConversionPolicy | None = None,
    ) -> None:
        self.repo_root = repo_root
        self.executable = executable
        self.conversion_overrides = conversion_policy.config_overrides if conversion_policy else ()

    def run(self, arguments: tuple[str, ...], *, maximum: int = MAX_GIT_OUTPUT_BYTES) -> GitResult:
        conversion_prefix = tuple(
            item for override in self.conversion_overrides for item in ("-c", override)
        )
        argv = [
            self.executable,
            "-C",
            os.fspath(self.repo_root),
            *self._PREFIX,
            *conversion_prefix,
            *arguments,
        ]
        process = subprocess.Popen(  # noqa: S603 - argv is fixed by the runner.
            argv,
            cwd="/",
            env=dict(self._ENVIRONMENT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        stdout = bytearray()
        stderr = bytearray()
        truncated = False
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    process.kill()
                    raise RunnerError(GIT_COMMAND_FAILED, "fixed Git command exceeded its timeout")
                for key, _events in selector.select(0.05):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = stdout if key.data == "stdout" else stderr
                    room = maximum - len(target)
                    if room <= 0:
                        truncated = True
                        process.kill()
                        continue
                    target.extend(chunk[:room])
                    if len(chunk) > room:
                        truncated = True
                        process.kill()
            returncode = process.wait(timeout=1)
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
        operation = (
            arguments[0]
            if arguments and re.fullmatch(r"[a-z][a-z-]*", arguments[0]) is not None
            else "command"
        )
        return GitResult(bytes(stdout), bytes(stderr), returncode, truncated, operation)

    def hash_blob(
        self,
        object_id: str,
        expected_size: int,
        *,
        maximum: int = MAX_GIT_OUTPUT_BYTES,
    ) -> GitBlobDigest:
        """Stream one bounded Git blob into SHA-256 without retaining its body."""
        if (
            GIT_OID_RE.fullmatch(object_id) is None
            or expected_size < 0
            or maximum < 0
            or expected_size > maximum
        ):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "Git blob digest request is invalid")
        conversion_prefix = tuple(
            item for override in self.conversion_overrides for item in ("-c", override)
        )
        argv = [
            self.executable,
            "-C",
            os.fspath(self.repo_root),
            *self._PREFIX,
            *conversion_prefix,
            "cat-file",
            "blob",
            object_id,
        ]
        process = subprocess.Popen(  # noqa: S603 - argv is fixed by the runner.
            argv,
            cwd="/",
            env=dict(self._ENVIRONMENT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        assert process.stdout is not None
        assert process.stderr is not None
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        digest = hashlib.sha256()
        prefix = bytearray()
        stderr = bytearray()
        byte_size = 0
        exceeded = False
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    process.kill()
                    raise RunnerError(GIT_COMMAND_FAILED, "fixed Git command exceeded its timeout")
                for key, _events in selector.select(0.05):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        byte_size += len(chunk)
                        if byte_size > maximum:
                            exceeded = True
                            process.kill()
                            continue
                        digest.update(chunk)
                        if len(prefix) < 16:
                            prefix.extend(chunk[: 16 - len(prefix)])
                        continue
                    room = 16 * 1024 - len(stderr)
                    if room <= 0 or len(chunk) > room:
                        process.kill()
                        raise RunnerError(
                            SNAPSHOT_COLLECTION_FAILED,
                            "Git blob digest stderr exceeded its bound",
                        )
                    stderr.extend(chunk)
            returncode = process.wait(timeout=1)
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
        if exceeded:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "Git blob digest exceeded its bound")
        if returncode != 0 or stderr or byte_size != expected_size:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "Git blob digest collection failed")
        return GitBlobDigest(byte_size, bytes(prefix), digest.hexdigest())


def _git_capability_refused() -> None:
    raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_CAPABILITY_REFUSED_ERROR)


def _git_replacement_refused() -> None:
    raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_REPLACEMENT_REFUSED_ERROR)


def _git_promisor_refused() -> None:
    raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_PROMISOR_REFUSED_ERROR)


def _git_shallow_refused() -> None:
    raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_SHALLOW_REFUSED_ERROR)


def _git_capability_state_changed() -> None:
    raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_CAPABILITY_STATE_CHANGED_ERROR)


def _directory_identity(path: Path) -> GitPathIdentity:
    try:
        metadata = path.lstat()
        if (
            not path.is_absolute()
            or ".." in path.parts
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or path.resolve(strict=True) != path
        ):
            _git_capability_state_changed()
    except (OSError, RuntimeError, ValueError) as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_CAPABILITY_STATE_CHANGED_ERROR) from exc
    return GitPathIdentity(os.fspath(path), metadata.st_dev, metadata.st_ino, metadata.st_mode)


def _path_is_within(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _resolved_git_path(git: GitRunner, relative: str) -> Path:
    result = git.run(
        ("rev-parse", "--path-format=absolute", "--git-path", relative),
        maximum=16 * 1024,
    )
    if (
        result.returncode != 0
        or result.truncated
        or result.stderr
        or not result.stdout.endswith(b"\n")
        or b"\r" in result.stdout
        or b"\0" in result.stdout
    ):
        _git_capability_state_changed()
    try:
        decoded = result.stdout.removesuffix(b"\n").decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_CAPABILITY_STATE_CHANGED_ERROR) from exc
    path = Path(decoded)
    if (
        not decoded
        or "\n" in decoded
        or not path.is_absolute()
        or ".." in path.parts
        or os.fspath(path) != os.path.abspath(path)
    ):
        _git_capability_state_changed()
    return path


def _shallow_directory_identity(path: Path) -> GitPathIdentity:
    try:
        metadata = path.lstat()
        if (
            not path.is_absolute()
            or ".." in path.parts
            or os.fspath(path) != os.path.abspath(path)
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or path.resolve(strict=True) != path
        ):
            _git_shallow_refused()
    except (OSError, RuntimeError, ValueError) as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_SHALLOW_REFUSED_ERROR) from exc
    return GitPathIdentity(os.fspath(path), metadata.st_dev, metadata.st_ino, metadata.st_mode)


def _resolved_shallow_path(git: GitRunner) -> Path:
    try:
        return _resolved_git_path(git, "shallow")
    except RunnerError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_SHALLOW_REFUSED_ERROR) from exc


def _shallow_repository_state(git: GitRunner) -> bool:
    result = git.run(("rev-parse", "--is-shallow-repository"), maximum=4096)
    if result.returncode != 0 or result.truncated or result.stderr:
        _git_shallow_refused()
    try:
        decoded = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_SHALLOW_REFUSED_ERROR) from exc
    if not decoded.endswith("\n") or decoded.removesuffix("\n") != "false":
        _git_shallow_refused()
    return False


def _absent_shallow_path_fingerprint(
    path: Path,
    roots: tuple[Path, ...],
) -> GitShallowPathFingerprint:
    if (
        not path.is_absolute()
        or ".." in path.parts
        or os.fspath(path) != os.path.abspath(path)
        or path.name != "shallow"
    ):
        _git_shallow_refused()
    parent = path.parent
    parent_identity = _shallow_directory_identity(parent)
    canonical_path = parent / "shallow"
    if canonical_path != path or not _path_is_within(canonical_path, roots):
        _git_shallow_refused()
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_SHALLOW_REFUSED_ERROR) from exc
    else:
        _git_shallow_refused()
    if _shallow_directory_identity(parent) != parent_identity:
        _git_shallow_refused()
    return GitShallowPathFingerprint(os.fspath(path), parent_identity, "absent")


def _shallow_fingerprint(
    git: GitRunner,
    git_dir: Path,
    git_common_dir: Path,
    runner_git_dir: Path,
    runner_git_common_dir: Path,
) -> GitShallowFingerprint:
    is_shallow = _shallow_repository_state(git)
    target_roots = tuple(dict.fromkeys((git_dir, git_common_dir)))
    all_roots = tuple(
        dict.fromkeys((git_dir, git_common_dir, runner_git_dir, runner_git_common_dir))
    )
    boundary_identities = tuple(
        sorted(
            (_shallow_directory_identity(path) for path in all_roots),
            key=lambda identity: identity.path,
        )
    )
    actual = _resolved_shallow_path(git)
    if not _path_is_within(actual, target_roots):
        _git_shallow_refused()
    candidates = tuple(
        sorted(
            {
                *(path / "shallow" for path in all_roots),
                actual,
            },
            key=os.fspath,
        )
    )
    candidate_fingerprints = tuple(
        _absent_shallow_path_fingerprint(path, all_roots) for path in candidates
    )
    boundary_by_path = {identity.path: identity for identity in boundary_identities}
    if any(
        fingerprint.parent.path in boundary_by_path
        and fingerprint.parent != boundary_by_path[fingerprint.parent.path]
        for fingerprint in candidate_fingerprints
    ):
        _git_shallow_refused()
    return GitShallowFingerprint(
        is_shallow,
        os.fspath(actual),
        candidate_fingerprints,
        boundary_identities,
    )


def _refuse_existing_path(path: Path, error: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, error) from exc
    raise RunnerError(GIT_PREFLIGHT_FAILED, error)


def _optional_object_directory_identity(path: Path) -> GitPathIdentity | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_CAPABILITY_STATE_CHANGED_ERROR) from exc
    return _directory_identity(path)


def _refuse_promisor_pack_markers(object_directory: Path) -> None:
    pack_directory = object_directory / "pack"
    try:
        metadata = pack_directory.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_PROMISOR_REFUSED_ERROR) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        _git_promisor_refused()
    entries = 0
    try:
        with os.scandir(pack_directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > MAX_GIT_PREFLIGHT_ENTRIES:
                    _git_promisor_refused()
                if entry.name.endswith(".promisor"):
                    _git_promisor_refused()
    except OSError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_PROMISOR_REFUSED_ERROR) from exc


def _capability_path_fingerprint(
    git: GitRunner,
    repo_root: Path,
    git_dir: Path,
    git_common_dir: Path,
    runner_git_dir: Path,
    runner_git_common_dir: Path,
) -> GitCapabilityFingerprint:
    shallow = _shallow_fingerprint(
        git,
        git_dir,
        git_common_dir,
        runner_git_dir,
        runner_git_common_dir,
    )
    roots = tuple(dict.fromkeys((git_dir, git_common_dir)))
    actual_graft = _resolved_git_path(git, "info/grafts")
    actual_objects = _resolved_git_path(git, "objects")
    if not _path_is_within(actual_graft, roots) or not _path_is_within(actual_objects, roots):
        _git_capability_state_changed()

    graft_paths = tuple(
        sorted(
            {
                os.fspath(git_dir / "info" / "grafts"),
                os.fspath(git_common_dir / "info" / "grafts"),
                os.fspath(actual_graft),
            }
        )
    )
    for raw_path in graft_paths:
        _refuse_existing_path(Path(raw_path), GIT_REPLACEMENT_REFUSED_ERROR)

    object_paths = tuple(
        sorted(
            {
                os.fspath(git_dir / "objects"),
                os.fspath(git_common_dir / "objects"),
                os.fspath(actual_objects),
            }
        )
    )
    object_identities: list[GitPathIdentity] = []
    for raw_path in object_paths:
        object_directory = Path(raw_path)
        identity = _optional_object_directory_identity(object_directory)
        if identity is None:
            continue
        object_identities.append(identity)
        for alternate_name in ("alternates", "http-alternates"):
            _refuse_existing_path(
                object_directory / "info" / alternate_name,
                GIT_ALTERNATE_OBJECTS_REFUSED_ERROR,
            )
        _refuse_promisor_pack_markers(object_directory)
    if os.fspath(actual_objects) not in {identity.path for identity in object_identities}:
        _git_capability_state_changed()

    return GitCapabilityFingerprint(
        _directory_identity(repo_root),
        next(
            identity for identity in shallow.boundary_directories if identity.path == str(git_dir)
        ),
        next(
            identity
            for identity in shallow.boundary_directories
            if identity.path == str(git_common_dir)
        ),
        graft_paths,
        object_paths,
        tuple(sorted(object_identities, key=lambda identity: identity.path)),
        shallow,
    )


def _refuse_replace_refs(git: GitRunner) -> None:
    result = git.run(
        ("for-each-ref", "--count=1", "--format=%(refname)", "refs/replace/"),
        maximum=4096,
    )
    if result.returncode != 0 or result.truncated or result.stderr or result.stdout:
        _git_replacement_refused()


def _config_names(git: GitRunner, scope: str) -> tuple[str, ...]:
    result = git.run(
        ("config", scope, "--no-includes", "--name-only", "--null", "--list"),
        maximum=64 * 1024,
    )
    if result.returncode != 0 or result.truncated or result.stderr:
        _git_capability_refused()
    try:
        names = {
            item.decode("utf-8", errors="strict") for item in result.stdout.split(b"\0") if item
        }
    except UnicodeDecodeError as exc:
        raise RunnerError(GIT_PREFLIGHT_FAILED, GIT_CAPABILITY_REFUSED_ERROR) from exc
    return tuple(sorted(names))


def _worktree_config_enabled(git: GitRunner) -> bool:
    result = git.run(
        (
            "config",
            "--local",
            "--no-includes",
            "--type=bool",
            "--null",
            "--get-all",
            "extensions.worktreeConfig",
        ),
        maximum=4096,
    )
    if result.returncode == 1 and not result.stdout and not result.stderr and not result.truncated:
        return False
    if result.returncode != 0 or result.truncated or result.stderr:
        _git_capability_refused()
    values = [value for value in result.stdout.split(b"\0") if value]
    if len(values) != 1 or values[0] not in {b"true", b"false"}:
        _git_capability_refused()
    return values[0] == b"true"


def _dangerous_config_name(name: str) -> bool:
    normalized = name.casefold()
    return normalized.startswith(("include.", "includeif.", "core.fsmonitor"))


def _promisor_config_name(name: str) -> bool:
    name = name.casefold()
    if name == "extensions.partialclone":
        return True
    parts = name.split(".")
    return (
        len(parts) >= 3
        and parts[0] == "remote"
        and bool(".".join(parts[1:-1]))
        and parts[-1] in {"promisor", "partialclonefilter"}
    )


def _conversion_policy(config_names: tuple[str, ...]) -> GitConversionPolicy:
    filter_types: dict[str, set[str]] = {}
    diff_types: dict[str, set[str]] = {}
    external_diff = False
    attributes_file_disabled = False
    for name in config_names:
        normalized = name.casefold()
        parts = name.split(".")
        normalized_parts = normalized.split(".")
        if normalized == "diff.external":
            external_diff = True
            continue
        if normalized == "core.attributesfile":
            attributes_file_disabled = True
            continue
        if len(parts) < 3 or len(parts) != len(normalized_parts):
            continue
        driver = ".".join(parts[1:-1])
        if (
            not driver
            or len(driver.encode("utf-8")) > 255
            or any(character in driver for character in ("\x00", "\r", "\n"))
        ):
            _git_capability_refused()
        section = normalized_parts[0]
        variable = normalized_parts[-1]
        if section == "filter" and variable in {"clean", "smudge", "process", "required"}:
            disabled_type = {
                "clean": "clean_filter",
                "smudge": "smudge_filter",
                "process": "process_filter",
                "required": "required_filter",
            }[variable]
            filter_types.setdefault(driver, set()).add(disabled_type)
        elif section == "diff" and variable in {"command", "textconv"}:
            disabled_type = "external_diff_driver" if variable == "command" else "textconv"
            diff_types.setdefault(driver, set()).add(disabled_type)

    overrides: list[str] = []
    for driver in sorted(filter_types):
        overrides.extend(
            (
                f"filter.{driver}.clean=",
                f"filter.{driver}.smudge=",
                f"filter.{driver}.process=",
                f"filter.{driver}.required=false",
            )
        )
    for driver in sorted(diff_types):
        overrides.extend((f"diff.{driver}.command=", f"diff.{driver}.textconv="))
    if len(overrides) > MAX_GIT_CONVERSION_OVERRIDES:
        _git_capability_refused()
    return GitConversionPolicy(
        tuple(overrides),
        tuple(
            GitConversionDriver(driver, tuple(sorted(disabled_types)))
            for driver, disabled_types in sorted(filter_types.items())
        ),
        tuple(
            GitConversionDriver(driver, tuple(sorted(disabled_types)))
            for driver, disabled_types in sorted(diff_types.items())
        ),
        external_diff,
        attributes_file_disabled,
    )


def _worktree_config_is_inert(worktree_config: Path) -> bool:
    """True only for a config.worktree that cannot carry a setting under any extension.

    Git reads this file solely when ``extensions.worktreeConfig`` is enabled, so with
    the extension off nothing in it takes effect today. That alone is not enough to
    accept: a populated file would become live the moment the extension is turned on,
    and its content is repository-controlled. An absent file, or a zero-byte ordinary
    file, carries no setting under either state, which is the only positively provable
    inert shape. Everything else - any content, a symlink, a directory, a special
    file, or a path that cannot be inspected - stays refused.

    Git itself leaves the empty form behind: enabling the extension, setting a
    ``--worktree`` key and unsetting it again truncates the file rather than removing
    it, and disabling the extension afterwards leaves the empty file in place.
    """
    try:
        stated = worktree_config.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return stat.S_ISREG(stated.st_mode) and stated.st_size == 0


def preflight_git_capabilities(
    repo_root: Path,
    git_dir: Path,
    git_common_dir: Path,
    git_executable: str = "/usr/bin/git",
    *,
    runner_git_dir: Path,
    runner_git_common_dir: Path,
    sealed_commits: tuple[str, ...] = (),
    expected_fingerprint: GitCapabilityFingerprint | None = None,
) -> GitCapabilityFingerprint:
    """Reject repository-controlled Git capabilities before collection."""

    git = GitRunner(repo_root, git_executable)
    before = _capability_path_fingerprint(
        git,
        repo_root,
        git_dir,
        git_common_dir,
        runner_git_dir,
        runner_git_common_dir,
    )
    _refuse_replace_refs(git)
    local_names = _config_names(git, "--local")
    worktree_enabled = _worktree_config_enabled(git)
    if not worktree_enabled and not _worktree_config_is_inert(git_dir / "config.worktree"):
        _git_capability_refused()
    worktree_names = _config_names(git, "--worktree") if worktree_enabled else set()
    names = tuple(sorted(set((*local_names, *worktree_names))))
    if any(_promisor_config_name(name) for name in names):
        _git_promisor_refused()
    if any(_dangerous_config_name(name) for name in names):
        _git_capability_refused()
    conversion_policy = _conversion_policy(names)
    if any(GIT_OID_RE.fullmatch(commit) is None for commit in sealed_commits):
        _git_capability_refused()
    after = _capability_path_fingerprint(
        git,
        repo_root,
        git_dir,
        git_common_dir,
        runner_git_dir,
        runner_git_common_dir,
    )
    if after.shallow != before.shallow or (
        expected_fingerprint is not None and after.shallow != expected_fingerprint.shallow
    ):
        _git_shallow_refused()
    if after != before:
        _git_capability_state_changed()
    current = replace(after, conversion_policy=conversion_policy)
    if expected_fingerprint is not None and current != expected_fingerprint:
        _git_capability_state_changed()
    return current


def _canonical_git_directory(raw: str, description: str, error: str) -> Path:
    try:
        candidate = Path(raw)
        if (
            not candidate.is_absolute()
            or ".." in candidate.parts
            or os.fspath(candidate) != os.path.abspath(candidate)
        ):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        return _canonical_owned_directory(candidate, description, error)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error) from exc


def _validate_git_paths(
    expected_worktree: Path,
    git_executable: str,
    description: str,
    error: str,
) -> RepositoryGitPaths:
    try:
        result = GitRunner(expected_worktree, git_executable).run(
            (
                "rev-parse",
                "--is-inside-work-tree",
                "--path-format=absolute",
                "--show-toplevel",
                "--absolute-git-dir",
                "--git-common-dir",
            ),
            maximum=16 * 1024,
        )
        if result.returncode != 0 or result.truncated or b"\x00" in result.stdout:
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        decoded = result.stdout.decode("utf-8", errors="strict")
        if "\r" in decoded or not decoded.endswith("\n"):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        lines = decoded.removesuffix("\n").split("\n")
        if len(lines) != 4 or lines[0] != "true":
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        worktree_root = _canonical_git_directory(lines[1], f"{description} worktree root", error)
        git_dir = _canonical_git_directory(lines[2], f"{description} git-dir", error)
        git_common_dir = _canonical_git_directory(lines[3], f"{description} git-common-dir", error)
        if worktree_root != expected_worktree:
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        return RepositoryGitPaths(worktree_root, git_dir, git_common_dir)
    except (OSError, UnicodeError, ValueError, RunnerError) as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error) from exc


def _validate_state_git_boundaries(
    state_home: Path,
    target_paths: RepositoryGitPaths,
    runner_root: Path,
    runner_paths: RepositoryGitPaths | None,
) -> None:
    protected = [
        target_paths.worktree_root,
        target_paths.git_dir,
        target_paths.git_common_dir,
        runner_root,
    ]
    if runner_paths is not None:
        protected.extend(
            (runner_paths.worktree_root, runner_paths.git_dir, runner_paths.git_common_dir)
        )
    if any(_paths_overlap(state_home, path) for path in protected):
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, STATE_GIT_BOUNDARY_ERROR)


def _validated_current_ref(git: GitRunner, error: str) -> str | None:
    result = git.run(("symbolic-ref", "--quiet", "HEAD"), maximum=4096)
    if result.truncated:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    if result.returncode == 1 and not result.stdout:
        return None
    if result.returncode != 0:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    try:
        value = result.stdout.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error) from exc
    if not value.endswith("\n") or "\r" in value:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    current_ref = value.removesuffix("\n")
    if "\n" in current_ref:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    return current_ref


def _resolved_commit(git: GitRunner, specification: str, error: str) -> str | None:
    result = git.run(("rev-parse", "--verify", f"{specification}^{{commit}}"), maximum=4096)
    if result.truncated or (result.returncode != 0 and result.stdout):
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    if result.returncode != 0:
        return None
    if not result.stdout.endswith(b"\n") or b"\r" in result.stdout:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    commit = result.stdout.removesuffix(b"\n").decode("ascii", errors="strict")
    if "\n" in commit or GIT_OID_RE.fullmatch(commit) is None:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    return commit


def _local_ref_exists(git: GitRunner, reference: str, error: str) -> bool:
    result = git.run(("show-ref", "--verify", "--quiet", reference), maximum=4096)
    if result.truncated or result.stdout:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)


def _empty_tree_oid(git: GitRunner, error: str) -> str:
    format_result = git.run(("rev-parse", "--show-object-format=storage"), maximum=128)
    if (
        format_result.returncode != 0
        or format_result.truncated
        or not format_result.stdout.endswith(b"\n")
        or b"\r" in format_result.stdout
    ):
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    object_format = format_result.stdout.removesuffix(b"\n").decode("ascii", errors="strict")
    oid_length = OBJECT_FORMAT_OID_LENGTHS.get(object_format)
    if oid_length is None or "\n" in object_format:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)

    oid_result = git.run(("hash-object", "-t", "tree", "--stdin", "--no-filters"), maximum=128)
    if (
        oid_result.returncode != 0
        or oid_result.truncated
        or not oid_result.stdout.endswith(b"\n")
        or b"\r" in oid_result.stdout
    ):
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    oid = oid_result.stdout.removesuffix(b"\n").decode("ascii", errors="strict")
    if "\n" in oid or re.fullmatch(rf"[0-9a-f]{{{oid_length}}}", oid) is None:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
    return oid


def _validate_git_identity(
    paths: RepositoryGitPaths,
    git_executable: str,
    error: str,
    *,
    allow_unborn: bool = False,
) -> RepositoryGitIdentity:
    try:
        git = GitRunner(paths.worktree_root, git_executable)
        current_ref = _validated_current_ref(git, error)
        head = _resolved_commit(git, "HEAD", error)
        if head is not None:
            if current_ref is not None and _resolved_commit(git, current_ref, error) != head:
                raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
            if (
                _validated_current_ref(git, error) != current_ref
                or _resolved_commit(git, "HEAD", error) != head
            ):
                raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
            head_state = HEAD_STATE_ATTACHED if current_ref is not None else HEAD_STATE_DETACHED
            evidence = TargetGitEvidence(current_ref, head_state, head)
            return RepositoryGitIdentity(
                paths,
                evidence.current_ref,
                evidence.head_state,
                evidence.head,
            )

        if (
            not allow_unborn
            or current_ref is None
            or not _is_canonical_local_ref(current_ref, ("refs/heads/",))
            or _local_ref_exists(git, current_ref, error)
        ):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        empty_tree_oid = _empty_tree_oid(git, error)
        if (
            _validated_current_ref(git, error) != current_ref
            or _resolved_commit(git, "HEAD", error) is not None
            or _local_ref_exists(git, current_ref, error)
        ):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        evidence = TargetGitEvidence(
            current_ref,
            HEAD_STATE_UNBORN,
            None,
            empty_tree_oid,
        )
        return RepositoryGitIdentity(
            paths,
            evidence.current_ref,
            evidence.head_state,
            evidence.head,
            evidence.empty_tree_oid,
        )
    except (OSError, UnicodeError, ValueError, RunnerError) as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error) from exc


def _validate_target_repository_context(
    target_path: Path,
    target_name: str,
    runner_path: Path,
    state_home: Path,
    git_executable: str,
    task: str,
    *,
    allow_installed_runner: bool = False,
) -> ValidatedTargetRepository:
    target_paths = _validate_git_paths(
        target_path,
        git_executable,
        "target repository",
        TARGET_REPOSITORY_INVALID_ERROR,
    )
    if allow_installed_runner:
        runner_root = _canonical_owned_directory(
            runner_path,
            "Runner installation",
            RUNNER_REPOSITORY_INVALID_ERROR,
        )
        if _paths_overlap(target_path, runner_root):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, RUNNER_REPOSITORY_INVALID_ERROR)
        runner_paths = None
    else:
        runner_paths = _validate_git_paths(
            runner_path,
            git_executable,
            "Runner repository",
            RUNNER_REPOSITORY_INVALID_ERROR,
        )
        runner_root = runner_paths.worktree_root
    _validate_state_git_boundaries(state_home, target_paths, runner_root, runner_paths)
    capability_fingerprint = None
    if task != "test-triage":
        capability_fingerprint = preflight_git_capabilities(
            target_path,
            target_paths.git_dir,
            target_paths.git_common_dir,
            git_executable,
            runner_git_dir=(runner_paths.git_dir if runner_paths else target_paths.git_dir),
            runner_git_common_dir=(
                runner_paths.git_common_dir if runner_paths else target_paths.git_common_dir
            ),
        )
    target_identity = _validate_git_identity(
        target_paths,
        git_executable,
        TARGET_REPOSITORY_INVALID_ERROR,
        allow_unborn=True,
    )
    runner_identity = (
        _validate_git_identity(
            runner_paths,
            git_executable,
            RUNNER_REPOSITORY_INVALID_ERROR,
        )
        if runner_paths is not None
        else None
    )
    return ValidatedTargetRepository(
        path=target_path,
        name=target_name,
        target_identity=target_identity,
        runner_root=runner_root,
        runner_identity=runner_identity,
        capability_fingerprint=capability_fingerprint,
        shared_common_dir=(
            runner_paths is not None and target_paths.git_common_dir == runner_paths.git_common_dir
        ),
        _seal=_VALIDATED_REPOSITORY_SEAL,
    )


def _revalidate_branch_review_seal(
    target: ValidatedTargetRepository,
    seal: BranchReviewSeal,
    git_executable: str,
) -> None:
    try:
        target_paths = _validate_git_paths(
            target.path,
            git_executable,
            "target repository",
            BRANCH_REVIEW_STATE_CHANGED_ERROR,
        )
        if target.runner_identity is None:
            runner_root = _canonical_owned_directory(
                target.runner_root,
                "Runner installation",
                BRANCH_REVIEW_STATE_CHANGED_ERROR,
            )
            runner_paths = None
            if runner_root != target.runner_root or _paths_overlap(target.path, runner_root):
                raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR)
        else:
            runner_paths = _validate_git_paths(
                target.runner_identity.paths.worktree_root,
                git_executable,
                "Runner repository",
                BRANCH_REVIEW_STATE_CHANGED_ERROR,
            )
        if target_paths != target.target_identity.paths or (
            target.runner_identity is not None and runner_paths != target.runner_identity.paths
        ):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR)
        target_identity = _validate_git_identity(
            target_paths,
            git_executable,
            BRANCH_REVIEW_STATE_CHANGED_ERROR,
        )
        runner_identity = (
            _validate_git_identity(
                runner_paths,
                git_executable,
                BRANCH_REVIEW_STATE_CHANGED_ERROR,
            )
            if runner_paths is not None
            else None
        )
        if (
            target_identity.current_ref != seal.target_ref
            or target_identity.head != seal.target_head
            or runner_identity != target.runner_identity
        ):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR)

        git = GitRunner(target.path, git_executable)
        base_result = git.run(
            ("rev-parse", "--verify", f"{seal.base_ref}^{{commit}}"), maximum=4096
        )
        if (
            base_result.returncode != 0
            or base_result.truncated
            or base_result.stdout != f"{seal.base_commit}\n".encode("ascii")
        ):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR)
        merge_result = git.run(
            ("merge-base", "--all", seal.base_commit, seal.target_head), maximum=4096
        )
        if (
            merge_result.returncode != 0
            or merge_result.truncated
            or merge_result.stdout != f"{seal.merge_base_commit}\n".encode("ascii")
        ):
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR)
    except (OSError, UnicodeError, ValueError, RunnerError) as exc:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR) from exc


def _find_executable(name: str) -> str:
    path = TRUSTED_EXECUTABLES.get(name)
    if path is None:
        raise RunnerError(
            REPOSITORY_VALIDATION_FAILED, f"required executable is unavailable: {name}"
        )
    try:
        path_stat = path.stat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(
            REPOSITORY_VALIDATION_FAILED, f"unable to inspect executable: {name}"
        ) from exc
    if not stat.S_ISREG(path_stat.st_mode) or not os.access(path, os.X_OK):
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, f"invalid executable: {name}")
    if any(
        os.access(candidate, os.W_OK)
        for candidate in (path, path.parent, resolved, resolved.parent)
    ):
        raise RunnerError(
            REPOSITORY_VALIDATION_FAILED,
            f"trusted executable path is writable by the runner user: {name}",
        )
    return os.fspath(resolved)
