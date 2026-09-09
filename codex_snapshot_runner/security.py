"""Deterministic secret and path handling for repository snapshot artifacts."""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath


class SecurityError(RuntimeError):
    """Raised when unsafe text cannot be bounded or redacted reliably."""


class RunnerError(RuntimeError):
    """A coded Runner failure with a short message safe for public output."""

    def __init__(self, code: str, message: str) -> None:
        if (
            re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", code) is None
            or not message
            or len(message.encode("utf-8")) > 512
            or "\n" in message
            or "\r" in message
        ):
            raise ValueError("invalid public Runner error")
        self.code = code
        self.message = message
        super().__init__(message)


REPOSITORY_VALIDATION_FAILED = "REPOSITORY_VALIDATION_FAILED"
ARTIFACT_VALIDATION_FAILED = "ARTIFACT_VALIDATION_FAILED"
ARTIFACT_PUBLISH_FAILED = "ARTIFACT_PUBLISH_FAILED"
GIT_PREFLIGHT_FAILED = "GIT_PREFLIGHT_FAILED"
SNAPSHOT_COLLECTION_FAILED = "SNAPSHOT_COLLECTION_FAILED"
GIT_COMMAND_FAILED = "GIT_COMMAND_FAILED"

MAX_SANITIZE_DEPTH = 32
MAX_SANITIZE_ELEMENTS = 10_000
MAX_DIFF_PATH_CANDIDATES = 128
MAX_EXTENSIONLESS_TEXT_BYTES = 64 * 1024
SCAN_CLASSIFIER_VERSION = 2
YAML_CONTENT_REFUSED = "yaml_content_refused"

PEM_PRIVATE_KEY_BOUNDARY_RE = re.compile(
    r"-{5}(?P<kind>BEGIN|END)[ \t]+"
    r"(?P<label>PRIVATE[ \t]+KEY|ENCRYPTED[ \t]+PRIVATE[ \t]+KEY|"
    r"RSA[ \t]+PRIVATE[ \t]+KEY|DSA[ \t]+PRIVATE[ \t]+KEY|"
    r"EC[ \t]+PRIVATE[ \t]+KEY|OPENSSH[ \t]+PRIVATE[ \t]+KEY)[ \t]*-{5}",
    re.IGNORECASE,
)
FILE_URI_RE = re.compile(r"(?i)\bfile://(?:localhost)?/[^\s\x00\"'<>]+")
AUTH_HEADER_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:proxy-)?authorization\s*[:=]\s*)(?P<value>[^\r\n]*)"
)
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
ABSOLUTE_PATH_RE = re.compile(r"(?<![\w+.:/~-])/(?!/)(?:[^\s\x00\"'<>|]+/)*[^\s\x00\"'<>|,;:)]*")

KNOWN_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OPENAI_TOKEN", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b")),
)

SENSITIVE_FILE_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx"})
SENSITIVE_EXACT_FILE_NAMES = frozenset(
    {
        ".env",
        ".netrc",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "secrets",
    }
)
ALLOWED_TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".md",
        ".rst",
        ".txt",
        ".toml",
        ".json",
        ".jsonl",
        ".sh",
        ".bash",
        ".sql",
        ".ini",
        ".cfg",
        ".conf",
        ".xml",
        ".html",
        ".css",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".lock",
        ".mako",
    }
)
ALLOWED_EXTENSIONLESS_NAMES = frozenset(
    {
        "justfile",
        "makefile",
        "dockerfile",
        ".gitignore",
        ".python-version",
        ".editorconfig",
        ".gitkeep",
    }
)
YAML_TEXT_SUFFIXES = frozenset({".yaml", ".yml"})
RASTER_IMAGE_MEDIA_TYPES = {
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
}
RASTER_IMAGE_EVIDENCE_RE = re.compile(
    r"binary image evidence\n"
    r"media_type: (?P<media_type>image/(?:jpeg|png|webp))\n"
    r"byte_size: (?P<byte_size>0|[1-9][0-9]*)\n"
    r"sha256: (?P<sha256>[0-9a-f]{64})\n"
)
REPOSITORY_NAME_RE = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]{0,127}")
_RUNNER_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class SanitizedText:
    text: str
    redactions: dict[str, int]


class ScanMode(Enum):
    PLAIN_TEXT = "plain_text"
    UNIFIED_DIFF = "unified_diff"


@dataclass(frozen=True, slots=True)
class ScanModeBinding:
    path: tuple[str | int, ...]
    mode: ScanMode


@dataclass(frozen=True, slots=True)
class ScanModeManifest:
    classifier_version: int
    bindings: tuple[ScanModeBinding, ...]

    def __post_init__(self) -> None:
        if self.classifier_version != SCAN_CLASSIFIER_VERSION:
            raise SecurityError("scan mode classifier version is invalid")
        seen: set[tuple[str | int, ...]] = set()
        for binding in self.bindings:
            if not isinstance(binding, ScanModeBinding) or not isinstance(binding.mode, ScanMode):
                raise SecurityError("scan mode manifest contains an invalid binding")
            if binding.path in seen:
                raise SecurityError("scan mode manifest contains duplicate paths")
            seen.add(binding.path)

    def mode_for(self, path: tuple[str | int, ...]) -> ScanMode:
        for binding in self.bindings:
            if binding.path == path:
                return binding.mode
        raise SecurityError("scan mode manifest is missing a text path")


def paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def validate_no_symlink_ancestors(path: Path, description: str) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RunnerError(
                REPOSITORY_VALIDATION_FAILED, f"unable to inspect {description} ancestors"
            ) from exc
        if stat.S_ISLNK(current_stat.st_mode):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, f"{description} has a symlink ancestor")
        if not stat.S_ISDIR(current_stat.st_mode):
            raise RunnerError(
                REPOSITORY_VALIDATION_FAILED,
                f"{description} has a non-directory path component",
            )


def is_safe_repository_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and value not in {".", ".."}
        and REPOSITORY_NAME_RE.fullmatch(value) is not None
    )


def canonical_owned_directory(path: Path, description: str, error: str) -> Path:
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        validate_no_symlink_ancestors(path, description)
        candidate_stat = path.lstat()
        if stat.S_ISLNK(candidate_stat.st_mode) or not stat.S_ISDIR(candidate_stat.st_mode):
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        if candidate_stat.st_uid != os.getuid():
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        canonical = path.resolve(strict=True)
        if canonical != path:
            raise RunnerError(REPOSITORY_VALIDATION_FAILED, error)
        return canonical
    except (OSError, RuntimeError, ValueError) as exc:
        raise RunnerError(REPOSITORY_VALIDATION_FAILED, error) from exc


def _normalize_pem_label(raw: str) -> str:
    return " ".join(raw.upper().split())


def _contains_complete_private_key_block(text: str) -> bool:
    open_boundaries: dict[str, int] = {}
    for boundary in PEM_PRIVATE_KEY_BOUNDARY_RE.finditer(text):
        label = _normalize_pem_label(boundary.group("label"))
        if boundary.group("kind").upper() == "BEGIN":
            open_boundaries[label] = boundary.end()
            continue
        start = open_boundaries.pop(label, None)
        if start is None:
            continue
        body = text[start : boundary.start()]
        if ("\n" in body or "\r" in body) and any(line.strip() for line in body.splitlines()):
            return True
    return False


def _reject_complete_private_key_block(text: str) -> None:
    if _contains_complete_private_key_block(text):
        raise SecurityError("PEM credential boundary cannot be proven")


def _normalize_leading_bom(text: str) -> str:
    normalized = text[1:] if text.startswith("\ufeff") else text
    if "\ufeff" in normalized:
        raise SecurityError("UTF-8 BOM is allowed only once at the beginning")
    return normalized


def _is_redacted_value(raw: str) -> bool:
    value = raw.strip().strip("\"'")
    return re.fullmatch(r"\[REDACTED(?:_[A-Z0-9_]+)?\]", value) is not None


def _assert_no_residual_credentials(text: str) -> None:
    for match in AUTH_HEADER_RE.finditer(text):
        if not _is_redacted_value(match.group("value")):
            raise SecurityError("text contains a residual authorization credential")
    if BEARER_RE.search(text):
        raise SecurityError("text contains a residual bearer credential")
    for _category, pattern in KNOWN_TOKEN_PATTERNS:
        if pattern.search(text):
            raise SecurityError("text contains a residual credential pattern")


def _redact_credentials(text: str, counts: Counter[str]) -> str:
    _reject_complete_private_key_block(text)
    redacted = text

    def authorization(match: re.Match[str]) -> str:
        if _is_redacted_value(match.group("value")):
            return match.group(0)
        counts["AUTH"] += 1
        return f"{match.group('prefix')}[REDACTED_AUTH]"

    redacted = AUTH_HEADER_RE.sub(authorization, redacted)
    redacted, replacements = BEARER_RE.subn("Bearer [REDACTED_BEARER]", redacted)
    counts["BEARER"] += replacements
    for category, pattern in KNOWN_TOKEN_PATTERNS:
        redacted, replacements = pattern.subn(f"[REDACTED_{category}]", redacted)
        counts[category] += replacements
    _assert_no_residual_credentials(redacted)
    return redacted


def _component_suffix(component: str) -> str:
    """Return ``PurePosixPath(component).suffix`` without building a path object.

    This is a hot path: diff header classification calls it once per path component
    per candidate, so constructing a ``PurePosixPath`` here dominated large-path runs.
    """
    name = "" if component == "." else component
    index = name.rfind(".")
    if 0 < index < len(name) - 1:
        return name[index:]
    return ""


def _is_sensitive_path_component(component: str) -> bool:
    lowered = component.lower()
    return (
        lowered in SENSITIVE_EXACT_FILE_NAMES
        or lowered.startswith(".env.")
        or _component_suffix(lowered) in SENSITIVE_FILE_SUFFIXES
    )


def _safe_basename(raw_path: str) -> str:
    basename = PurePosixPath(raw_path.rstrip("/")).name
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", basename)[:64]
    if not safe or _is_sensitive_path_component(safe):
        return "path"
    return safe


def _redact_absolute_paths(
    text: str,
    counts: Counter[str],
    *,
    repository_root: Path | None,
    explicit_paths: tuple[Path, ...],
) -> str:
    redacted, file_uri_count = FILE_URI_RE.subn("[REDACTED_FILE_URI]", text)
    counts["FILE_URI"] += file_uri_count
    replacements: list[tuple[str, str]] = []
    if repository_root is not None:
        repository = os.fspath(repository_root)
        replacements.append((repository + os.sep, ""))
        replacements.append((repository, "."))
    for path in explicit_paths:
        replacements.append((os.fspath(path), _safe_basename(os.fspath(path))))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    for original, replacement in replacements:
        if original and original in redacted:
            occurrences = redacted.count(original)
            redacted = redacted.replace(original, replacement)
            counts["ABSOLUTE_PATH"] += occurrences

    def generic_path(match: re.Match[str]) -> str:
        raw = match.group(0)
        if raw in {"/", "//"}:
            return raw
        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
        counts["ABSOLUTE_PATH"] += 1
        return f"<ABS_PATH:{_safe_basename(raw)}:{digest}>"

    if "/" not in redacted:
        return redacted
    return ABSOLUTE_PATH_RE.sub(generic_path, redacted)


def is_yaml_content_path(relative_path: str) -> bool:
    """Return whether a repository path has an unsupported YAML suffix."""
    return isinstance(relative_path, str) and (
        PurePosixPath(relative_path).suffix.lower() in YAML_TEXT_SUFFIXES
    )


def classify_scan_mode(relative_path: str) -> ScanMode:
    if not isinstance(relative_path, str) or not relative_path:
        raise SecurityError("scan mode path is missing")
    if is_yaml_content_path(relative_path):
        raise SecurityError(YAML_CONTENT_REFUSED)
    if any(character in relative_path for character in ("\x00", "\r", "\n", "\ufeff")):
        raise SecurityError("scan mode path contains an unsupported character")
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != relative_path:
        raise SecurityError("scan mode path is not a canonical relative path")
    if not is_relevant_text_path(relative_path):
        raise SecurityError("scan mode path is not an approved text path")
    return ScanMode.PLAIN_TEXT


def _is_explicit_bounded_diff_text_path(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    return path.name == ".gitattributes" or path.suffix.lower() == ".csv"


def _validate_bounded_diff_text(
    relative_path: str,
    repository_root: Path | None,
) -> None:
    path = PurePosixPath(relative_path)
    is_csv = path.suffix.lower() == ".csv"
    is_gitattributes = path.name == ".gitattributes"
    if not path.parts or not (is_csv or is_gitattributes):
        raise SecurityError("scan mode path is not an approved text path")
    if is_csv:
        if any(_is_sensitive_path_component(part) for part in path.parts):
            raise SecurityError("scan mode path is not an approved text path")
    elif is_sensitive_repository_path(relative_path):
        raise SecurityError("scan mode path is not an approved text path")
    if repository_root == _RUNNER_REPOSITORY_ROOT:
        return
    if repository_root is None:
        raise SecurityError("scan mode path is not an approved text path")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_descriptor = os.open(repository_root, directory_flags)
    except OSError as exc:
        raise SecurityError("extensionless text repository root is unavailable") from exc
    descriptor: int | None = None
    try:
        for component in path.parts[:-1]:
            try:
                component_stat = os.stat(
                    component,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if stat.S_ISLNK(component_stat.st_mode):
                    raise SecurityError("extensionless text has a symlink path component")
                if not stat.S_ISDIR(component_stat.st_mode):
                    raise SecurityError("extensionless text has a non-directory path component")
                next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            except OSError as exc:
                raise SecurityError("extensionless text directory open failed") from exc
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        try:
            candidate = os.stat(
                path.parts[-1],
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if stat.S_ISLNK(candidate.st_mode):
                raise SecurityError("extensionless text symlink refused")
            if not stat.S_ISREG(candidate.st_mode):
                raise SecurityError("extensionless text non-regular file refused")
            if candidate.st_size > MAX_EXTENSIONLESS_TEXT_BYTES:
                raise SecurityError("extensionless text exceeds the file size limit")
            file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path.parts[-1], file_flags, dir_fd=directory_descriptor)
            opened = os.fstat(descriptor)
        except OSError as exc:
            raise SecurityError("extensionless text file open failed") from exc
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            candidate.st_dev,
            candidate.st_ino,
        ):
            raise SecurityError("extensionless text changed during safe open")
        chunks: list[bytes] = []
        remaining = MAX_EXTENSIONLESS_TEXT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        raw = b"".join(chunks)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) or len(raw) != opened.st_size:
            raise SecurityError("extensionless text changed while reading")
        if b"\0" in raw:
            raise SecurityError("extensionless text binary content refused")
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SecurityError("extensionless text is not valid UTF-8") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_descriptor)


def _classify_diff_scan_mode(
    relative_path: str,
    repository_root: Path | None,
) -> ScanMode:
    requires_validation = _is_explicit_bounded_diff_text_path(relative_path)
    try:
        mode = classify_scan_mode(relative_path)
    except SecurityError as exc:
        if str(exc) != "scan mode path is not an approved text path":
            raise
        if is_extensionless_text_candidate(relative_path):
            return ScanMode.PLAIN_TEXT
        mode = ScanMode.PLAIN_TEXT
        requires_validation = True
    if mode is ScanMode.PLAIN_TEXT and requires_validation:
        _validate_bounded_diff_text(relative_path, repository_root)
    return mode


def _diff_line_text(line: str) -> str:
    if line.endswith("\n"):
        line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
    return line


_GIT_PATH_ESCAPES = {
    "a": 0x07,
    "b": 0x08,
    "t": 0x09,
    "n": 0x0A,
    "v": 0x0B,
    "f": 0x0C,
    "r": 0x0D,
    '"': 0x22,
    "\\": 0x5C,
}


def _split_quoted_git_path_atom(raw: str) -> tuple[str, str]:
    if not raw.startswith('"'):
        raise SecurityError("Git path atom is not quoted")
    index = 1
    while index < len(raw):
        character = raw[index]
        if character == "\\":
            if index + 1 >= len(raw):
                raise SecurityError("Git path atom has an incomplete escape")
            index += 2
            continue
        if character == '"':
            return raw[: index + 1], raw[index + 1 :]
        if character in "\x00\r\n":
            raise SecurityError("Git path atom contains an unescaped control character")
        index += 1
    raise SecurityError("Git path atom has an unterminated quote")


def _decode_git_path_atom(raw: str) -> str:
    if not raw:
        raise SecurityError("Git path atom is empty")
    if not raw.startswith('"'):
        if any(character in raw for character in ('"', "\\", "\x00", "\r", "\n", "\t")):
            raise SecurityError("Git path atom contains an invalid unquoted character")
        encoded = raw.encode("utf-8", errors="strict")
    else:
        quoted, remainder = _split_quoted_git_path_atom(raw)
        if remainder:
            raise SecurityError("Git path atom has trailing data")
        encoded_bytes = bytearray()
        payload = quoted[1:-1]
        index = 0
        while index < len(payload):
            character = payload[index]
            if character != "\\":
                if character == '"' or character in "\x00\r\n":
                    raise SecurityError("Git path atom contains an invalid quoted character")
                encoded_bytes.extend(character.encode("utf-8", errors="strict"))
                index += 1
                continue
            index += 1
            if index >= len(payload):
                raise SecurityError("Git path atom has an incomplete escape")
            escaped = payload[index]
            if escaped in _GIT_PATH_ESCAPES:
                encoded_bytes.append(_GIT_PATH_ESCAPES[escaped])
                index += 1
                continue
            if escaped not in "01234567":
                raise SecurityError("Git path atom has an invalid escape")
            digits = escaped
            index += 1
            while index < len(payload) and len(digits) < 3 and payload[index] in "01234567":
                digits += payload[index]
                index += 1
            value = int(digits, 8)
            if value > 0xFF:
                raise SecurityError("Git path atom has an invalid octal escape")
            encoded_bytes.append(value)
        encoded = bytes(encoded_bytes)
    if b"\x00" in encoded:
        raise SecurityError("Git path atom contains a forbidden NUL")
    try:
        return encoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SecurityError("Git path atom is not valid UTF-8") from exc


def _parse_single_git_path_atom(raw: str, *, allow_trailing_tab: bool) -> str:
    if raw.startswith('"'):
        atom, remainder = _split_quoted_git_path_atom(raw)
    elif "\t" in raw:
        atom, suffix = raw.split("\t", 1)
        remainder = "\t" + suffix
    else:
        atom, remainder = raw, ""
    allowed_remainders = {"", "\t"} if allow_trailing_tab else {""}
    if remainder not in allowed_remainders:
        raise SecurityError("Git path atom has unsupported trailing data")
    return _decode_git_path_atom(atom)


def _diff_prefixed_path(
    raw: str,
    prefix: str,
    repository_root: Path | None,
) -> str:
    if not raw.startswith(prefix) or len(raw) == len(prefix):
        raise SecurityError("unified diff path prefix is invalid")
    relative = raw[len(prefix) :]
    _classify_diff_scan_mode(relative, repository_root)
    return relative


def _diff_git_path_candidates(
    raw: str,
    repository_root: Path | None,
) -> tuple[tuple[str, str], ...]:
    raw_pairs: list[tuple[str, str]] = []
    if raw.startswith('"'):
        first, remainder = _split_quoted_git_path_atom(raw)
        if not remainder.startswith(" ") or len(remainder) == 1:
            raise SecurityError("unified diff file boundary paths are invalid")
        raw_pairs.append((first, remainder[1:]))
    else:
        for marker in (" b/", ' "b/'):
            start = 0
            while True:
                boundary = raw.find(marker, start)
                if boundary < 0:
                    break
                if len(raw_pairs) >= MAX_DIFF_PATH_CANDIDATES:
                    raise SecurityError("unified diff file boundary has too many candidate paths")
                raw_pairs.append((raw[:boundary], raw[boundary + 1 :]))
                start = boundary + 1
    candidates: list[tuple[str, str]] = []
    errors: list[SecurityError] = []
    for old_raw, new_raw in raw_pairs:
        try:
            old_atom = _decode_git_path_atom(old_raw)
            new_atom = _decode_git_path_atom(new_raw)
            candidate = (
                _diff_prefixed_path(old_atom, "a/", repository_root),
                _diff_prefixed_path(new_atom, "b/", repository_root),
            )
        except SecurityError as exc:
            errors.append(exc)
            continue
        if candidate not in candidates:
            candidates.append(candidate)
    if not candidates:
        if len(raw_pairs) == 1 and errors:
            raise errors[0]
        for error in errors:
            if str(error) == YAML_CONTENT_REFUSED:
                raise error
        raise SecurityError("unified diff file boundary paths are invalid")
    return tuple(candidates)


def _diff_side_path(
    raw: str,
    prefix: str,
    repository_root: Path | None,
) -> str | None:
    decoded = _parse_single_git_path_atom(raw, allow_trailing_tab=True)
    if decoded == "/dev/null":
        return None
    return _diff_prefixed_path(decoded, prefix, repository_root)


def _diff_metadata_path(raw: str, repository_root: Path | None) -> str:
    relative = _parse_single_git_path_atom(raw, allow_trailing_tab=False)
    _classify_diff_scan_mode(relative, repository_root)
    return relative


def _diff_mode(
    old_path: str | None,
    new_path: str | None,
    repository_root: Path | None,
) -> ScanMode:
    if old_path is None and new_path is None:
        raise SecurityError("unified diff has no file path")
    old_mode = _classify_diff_scan_mode(old_path, repository_root) if old_path is not None else None
    new_mode = _classify_diff_scan_mode(new_path, repository_root) if new_path is not None else None
    if old_mode is not None and new_mode is not None and old_mode is not new_mode:
        raise SecurityError("unified diff old and new path modes conflict")
    return old_mode or new_mode  # type: ignore[return-value]


def _select_diff_header_paths(
    candidates: tuple[tuple[str, str], ...],
    expected: tuple[str, str] | None,
) -> tuple[str, str]:
    matches = (
        [candidate for candidate in candidates if candidate == expected]
        if expected is not None
        else [candidate for candidate in candidates if candidate[0] == candidate[1]]
    )
    if len(matches) != 1:
        raise SecurityError("unified diff file boundary paths are ambiguous or inconsistent")
    return matches[0]


def _resolve_diff_section_paths(
    candidates: tuple[tuple[str, str], ...],
    *,
    saw_old_header: bool,
    old_side: str | None,
    saw_new_header: bool,
    new_side: str | None,
    metadata_pair: tuple[str, str] | None,
    new_file: bool,
    deleted_file: bool,
) -> tuple[tuple[str, str], tuple[str | None, str | None]]:
    if saw_old_header is not saw_new_header:
        raise SecurityError("unified diff has incomplete file side headers")
    if new_file and deleted_file:
        raise SecurityError("unified diff has conflicting add/delete metadata")
    change: tuple[str | None, str | None] | None = None
    if saw_old_header and saw_new_header:
        if old_side is None and new_side is None:
            raise SecurityError("unified diff has no file path")
        change = (old_side, new_side)
    if metadata_pair is not None:
        if change is not None and change != metadata_pair:
            raise SecurityError("unified diff metadata paths conflict with file side headers")
        change = metadata_pair
    expected: tuple[str, str] | None = None
    if change is not None:
        old_path, new_path = change
        surviving = old_path or new_path
        if surviving is None:
            raise SecurityError("unified diff has no file path")
        expected = (old_path or surviving, new_path or surviving)
    selected = _select_diff_header_paths(candidates, expected)
    if change is None:
        if new_file:
            change = (None, selected[1])
        elif deleted_file:
            change = (selected[0], None)
        else:
            change = selected
    old_path, new_path = change
    if old_path is None:
        if not new_file or deleted_file or new_path is None or selected[0] != selected[1]:
            raise SecurityError("unified diff has invalid added-file path metadata")
    elif new_file:
        raise SecurityError("unified diff misuses added-file metadata")
    if new_path is None:
        if not deleted_file or new_file or selected[0] != selected[1]:
            raise SecurityError("unified diff has invalid deleted-file path metadata")
    elif deleted_file:
        raise SecurityError("unified diff misuses deleted-file metadata")
    return selected, change


def _parse_diff_range(raw: str, prefix: str) -> int:
    if not raw.startswith(prefix):
        raise SecurityError("unified diff hunk range is invalid")
    value = raw[1:]
    if "," in value:
        start, count = value.split(",", 1)
    else:
        start, count = value, "1"
    if not start.isdigit() or not count.isdigit():
        raise SecurityError("unified diff hunk range is invalid")
    if int(start) < 0 or int(count) < 0:
        raise SecurityError("unified diff hunk range is invalid")
    return int(count)


def _parse_diff_hunk_header(line: str) -> tuple[int, int]:
    raw = _diff_line_text(line)
    if not raw.startswith("@@ "):
        raise SecurityError("unified diff hunk header is invalid")
    closing = raw.find(" @@", 3)
    if closing < 0:
        raise SecurityError("unified diff hunk header is incomplete")
    fields = raw[3:closing].split()
    if len(fields) != 2:
        raise SecurityError("unified diff hunk header ranges are invalid")
    return _parse_diff_range(fields[0], "-"), _parse_diff_range(fields[1], "+")


def _sanitize_diff_payload(
    payload: str,
    mode: ScanMode,
    counts: Counter[str],
    *,
    repository_root: Path | None,
    explicit_paths: tuple[Path, ...],
) -> list[str]:
    if not payload:
        return []
    sanitized = sanitize_text(
        payload,
        scan_mode=mode,
        repository_root=repository_root,
        explicit_paths=explicit_paths,
    )
    for category, count in sanitized.redactions.items():
        counts[category] += count
    return sanitized.text.splitlines(keepends=True)


def _validate_diff_control_line(line: str) -> None:
    counts: Counter[str] = Counter()
    sanitized = _redact_credentials(line, counts)
    if sanitized != line or any(counts.values()):
        raise SecurityError("unified diff control line contains credential material")


def _process_unified_diff(
    text: str,
    *,
    repository_root: Path | None,
    explicit_paths: tuple[Path, ...],
    sanitize_payload: bool,
) -> tuple[SanitizedText, tuple[tuple[str | None, str | None], ...]]:
    if "\x00" in text:
        raise SecurityError("unified diff contains a forbidden NUL")
    if not text:
        return SanitizedText("", {}), ()
    lines = text.splitlines(keepends=True)
    output = list(lines)
    counts: Counter[str] = Counter()
    changes: list[tuple[str | None, str | None]] = []
    index = 0
    while index < len(lines):
        header = _diff_line_text(lines[index])
        _validate_diff_control_line(header)
        if not header.startswith("diff --git "):
            raise SecurityError("unified diff file boundary is invalid")
        candidates = _diff_git_path_candidates(
            header[len("diff --git ") :],
            repository_root,
        )
        index += 1
        saw_old_header = False
        old_side: str | None = None
        saw_new_header = False
        new_side: str | None = None
        saw_binary = False
        new_file = False
        deleted_file = False
        metadata_kind: str | None = None
        metadata_old: str | None = None
        metadata_new: str | None = None
        while index < len(lines) and not _diff_line_text(lines[index]).startswith("diff --git "):
            line = _diff_line_text(lines[index])
            if line.startswith("--- "):
                _validate_diff_control_line(line)
                if saw_old_header:
                    raise SecurityError("unified diff repeats its old file side header")
                old_side = _diff_side_path(line[4:], "a/", repository_root)
                saw_old_header = True
                index += 1
                continue
            if line.startswith("+++ "):
                _validate_diff_control_line(line)
                if saw_new_header:
                    raise SecurityError("unified diff repeats its new file side header")
                new_side = _diff_side_path(line[4:], "b/", repository_root)
                saw_new_header = True
                index += 1
                continue
            if line.startswith("@@ "):
                _validate_diff_control_line(line)
                if not (saw_old_header and saw_new_header):
                    raise SecurityError("unified diff hunk precedes its file paths")
                metadata_pair = (
                    (metadata_old, metadata_new)
                    if metadata_old is not None and metadata_new is not None
                    else None
                )
                _resolve_diff_section_paths(
                    candidates,
                    saw_old_header=saw_old_header,
                    old_side=old_side,
                    saw_new_header=saw_new_header,
                    new_side=new_side,
                    metadata_pair=metadata_pair,
                    new_file=new_file,
                    deleted_file=deleted_file,
                )
                mode = _diff_mode(old_side, new_side, repository_root)
                old_count, new_count = _parse_diff_hunk_header(lines[index])
                index += 1
                old_refs: list[int] = []
                new_refs: list[int] = []
                context_refs: list[int] = []
                old_payload: list[str] = []
                new_payload: list[str] = []
                previous_payload = False
                while len(old_refs) < old_count or len(new_refs) < new_count:
                    if index >= len(lines):
                        raise SecurityError("unified diff hunk is truncated")
                    payload_line = lines[index]
                    if payload_line.startswith("\\ No newline at end of file"):
                        if not previous_payload:
                            raise SecurityError("unified diff newline marker is misplaced")
                        index += 1
                        previous_payload = False
                        continue
                    if not payload_line or payload_line[0] not in " +-":
                        raise SecurityError("unified diff hunk payload is invalid")
                    prefix = payload_line[0]
                    payload = payload_line[1:]
                    if prefix in " -":
                        old_refs.append(index)
                        old_payload.append(payload)
                    if prefix in " +":
                        new_refs.append(index)
                        new_payload.append(payload)
                    if prefix == " ":
                        context_refs.append(index)
                    if len(old_refs) > old_count or len(new_refs) > new_count:
                        raise SecurityError("unified diff hunk line counts overflow")
                    previous_payload = True
                    index += 1
                if index < len(lines) and lines[index].startswith("\\ No newline at end of file"):
                    index += 1
                if sanitize_payload:
                    sanitized_old = _sanitize_diff_payload(
                        "".join(old_payload),
                        mode,
                        counts,
                        repository_root=repository_root,
                        explicit_paths=explicit_paths,
                    )
                    sanitized_new = _sanitize_diff_payload(
                        "".join(new_payload),
                        mode,
                        counts,
                        repository_root=repository_root,
                        explicit_paths=explicit_paths,
                    )
                    if len(sanitized_old) != len(old_refs) or len(sanitized_new) != len(new_refs):
                        raise SecurityError(
                            "credential sanitization changed unified diff line boundaries"
                        )
                    replacements: dict[int, str] = {}
                    for line_index, payload in zip(old_refs, sanitized_old, strict=True):
                        replacements[line_index] = "-" + payload
                    for line_index, payload in zip(new_refs, sanitized_new, strict=True):
                        replacement = "+" + payload
                        if line_index in replacements:
                            if replacements[line_index][1:] != payload:
                                raise SecurityError(
                                    "unified diff context sanitization is inconsistent"
                                )
                            replacement = " " + payload
                        replacements[line_index] = replacement
                    for line_index in context_refs:
                        if line_index not in replacements:
                            raise SecurityError("unified diff context line was not reconstructed")
                    for line_index, replacement in replacements.items():
                        output[line_index] = replacement
                continue
            if line.startswith("Binary files ") and line.endswith(" differ"):
                _validate_diff_control_line(line)
                saw_binary = True
                index += 1
                continue
            metadata_prefixes = (
                "index ",
                "old mode ",
                "new mode ",
                "deleted file mode ",
                "new file mode ",
                "similarity index ",
                "dissimilarity index ",
                "rename from ",
                "rename to ",
                "copy from ",
                "copy to ",
            )
            if line.startswith(metadata_prefixes):
                _validate_diff_control_line(line)
                if line.startswith("new file mode "):
                    new_file = True
                elif line.startswith("deleted file mode "):
                    deleted_file = True
                if line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
                    prefix, kind, side = next(
                        (prefix, kind, side)
                        for prefix, kind, side in (
                            ("rename from ", "rename", "old"),
                            ("rename to ", "rename", "new"),
                            ("copy from ", "copy", "old"),
                            ("copy to ", "copy", "new"),
                        )
                        if line.startswith(prefix)
                    )
                    if metadata_kind is not None and metadata_kind != kind:
                        raise SecurityError("unified diff mixes rename and copy metadata")
                    metadata_kind = kind
                    relative = _diff_metadata_path(line[len(prefix) :], repository_root)
                    if side == "old":
                        if metadata_old is not None:
                            raise SecurityError("unified diff repeats old rename or copy metadata")
                        metadata_old = relative
                    else:
                        if metadata_new is not None:
                            raise SecurityError("unified diff repeats new rename or copy metadata")
                        metadata_new = relative
                index += 1
                continue
            raise SecurityError("unified diff contains an unsupported file-section line")
        if saw_binary and (saw_old_header or saw_new_header):
            raise SecurityError("unified diff binary and text boundaries conflict")
        if (metadata_old is None) is not (metadata_new is None):
            raise SecurityError("unified diff has incomplete rename or copy metadata")
        metadata_pair = (
            (metadata_old, metadata_new)
            if metadata_old is not None and metadata_new is not None
            else None
        )
        selected, change = _resolve_diff_section_paths(
            candidates,
            saw_old_header=saw_old_header,
            old_side=old_side,
            saw_new_header=saw_new_header,
            new_side=new_side,
            metadata_pair=metadata_pair,
            new_file=new_file,
            deleted_file=deleted_file,
        )
        mode = _diff_mode(change[0], change[1], repository_root)
        if _diff_mode(selected[0], selected[1], repository_root) is not mode:
            raise SecurityError("unified diff path modes conflict")
        changes.append(change)
    return (
        SanitizedText(
            "".join(output),
            dict(sorted((key, value) for key, value in counts.items() if value)),
        ),
        tuple(changes),
    )


def _sanitize_unified_diff(
    text: str,
    *,
    repository_root: Path | None,
    explicit_paths: tuple[Path, ...],
) -> SanitizedText:
    sanitized, _changes = _process_unified_diff(
        text,
        repository_root=repository_root,
        explicit_paths=explicit_paths,
        sanitize_payload=True,
    )
    return sanitized


def unified_diff_path_changes(
    text: str,
    *,
    repository_root: Path | None,
) -> tuple[tuple[str | None, str | None], ...]:
    _sanitized, changes = _process_unified_diff(
        text,
        repository_root=repository_root,
        explicit_paths=(),
        sanitize_payload=False,
    )
    return changes


def sanitize_text(
    text: str,
    *,
    scan_mode: ScanMode | None = None,
    repository_root: Path | None = None,
    explicit_paths: tuple[Path, ...] = (),
) -> SanitizedText:
    """Redact deterministic credentials and filesystem absolute paths."""
    if not isinstance(scan_mode, ScanMode):
        raise SecurityError("a valid scan mode is required")
    if scan_mode is ScanMode.UNIFIED_DIFF:
        return _sanitize_unified_diff(
            text,
            repository_root=repository_root,
            explicit_paths=explicit_paths,
        )
    text = _normalize_leading_bom(text)
    if "\x00" in text:
        raise SecurityError("NUL byte in text")
    counts: Counter[str] = Counter()
    redacted = _redact_credentials(text, counts)
    redacted = _redact_absolute_paths(
        redacted,
        counts,
        repository_root=repository_root,
        explicit_paths=explicit_paths,
    )
    _assert_no_residual_credentials(redacted)
    return SanitizedText(
        redacted, dict(sorted((key, value) for key, value in counts.items() if value))
    )


def sanitize_json_value(
    value: object,
    *,
    scan_mode: ScanMode | None = None,
    scan_manifest: ScanModeManifest | None = None,
    repository_root: Path | None = None,
    explicit_paths: tuple[Path, ...] = (),
    max_depth: int = MAX_SANITIZE_DEPTH,
    max_elements: int = MAX_SANITIZE_ELEMENTS,
) -> object:
    if max_depth < 0 or max_elements <= 0:
        raise SecurityError("invalid recursive sanitization limits")
    if (scan_mode is None) == (scan_manifest is None):
        raise SecurityError("exactly one scan mode source is required")
    if scan_mode is not None and not isinstance(scan_mode, ScanMode):
        raise SecurityError("a valid scan mode is required")
    if scan_manifest is not None and not isinstance(scan_manifest, ScanModeManifest):
        raise SecurityError("a valid scan mode manifest is required")
    elements = 0
    active_containers: set[int] = set()
    used_scan_paths: set[tuple[str | int, ...]] = set()

    def mode_for(path: tuple[str | int, ...]) -> ScanMode:
        if scan_mode is not None:
            return scan_mode
        assert scan_manifest is not None
        mode = scan_manifest.mode_for(path)
        used_scan_paths.add(path)
        return mode

    def consume() -> None:
        nonlocal elements
        elements += 1
        if elements > max_elements:
            raise SecurityError("artifact exceeds the recursive element limit")

    def walk(current: object, depth: int, path: tuple[str | int, ...]) -> object:
        consume()
        if depth > max_depth:
            raise SecurityError("artifact exceeds the recursive depth limit")
        if isinstance(current, str):
            return sanitize_text(
                current,
                scan_mode=mode_for(path),
                repository_root=repository_root,
                explicit_paths=explicit_paths,
            ).text
        if current is None or isinstance(current, (bool, int)):
            return current
        if isinstance(current, float):
            if not math.isfinite(current):
                raise SecurityError("artifact contains a non-finite float")
            return current
        if isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in active_containers:
                raise SecurityError("artifact contains a recursive sequence")
            active_containers.add(identity)
            try:
                return [walk(item, depth + 1, (*path, index)) for index, item in enumerate(current)]
            finally:
                active_containers.remove(identity)
        if isinstance(current, dict):
            identity = id(current)
            if identity in active_containers:
                raise SecurityError("artifact contains a recursive mapping")
            active_containers.add(identity)
            normalized: dict[str, object] = {}
            try:
                for key, item in current.items():
                    consume()
                    if not isinstance(key, str):
                        raise SecurityError("artifact mapping keys must be strings")
                    safe_key = sanitize_text(
                        key,
                        scan_mode=ScanMode.PLAIN_TEXT,
                        repository_root=repository_root,
                        explicit_paths=explicit_paths,
                    ).text
                    if safe_key in normalized:
                        raise SecurityError("artifact mapping keys collide after sanitization")
                    normalized[safe_key] = walk(item, depth + 1, (*path, key))
            finally:
                active_containers.remove(identity)
            return normalized
        raise SecurityError("artifact contains an unsupported value type")

    normalized = walk(value, 0, ())
    if scan_manifest is not None:
        expected_paths = {binding.path for binding in scan_manifest.bindings}
        if used_scan_paths != expected_paths:
            raise SecurityError("scan mode manifest does not exactly cover text values")
    return normalized


def is_sensitive_repository_path(relative_path: str) -> bool:
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts:
        return True
    return any(_is_sensitive_path_component(part) for part in path.parts)


def is_relevant_text_path(relative_path: str) -> bool:
    if is_sensitive_repository_path(relative_path):
        return False
    path = PurePosixPath(relative_path)
    return (
        path.suffix.lower() in ALLOWED_TEXT_SUFFIXES
        or path.name.lower() in ALLOWED_EXTENSIONLESS_NAMES
        or path.name == ".gitattributes"
    )


def has_supported_raster_image_suffix(relative_path: str) -> bool:
    """Return whether a path declares one of the fixed raster image types."""
    return (
        isinstance(relative_path, str)
        and bool(relative_path)
        and PurePosixPath(relative_path).suffix.lower() in RASTER_IMAGE_MEDIA_TYPES
    )


def raster_image_media_type(relative_path: str) -> str | None:
    """Return the declared raster type for one safe repository-relative path."""
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or is_sensitive_repository_path(relative_path)
        or any(character in relative_path for character in ("\x00", "\r", "\n", "\ufeff"))
    ):
        return None
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != relative_path:
        return None
    return RASTER_IMAGE_MEDIA_TYPES.get(path.suffix.lower())


def raster_image_magic_matches(media_type: str, prefix: bytes, byte_size: int) -> bool:
    """Validate only the fixed magic bytes required by the declared raster type."""
    if not isinstance(prefix, bytes) or byte_size < 0:
        return False
    if media_type == "image/jpeg":
        return byte_size >= 3 and prefix.startswith(b"\xff\xd8\xff")
    if media_type == "image/png":
        return byte_size >= 8 and prefix.startswith(b"\x89PNG\r\n\x1a\n")
    if media_type == "image/webp":
        return byte_size >= 12 and prefix.startswith(b"RIFF") and prefix[8:12] == b"WEBP"
    return False


def is_raster_image_evidence(
    relative_path: str,
    content: str,
    *,
    maximum_bytes: int,
) -> bool:
    """Validate the exact bounded text summary used for raster image evidence."""
    media_type = raster_image_media_type(relative_path)
    match = RASTER_IMAGE_EVIDENCE_RE.fullmatch(content) if isinstance(content, str) else None
    if (
        media_type is None
        or match is None
        or maximum_bytes < 0
        or match.group("media_type") != media_type
    ):
        return False
    byte_size = int(match.group("byte_size"))
    minimum = 12 if media_type == "image/webp" else 8 if media_type == "image/png" else 3
    return minimum <= byte_size <= maximum_bytes


def is_extensionless_text_candidate(relative_path: str) -> bool:
    """Return whether a path may use the bounded extensionless-text fallback."""
    if not isinstance(relative_path, str) or not relative_path:
        return False
    if is_yaml_content_path(relative_path) or is_sensitive_repository_path(relative_path):
        return False
    path = PurePosixPath(relative_path)
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and path.as_posix() == relative_path
        and bool(path.parts)
        and "." not in path.name
        and not is_relevant_text_path(relative_path)
        and not any(character in relative_path for character in ("\x00", "\r", "\n", "\ufeff"))
    )
