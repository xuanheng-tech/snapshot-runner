from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

from ..evidence import (
    _branch_changes,
    _BranchPathChange,
    _safe_relative_path,
    _validate_branch_diff_paths,
    _validate_workspace_diff_paths,
)
from ..git import (
    BRANCH_REVIEW_RANGE_SEMANTICS,
    BRANCH_REVIEW_STATE_CHANGED_ERROR,
    GIT_OID_RE,
    HEAD_STATE_ATTACHED,
    HEAD_STATE_DETACHED,
    HEAD_STATE_UNBORN,
    BranchReviewSeal,
    GitConversionPolicy,
    GitRunner,
    TargetGitEvidence,
    detect_active_git_operation,
)
from ..model import (
    MAX_CONTEXT_FILES,
    MAX_FILE_BYTES,
    MAX_GENERATED_TREE_BYTES,
    MAX_GENERATED_TREE_FILES,
    MAX_INITIAL_CONTEXT_FILES,
    _publication_workspace_sha256,
)
from ..security import (
    SNAPSHOT_COLLECTION_FAILED,
    RunnerError,
    ScanMode,
    SecurityError,
    classify_scan_mode,
    has_supported_raster_image_suffix,
    is_relevant_text_path,
    is_sensitive_repository_path,
    sanitize_text,
)
from .builder import (
    Snapshot,
    SnapshotBuilder,
)
from .readers import (
    _file_context_limit,
    _read_complete_regular,
    _read_test_log,
)
from .security_gate import (
    _add_context,
    _uses_bounded_csv_diff,
    _uses_extensionless_fallback,
)
from .workspace import (
    _add_branch_blob_context,
    _add_branch_conversion_safety,
    _add_workspace_conversion_safety,
    _changed_paths,
    _decode_git,
    _decode_unified_diff,
    _deleted_file_metadata,
    _prepare_branch_extensionless,
    _prepare_branch_images,
    _prepare_workspace_extensionless,
    _prepare_workspace_images,
    _refuse_yaml_paths,
    _workspace_changed_paths,
    _workspace_conversion_paths,
    _workspace_unified_diff,
)


def _current_target_evidence(git: GitRunner, builder: SnapshotBuilder) -> TargetGitEvidence:
    ref_result = git.run(("symbolic-ref", "--quiet", "HEAD"), maximum=4096)
    if ref_result.truncated:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "target current ref evidence exceeded its hard limit"
        )
    if ref_result.returncode == 0:
        current_ref = _decode_git(ref_result, "current-ref", builder)
        if not current_ref.endswith("\n") or "\r" in current_ref:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "target current ref evidence is not canonical"
            )
        current_ref = current_ref.removesuffix("\n")
        if not current_ref or "\n" in current_ref or "\r" in current_ref:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED, "target current ref evidence is not canonical"
            )
    elif ref_result.returncode == 1 and not ref_result.stdout:
        current_ref = None
    else:
        _decode_git(ref_result, "current-ref", builder)
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "unable to determine target current ref")
    head = _decode_git(
        git.run(("rev-parse", "--verify", "HEAD"), maximum=4096),
        "HEAD",
        builder,
    ).strip()
    head_state = HEAD_STATE_ATTACHED if current_ref is not None else HEAD_STATE_DETACHED
    return TargetGitEvidence(current_ref, head_state, head)


def _sealed_branch_target(
    git: GitRunner,
    builder: SnapshotBuilder,
    expected: TargetGitEvidence,
) -> TargetGitEvidence:
    before = _current_target_evidence(git, builder)
    if before.current_ref is None:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "branch-review requires an attached target branch"
        )
    ref_commit = _decode_git(
        git.run(("rev-parse", "--verify", f"{before.current_ref}^{{commit}}"), maximum=4096),
        "target-ref-commit",
        builder,
    ).strip()
    after = _current_target_evidence(git, builder)
    if before != after or before.head != ref_commit or before != expected:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, BRANCH_REVIEW_STATE_CHANGED_ERROR)
    return before


def _unique_merge_base(
    git: GitRunner,
    builder: SnapshotBuilder,
    base_commit: str,
    target_head: str,
) -> str:
    result = git.run(("merge-base", "--all", base_commit, target_head), maximum=4096)
    decoded = _decode_git(result, "branch-merge-base", builder)
    if result.truncated:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "branch-review merge-base evidence exceeded its hard limit"
        )
    commits = [line for line in decoded.splitlines() if line]
    if len(commits) != 1 or GIT_OID_RE.fullmatch(commits[0]) is None:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "branch-review requires exactly one merge-base commit"
        )
    return commits[0]


def _display_branch(current_ref: str | None) -> str:
    if current_ref is None:
        return "(detached)"
    return current_ref.removeprefix("refs/heads/")


def _single_repository_config_value(git: GitRunner, key: str) -> str | None:
    result = git.run(
        ("config", "--no-includes", "--null", "--get-all", key),
        maximum=4096,
    )
    if result.returncode == 1 and not result.stdout and not result.stderr and not result.truncated:
        return None
    if result.returncode != 0 or result.truncated or result.stderr:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to determine configured upstream target"
        )
    values = result.stdout.split(b"\0")
    if values and values[-1] == b"":
        values.pop()
    if len(values) != 1:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to determine configured upstream target"
        )
    try:
        value = values[0].decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to determine configured upstream target"
        ) from exc
    if not value or any(character in value for character in ("\x00", "\r", "\n")):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to determine configured upstream target"
        )
    return value


def _configured_upstream_target(git: GitRunner, current_ref: str) -> str | None:
    branch = _display_branch(current_ref)
    remote = _single_repository_config_value(git, f"branch.{branch}.remote")
    merge = _single_repository_config_value(git, f"branch.{branch}.merge")
    if remote is None and merge is None:
        return None
    if remote is None or merge is None or not merge.startswith("refs/heads/"):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to determine configured upstream target"
        )
    merge_branch = merge.removeprefix("refs/heads/")
    target_ref = merge if remote == "." else f"refs/remotes/{remote}/{merge_branch}"
    validation = git.run(("check-ref-format", target_ref), maximum=4096)
    if (
        not merge_branch
        or validation.returncode != 0
        or validation.truncated
        or validation.stdout
        or validation.stderr
    ):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to determine configured upstream target"
        )
    return merge_branch if remote == "." else f"{remote}/{merge_branch}"


def _upstream_ahead_behind(git: GitRunner, head: str | None) -> str:
    if head is None:
        return "not available"
    result = git.run(
        ("rev-list", "--left-right", "--count", f"{head}...@{{upstream}}"),
        maximum=4096,
    )
    if result.truncated:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "unable to calculate upstream relationship")
    if result.returncode != 0:
        return "not available"
    if result.stderr:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "unable to calculate upstream relationship")
    try:
        counts = result.stdout.decode("ascii", errors="strict").split()
    except UnicodeDecodeError as exc:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "unable to calculate upstream relationship"
        ) from exc
    if len(counts) != 2 or any(not count.isdecimal() for count in counts):
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "unable to calculate upstream relationship")
    return f"{int(counts[0])} / {int(counts[1])}"


def _current_branch_evidence(evidence: TargetGitEvidence) -> str:
    if evidence.current_ref is None:
        return ""
    head = evidence.head if evidence.head is not None else HEAD_STATE_UNBORN
    return f"{_display_branch(evidence.current_ref)}\t{head}\n"


def collect_repo_status(
    repo_root: Path,
    target_evidence: TargetGitEvidence,
    conversion_policy: GitConversionPolicy,
    git_executable: str = "/usr/bin/git",
    git_dir: Path | None = None,
) -> Snapshot:
    builder = SnapshotBuilder("repo-status", repo_root.name, repo_root)
    git = GitRunner(repo_root, git_executable, conversion_policy=conversion_policy)
    if git_dir is None:
        rev_result = git.run(("rev-parse", "--path-format=absolute", "--git-dir"), maximum=4096)
        if (
            rev_result.returncode == 0
            and not rev_result.truncated
            and rev_result.stdout.endswith(b"\n")
        ):
            raw_git_dir = rev_result.stdout.removesuffix(b"\n").decode("utf-8", errors="strict")
            git_dir = Path(raw_git_dir).resolve()
        else:
            git_dir = repo_root / ".git"

    active_operation = detect_active_git_operation(git_dir)
    if active_operation is not None:
        builder.add_value(
            "active_operation",
            active_operation,
            scan_mode=ScanMode.PLAIN_TEXT,
        )

    staged_paths, unstaged_paths, untracked_paths = _workspace_changed_paths(git, builder)
    tracked_paths = _changed_paths(git, builder, ("ls-files", "--cached", "-z", "--"))
    conversion_paths = _workspace_conversion_paths(
        git, conversion_policy, tracked_paths, staged_paths, unstaged_paths, untracked_paths
    )
    status_text = _decode_git(
        git.run(("status", "--short", "--untracked-files=all")), "git-status", builder
    )
    if target_evidence.head is None:
        recent = ""
    else:
        recent = _decode_git(
            git.run(
                (
                    "log",
                    "-25",
                    "--date=short",
                    "--pretty=format:%h%x09%ad%x09%s",
                    target_evidence.head,
                    "--",
                )
            ),
            "recent-commits",
            builder,
        )
    builder.add_text(
        "current_branch",
        _display_branch(target_evidence.current_ref),
        source="current-branch",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    builder.add_text(
        "head",
        target_evidence.head if target_evidence.head is not None else HEAD_STATE_UNBORN,
        source="HEAD",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    if target_evidence.current_ref is not None:
        upstream = _configured_upstream_target(git, target_evidence.current_ref)
        builder.add_text(
            "upstream",
            upstream if upstream is not None else "not configured",
            source="upstream",
            scan_mode=ScanMode.PLAIN_TEXT,
        )
        builder.add_text(
            "ahead_behind",
            _upstream_ahead_behind(git, target_evidence.head)
            if upstream is not None
            else "not available",
            source="ahead-behind",
            scan_mode=ScanMode.PLAIN_TEXT,
        )
    builder.add_text(
        "status_short", status_text, source="git-status", scan_mode=ScanMode.PLAIN_TEXT
    )
    builder.add_text(
        "recent_commits", recent, source="recent-commits", scan_mode=ScanMode.PLAIN_TEXT
    )
    builder.add_text(
        "local_branches",
        _current_branch_evidence(target_evidence),
        source="target-current-branch",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    _add_workspace_conversion_safety(
        builder,
        git,
        conversion_policy,
        target_evidence.head,
        tracked_paths,
        staged_paths,
        unstaged_paths,
        untracked_paths,
        conversion_paths,
    )
    return builder.finish()


def _canonical_generated_tree(raw: str) -> str:
    relative = _safe_relative_path(raw)
    if (
        relative is None
        or relative != raw
        or relative in {".", ".git"}
        or relative.startswith(".git/")
        or is_sensitive_repository_path(relative)
    ):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated tree must be a canonical repository-relative directory",
        )
    return relative


def _enumerate_generated_tree(repo_root: Path, tree_relative: str) -> tuple[str, ...]:
    tree_path = repo_root.joinpath(*PurePosixPath(tree_relative).parts)
    try:
        tree_stat = tree_path.lstat()
    except OSError as exc:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated tree does not exist",
        ) from exc
    if stat.S_ISLNK(tree_stat.st_mode) or not stat.S_ISDIR(tree_stat.st_mode):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated tree must be a real directory",
        )
    files: list[str] = []
    for current, directory_names, file_names in os.walk(tree_path, topdown=True, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            try:
                entry_stat = (current_path / name).lstat()
            except OSError as exc:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED,
                    "generated tree changed while enumerating",
                ) from exc
            if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISDIR(entry_stat.st_mode):
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED,
                    "generated tree contains a symlink or special directory",
                )
        for name in file_names:
            candidate = current_path / name
            try:
                entry_stat = candidate.lstat()
            except OSError as exc:
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED,
                    "generated tree changed while enumerating",
                ) from exc
            if stat.S_ISLNK(entry_stat.st_mode) or not stat.S_ISREG(entry_stat.st_mode):
                raise RunnerError(
                    SNAPSHOT_COLLECTION_FAILED,
                    "generated tree contains a symlink or special file",
                )
            files.append(candidate.relative_to(tree_path).as_posix())
    return tuple(files)


def _decode_scanned_generated_json(
    repo_root: Path,
    relative: str,
    raw: bytes,
) -> object:
    try:
        text = raw.decode("utf-8", errors="strict")
        sanitized = sanitize_text(
            text,
            scan_mode=ScanMode.PLAIN_TEXT,
            repository_root=repo_root,
        )
        parsed = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, SecurityError) as exc:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated JSON failed content validation or sensitive scanning",
        ) from exc
    credential_redactions = set(sanitized.redactions) - {"ABSOLUTE_PATH", "FILE_URI"}
    if credential_redactions:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated JSON contains a credential pattern",
        )
    if PurePosixPath(relative).suffix.lower() != ".json":
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated manifest coverage only accepts JSON members",
        )
    return parsed


def _collect_generated_tree_evidence(
    repo_root: Path,
    tree_relative: str,
    untracked_paths: frozenset[str],
) -> tuple[dict[str, object], list[dict[str, object]], frozenset[str]]:
    tree = _canonical_generated_tree(tree_relative)
    manifest_path = f"{tree}/manifest.json"
    if manifest_path not in untracked_paths:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated tree manifest must be part of the unborn publication scope",
        )
    manifest = _read_complete_regular(repo_root, manifest_path, MAX_FILE_BYTES)
    if manifest.executable:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated tree manifest must not be executable",
        )
    parsed = _decode_scanned_generated_json(repo_root, manifest_path, manifest.content)
    if not isinstance(parsed, dict):
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "generated manifest must be a JSON object")
    entries = parsed.get("files")
    declared_count = parsed.get("file_count")
    declared_total = parsed.get("total_bytes")
    if (
        not isinstance(entries, list)
        or not isinstance(declared_count, int)
        or isinstance(declared_count, bool)
        or not isinstance(declared_total, int)
        or isinstance(declared_total, bool)
        or declared_count < 0
        or declared_total < 0
        or declared_count != len(entries)
        or len(entries) > MAX_GENERATED_TREE_FILES
        or declared_total > MAX_GENERATED_TREE_BYTES
    ):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated manifest count or size bounds are invalid",
        )

    member_paths: list[str] = []
    expected: dict[str, tuple[int, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated manifest file entry schema is invalid",
            )
        member = entry.get("path")
        byte_size = entry.get("bytes")
        sha256 = entry.get("sha256")
        safe_member = _safe_relative_path(member) if isinstance(member, str) else None
        if (
            safe_member is None
            or safe_member != member
            or safe_member in {".", "manifest.json"}
            or PurePosixPath(safe_member).suffix.lower() != ".json"
            or not isinstance(byte_size, int)
            or isinstance(byte_size, bool)
            or byte_size < 0
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated manifest file entry is unsafe or invalid",
            )
        if safe_member in expected:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated manifest contains a duplicate path",
            )
        expected[safe_member] = (byte_size, sha256)
        member_paths.append(safe_member)
    if member_paths != sorted(member_paths):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated manifest paths must be in lexical order",
        )

    actual = _enumerate_generated_tree(repo_root, tree)
    if set(actual) != {"manifest.json", *expected}:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated manifest does not exactly match the directory tree",
        )
    records: list[dict[str, object]] = []
    observed_total = 0
    full_member_paths: set[str] = set()
    for member in member_paths:
        relative = f"{tree}/{member}"
        if relative not in untracked_paths:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated manifest member is outside the unborn publication scope",
            )
        evidence = _read_complete_regular(repo_root, relative, MAX_GENERATED_TREE_BYTES)
        expected_size, expected_sha256 = expected[member]
        if evidence.executable:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated JSON member must not be executable",
            )
        if evidence.byte_size != expected_size:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated manifest member size does not match",
            )
        if evidence.sha256 != expected_sha256:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated manifest member SHA-256 does not match",
            )
        _decode_scanned_generated_json(repo_root, relative, evidence.content)
        observed_total += evidence.byte_size
        full_member_paths.add(relative)
        records.append(
            {
                "path": relative,
                "bytes": evidence.byte_size,
                "sha256": evidence.sha256,
                "executable": False,
                "coverage": "generated_manifest",
                "manifest_path": manifest_path,
            }
        )
    if observed_total != declared_total:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated manifest total size does not match",
        )
    if _enumerate_generated_tree(repo_root, tree) != actual:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated tree changed while validating",
        )
    summary = {
        "path": tree,
        "manifest_path": manifest_path,
        "manifest_bytes": manifest.byte_size,
        "manifest_sha256": manifest.sha256,
        "file_count": len(records),
        "total_bytes": observed_total,
    }
    return summary, records, frozenset(full_member_paths)


def _initial_content_evidence(
    builder: SnapshotBuilder,
    paths: list[str],
) -> tuple[list[dict[str, object]], dict[str, str]]:
    records: list[dict[str, object]] = []
    sanitized_content: dict[str, str] = {}
    for relative in list(dict.fromkeys(paths))[:MAX_INITIAL_CONTEXT_FILES]:
        evidence = _read_complete_regular(
            builder.repo_root,
            relative,
            _file_context_limit(relative),
        )
        try:
            text = evidence.content.decode("utf-8", errors="strict")
            scan_mode = classify_scan_mode(relative)
            sanitized = sanitize_text(
                text,
                scan_mode=scan_mode,
                repository_root=builder.repo_root,
            )
        except (UnicodeDecodeError, SecurityError) as exc:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication content evidence failed closed",
            ) from exc
        sanitized_content[relative] = sanitized.text
        records.append(
            {
                "path": relative,
                "bytes": evidence.byte_size,
                "sha256": evidence.sha256,
                "executable": evidence.executable,
                "coverage": "content",
            }
        )
    return records, sanitized_content


def _start_initial_publication_evidence(
    builder: SnapshotBuilder,
    untracked_paths: list[str],
    generated_trees: tuple[str, ...],
) -> tuple[frozenset[str], dict[str, str]]:
    untracked = frozenset(untracked_paths)
    generated_records: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    generated_members: set[str] = set()
    roots: list[str] = []
    for raw_tree in generated_trees:
        tree = _canonical_generated_tree(raw_tree)
        if any(
            PurePosixPath(tree).is_relative_to(PurePosixPath(existing))
            or PurePosixPath(existing).is_relative_to(PurePosixPath(tree))
            for existing in roots
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated tree declarations must not overlap",
            )
        roots.append(tree)
        summary, records, members = _collect_generated_tree_evidence(
            builder.repo_root,
            tree,
            untracked,
        )
        if generated_members & members:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "generated tree declarations contain duplicate members",
            )
        summaries.append(summary)
        generated_records.extend(records)
        generated_members.update(members)

    if (
        len(generated_records) > MAX_GENERATED_TREE_FILES
        or sum(int(record["bytes"]) for record in generated_records) > MAX_GENERATED_TREE_BYTES
    ):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated publication evidence exceeds its aggregate hard limit",
        )

    manual_paths = [path for path in untracked_paths if path not in generated_members]
    content_records, sanitized_content = _initial_content_evidence(builder, manual_paths)
    records = sorted([*content_records, *generated_records], key=lambda item: str(item["path"]))
    payload = {
        "schema_version": 1,
        "mode": "unborn",
        "complete": False,
        "sensitive_scan": "partial",
        "changed_file_count": len(untracked),
        "covered_file_count": len(records),
        "content_file_count": len(content_records),
        "generated_file_count": len(generated_records),
        "workspace_sha256": _publication_workspace_sha256(records),
        "files": records,
        "generated_trees": sorted(summaries, key=lambda item: str(item["path"])),
    }
    builder.add_value("initial_publication", payload, scan_mode=ScanMode.PLAIN_TEXT)
    return frozenset(generated_members), sanitized_content


def _finish_initial_publication_evidence(
    builder: SnapshotBuilder,
    sanitized_content: dict[str, str],
) -> None:
    publication = builder.data.get("initial_publication")
    contexts = builder.data.get("file_context")
    if not isinstance(publication, dict) or not isinstance(contexts, list):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "initial publication evidence was not retained",
        )
    observed_content: dict[str, str] = {}
    for context in contexts:
        if not isinstance(context, dict):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication file context is invalid",
            )
        path = context.get("path")
        content = context.get("content")
        if not isinstance(path, str) or not isinstance(content, str) or path in observed_content:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication file context is ambiguous",
            )
        observed_content[path] = content
    content_matches = observed_content == sanitized_content
    if not content_matches and not builder.gaps:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "initial publication files changed while collecting evidence",
        )
    changed_count = publication.get("changed_file_count")
    covered_count = publication.get("covered_file_count")
    all_paths_scanned = changed_count == covered_count
    records = publication.get("files")
    trees = publication.get("generated_trees")
    if not isinstance(records, list) or not isinstance(trees, list):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "initial publication evidence is invalid",
        )
    for record in records:
        if not isinstance(record, dict):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication file evidence is invalid",
            )
        relative = record.get("path")
        expected_size = record.get("bytes")
        expected_sha256 = record.get("sha256")
        expected_executable = record.get("executable")
        if not isinstance(relative, str) or not isinstance(expected_size, int):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication file evidence is invalid",
            )
        evidence = _read_complete_regular(builder.repo_root, relative, expected_size)
        if (
            evidence.byte_size != expected_size
            or evidence.sha256 != expected_sha256
            or evidence.executable is not expected_executable
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication workspace changed while collecting evidence",
            )
    for tree in trees:
        if not isinstance(tree, dict):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication generated-tree evidence is invalid",
            )
        root = tree.get("path")
        manifest_path = tree.get("manifest_path")
        if not isinstance(root, str) or not isinstance(manifest_path, str):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication generated-tree evidence is invalid",
            )
        expected_members = {
            str(record["path"])[len(root) + 1 :]
            for record in records
            if record.get("coverage") == "generated_manifest"
            and record.get("manifest_path") == manifest_path
        }
        if set(_enumerate_generated_tree(builder.repo_root, root)) != {
            "manifest.json",
            *expected_members,
        }:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication generated tree changed while collecting evidence",
            )
    publication["sensitive_scan"] = "complete" if all_paths_scanned else "partial"
    publication["complete"] = bool(not builder.gaps and all_paths_scanned and content_matches)


def collect_diff_audit(
    repo_root: Path,
    target_evidence: TargetGitEvidence,
    conversion_policy: GitConversionPolicy,
    git_executable: str = "/usr/bin/git",
    *,
    initial_publish_evidence: bool = False,
    generated_trees: tuple[str, ...] = (),
    review_scope: tuple[str, ...] = (),
) -> Snapshot:
    builder = SnapshotBuilder("diff-audit", repo_root.name, repo_root)
    if review_scope:
        if initial_publish_evidence:
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "isolated review scope is incompatible with initial publication evidence",
            )
        builder.add_value(
            "review_scope",
            {"mode": "isolated-clone", "paths": list(review_scope)},
            scan_mode=ScanMode.PLAIN_TEXT,
        )
    git = GitRunner(repo_root, git_executable, conversion_policy=conversion_policy)
    staged_paths, unstaged_paths, untracked_paths = _workspace_changed_paths(git, builder)
    tracked_paths = _changed_paths(git, builder, ("ls-files", "--cached", "-z", "--"))
    if generated_trees and not initial_publish_evidence:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED,
            "generated-tree evidence requires initial publication mode",
        )
    generated_members = frozenset()
    sanitized_initial_content: dict[str, str] = {}
    if initial_publish_evidence:
        if (
            target_evidence.head_state != HEAD_STATE_UNBORN
            or tracked_paths
            or staged_paths
            or unstaged_paths
        ):
            raise RunnerError(
                SNAPSHOT_COLLECTION_FAILED,
                "initial publication evidence requires an entirely untracked unborn worktree",
            )
        generated_members, sanitized_initial_content = _start_initial_publication_evidence(
            builder,
            untracked_paths,
            generated_trees,
        )
    conversion_paths = _workspace_conversion_paths(
        git, conversion_policy, tracked_paths, staged_paths, unstaged_paths, untracked_paths
    )
    omitted_conversion_paths = {
        path
        for path, _disabled_types, _content_filter in conversion_paths
        if not is_relevant_text_path(path)
    }
    context_staged_paths = [path for path in staged_paths if path not in omitted_conversion_paths]
    context_unstaged_paths = [
        path for path in unstaged_paths if path not in omitted_conversion_paths
    ]
    context_untracked_paths = [
        path
        for path in untracked_paths
        if path not in omitted_conversion_paths and path not in generated_members
    ]
    unsupported_diff_paths = {
        path
        for path in (*context_staged_paths, *context_unstaged_paths)
        if not (
            is_relevant_text_path(path)
            or _uses_extensionless_fallback(path)
            or _uses_bounded_csv_diff(path)
            or has_supported_raster_image_suffix(path)
        )
    }
    extensionless = _prepare_workspace_extensionless(
        builder,
        git,
        target_evidence.head,
        context_staged_paths,
        context_unstaged_paths,
        context_untracked_paths,
    )
    images = _prepare_workspace_images(
        builder,
        git,
        context_staged_paths,
        context_unstaged_paths,
        context_untracked_paths,
    )
    staged_diff_paths = [
        path
        for path in context_staged_paths
        if path not in images.paths
        and path not in unsupported_diff_paths
        and (path not in extensionless.fallback_paths or path in extensionless.staged_diff_paths)
    ]
    unstaged_diff_paths = [
        path
        for path in context_unstaged_paths
        if path not in images.paths
        and path not in unsupported_diff_paths
        and (path not in extensionless.fallback_paths or path in extensionless.unstaged_diff_paths)
    ]
    status_text = _decode_git(
        git.run(("status", "--short", "--untracked-files=all")), "git-status", builder
    )
    staged = _workspace_unified_diff(
        git,
        builder,
        "staged-diff",
        staged_diff_paths,
        cached=True,
    )
    unstaged = _workspace_unified_diff(
        git,
        builder,
        "unstaged-diff",
        unstaged_diff_paths,
        cached=False,
    )
    staged_changes = _validate_workspace_diff_paths(
        staged,
        staged_diff_paths,
        repo_root,
        "staged-diff",
    )
    unstaged_changes = _validate_workspace_diff_paths(
        unstaged,
        unstaged_diff_paths,
        repo_root,
        "unstaged-diff",
    )
    builder.add_text(
        "status_short", status_text, source="git-status", scan_mode=ScanMode.PLAIN_TEXT
    )
    if target_evidence.head_state == HEAD_STATE_UNBORN:
        if target_evidence.empty_tree_oid is None:
            raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "unborn baseline evidence is missing")
        builder.add_text(
            "baseline_kind",
            "empty_tree",
            source="diff-baseline-kind",
            scan_mode=ScanMode.PLAIN_TEXT,
        )
        builder.add_text(
            "baseline_oid",
            target_evidence.empty_tree_oid,
            source="diff-baseline-oid",
            scan_mode=ScanMode.PLAIN_TEXT,
        )
    builder.add_text(
        "staged_diff",
        staged,
        source="staged-diff",
        scan_mode=ScanMode.UNIFIED_DIFF,
    )
    builder.add_text(
        "unstaged_diff",
        unstaged,
        source="unstaged-diff",
        scan_mode=ScanMode.UNIFIED_DIFF,
    )
    deleted_staged = {old_path for old_path, new_path in staged_changes if new_path is None}
    deleted_unstaged = {old_path for old_path, new_path in unstaged_changes if new_path is None}
    later_context_paths = set(context_unstaged_paths) | set(context_untracked_paths)
    untracked_context_paths = set(context_untracked_paths)
    _add_context(
        builder,
        [
            *(
                path
                for path in context_staged_paths
                if path not in deleted_staged or path in later_context_paths
            ),
            *(
                path
                for path in context_unstaged_paths
                if path not in deleted_unstaged or path in untracked_context_paths
            ),
            *context_untracked_paths,
        ],
        max_context_files=(
            MAX_INITIAL_CONTEXT_FILES if initial_publish_evidence else MAX_CONTEXT_FILES
        ),
        prepared_extensionless=extensionless.contexts,
        handled_extensionless=extensionless.fallback_paths,
        prepared_images=images.contexts,
        handled_images=images.paths,
    )
    _add_workspace_conversion_safety(
        builder,
        git,
        conversion_policy,
        target_evidence.head,
        tracked_paths,
        staged_paths,
        unstaged_paths,
        untracked_paths,
        conversion_paths,
    )
    if initial_publish_evidence:
        _finish_initial_publication_evidence(builder, sanitized_initial_content)
    return builder.finish()


def _validated_base(
    git: GitRunner,
    raw_base: str,
    builder: SnapshotBuilder,
    forbidden_base_ref: str | None = None,
) -> tuple[str, str]:
    if (
        not raw_base
        or len(raw_base.encode("utf-8")) > 255
        or raw_base.startswith("-")
        or any(character in raw_base for character in ("\x00", "\n", "\r", " "))
        or ".." in raw_base
        or raw_base.endswith((".", "/"))
    ):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "base must name a validated local branch or tag"
        )
    if raw_base.startswith(("refs/heads/", "refs/tags/")):
        candidates = (raw_base,)
    elif raw_base.startswith("refs/"):
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "base must name a validated local branch or tag"
        )
    else:
        candidates = (f"refs/heads/{raw_base}", f"refs/tags/{raw_base}")
    matches: list[str] = []
    for candidate in candidates:
        result = git.run(("show-ref", "--verify", "--quiet", candidate), maximum=4096)
        if result.returncode == 0:
            matches.append(candidate)
            continue
        if result.returncode not in {1}:
            _decode_git(result, "base-validation", builder)
    if not matches:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "base is not an existing local branch or tag")
    if len(matches) != 1:
        raise RunnerError(
            SNAPSHOT_COLLECTION_FAILED, "base is ambiguous; use a full local branch or tag ref"
        )
    selected = matches[0]
    if forbidden_base_ref is not None and selected == forbidden_base_ref:
        raise RunnerError(SNAPSHOT_COLLECTION_FAILED, "base ref belongs to the Runner worktree")
    commit = _decode_git(
        git.run(("rev-parse", "--verify", f"{selected}^{{commit}}"), maximum=4096),
        "base-commit",
        builder,
    ).strip()
    return selected, commit


def collect_branch_review(
    repo_root: Path,
    base: str,
    target_evidence: TargetGitEvidence,
    conversion_policy: GitConversionPolicy,
    git_executable: str = "/usr/bin/git",
    *,
    forbidden_base_ref: str | None = None,
) -> Snapshot:
    builder = SnapshotBuilder("branch-review", repo_root.name, repo_root)
    git = GitRunner(repo_root, git_executable, conversion_policy=conversion_policy)
    sealed_target = _sealed_branch_target(git, builder, target_evidence)
    selected, commit = _validated_base(git, base, builder, forbidden_base_ref)
    merge_base_commit = _unique_merge_base(git, builder, commit, sealed_target.head)
    range_spec = f"{merge_base_commit}..{sealed_target.head}"
    changes = _branch_changes(
        git.run(
            (
                "diff",
                "--name-status",
                "-z",
                "--find-renames=50%",
                "--diff-filter=ADMRT",
                "--no-ext-diff",
                "--no-textconv",
                range_spec,
                "--",
            )
        )
    )
    changed_paths = [
        path
        for change in changes
        for path in ((change.old_path,) if change.old_path is not None else ()) + (change.path,)
    ]
    _refuse_yaml_paths(changed_paths)
    extensionless = _prepare_branch_extensionless(
        builder,
        git,
        merge_base_commit,
        sealed_target.head,
        changes,
    )
    images = _prepare_branch_images(builder, git, sealed_target.head, changes)
    diff_paths: list[str] = []
    diff_changes: list[_BranchPathChange] = []
    for change in changes:
        if change.status == "D":
            continue
        paths = [change.path]
        if change.old_path is not None:
            paths.insert(0, change.old_path)
        if any(has_supported_raster_image_suffix(path) for path in paths):
            if not has_supported_raster_image_suffix(change.path):
                builder.gap(
                    "diff_file_refused",
                    change.path,
                    "raster image rename target has an unsupported extension",
                )
            continue
        if all(
            is_relevant_text_path(path) or path in extensionless.accepted_diff_paths
            for path in paths
        ):
            diff_paths.extend(paths)
            diff_changes.append(change)
        elif not any(path in extensionless.fallback_paths for path in paths):
            builder.gap(
                "diff_file_refused",
                change.path,
                "sensitive or unsupported diff file type refused",
            )
    commits = _decode_git(
        git.run(("log", "--oneline", "--no-decorate", range_spec, "--")),
        "branch-commits",
        builder,
    )
    unique_diff_paths = list(dict.fromkeys(diff_paths))
    if unique_diff_paths:
        diff = _decode_unified_diff(
            git.run(
                (
                    "-c",
                    "core.quotePath=true",
                    "diff",
                    "--find-renames=50%",
                    "--no-ext-diff",
                    "--no-textconv",
                    range_spec,
                    "--",
                    *(f":(top,literal){path}" for path in unique_diff_paths),
                )
            ),
            "branch-diff",
            builder,
        )
    else:
        diff = ""
    _validate_branch_diff_paths(diff, diff_changes, repo_root, "branch-diff")
    seal = BranchReviewSeal(
        selected,
        commit,
        sealed_target.current_ref,
        sealed_target.head,
        merge_base_commit,
    )
    builder.add_text("base", selected, source="base", scan_mode=ScanMode.PLAIN_TEXT)
    builder.add_text("base_commit", commit, source="base-commit", scan_mode=ScanMode.PLAIN_TEXT)
    builder.add_text(
        "target_ref",
        seal.target_ref,
        source="target-ref",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    builder.add_text(
        "target_head",
        seal.target_head,
        source="target-head",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    builder.add_text(
        "merge_base_commit",
        seal.merge_base_commit,
        source="merge-base-commit",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    builder.add_text(
        "range_semantics",
        BRANCH_REVIEW_RANGE_SEMANTICS,
        source="range-semantics",
        scan_mode=ScanMode.PLAIN_TEXT,
    )
    builder.add_text("commits", commits, source="branch-commits", scan_mode=ScanMode.PLAIN_TEXT)
    builder.add_text(
        "diff",
        diff,
        source="branch-diff",
        scan_mode=ScanMode.UNIFIED_DIFF,
    )
    _deleted_file_metadata(builder, git, seal.merge_base_commit, changes)
    _add_branch_blob_context(
        builder,
        git,
        seal.target_head,
        changes,
        extensionless,
        images,
    )
    _add_branch_conversion_safety(
        builder,
        git,
        conversion_policy,
        seal.merge_base_commit,
        seal.target_head,
        changed_paths,
        unique_diff_paths,
    )
    return builder.finish(branch_review_seal=seal)


def collect_test_triage(repo_root: Path, log_argument: str) -> Snapshot:
    builder = SnapshotBuilder("test-triage", repo_root.name, repo_root)
    text, omitted, display_name = _read_test_log(repo_root, log_argument)
    builder.add_text("log", text, source=display_name, scan_mode=ScanMode.PLAIN_TEXT)
    builder.add_value("log_display_name", display_name, scan_mode=ScanMode.PLAIN_TEXT)
    if omitted:
        builder.gap(
            "test_log_limit",
            display_name,
            "test log middle truncated at the 2 MiB head/tail hard limit",
            omitted,
        )
    return builder.finish()
