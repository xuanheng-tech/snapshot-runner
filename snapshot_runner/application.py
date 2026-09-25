"""Use cases behind the snapshot commands: validation, collection, publication, reads."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import re
import sys
from importlib import metadata
from pathlib import Path

from . import __version__, security
from . import artifact as artifact_module
from . import collect as collect_module
from . import git as git_module
from . import isolation as isolation_module
from . import legacy_v2 as legacy_v2_module
from . import model as model_module
from . import store as store_module
from . import views as views_module
from .security import RunnerError, SecurityError

ARGUMENT_ERROR = "ARGUMENT_ERROR"
RUNNER_UNEXPECTED_ERROR = "RUNNER_UNEXPECTED_ERROR"
CLI_ARGUMENT_ERROR = "invalid command-line arguments"
READ_TARGET_REPOSITORY_REQUIRED_ERROR = "explicit --repo is required for read"
SNAPSHOT_NOT_FOUND_ERROR = "snapshot not found in the private snapshot store"
EVIDENCE_FIELD_MISSING_ERROR = "requested evidence field is not present in the snapshot task data"
BRANCH_REVIEW_UNBORN_ERROR = "branch-review requires a target branch with at least one commit"


def _safe_exception_type(error: BaseException) -> str:
    exception_type = type(error).__name__
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", exception_type) is None:
        return "Exception"
    return exception_type


def _unexpected_error(error: BaseException, stage: str) -> RunnerError:
    return RunnerError(
        RUNNER_UNEXPECTED_ERROR,
        f"unexpected {_safe_exception_type(error)} during {stage}",
    )


def _installed_runner_root() -> Path | None:
    try:
        distribution = metadata.distribution("snapshot-runner")
        if distribution.version != __version__ or distribution.files is None:
            return None
        cli_entries = [
            entry for entry in distribution.files if entry.as_posix() == "snapshot_runner/cli.py"
        ]
        if len(cli_entries) != 1:
            return None
        installed_cli = Path(distribution.locate_file(cli_entries[0])).resolve(strict=True)
        if installed_cli != Path(__file__).resolve(strict=True).parent / "cli.py":
            return None
        return installed_cli.parents[1]
    except (metadata.PackageNotFoundError, OSError, RuntimeError, ValueError):
        return None


def _validated_runner_worktree_path() -> Path:
    installed_root = _installed_runner_root()
    return security.canonical_owned_directory(
        installed_root if installed_root is not None else model_module.REPOSITORY_ROOT,
        "Runner runtime root",
        git_module.RUNNER_REPOSITORY_INVALID_ERROR,
    )


def _validate_target_repository_path(raw: str) -> tuple[Path, str, Path]:
    try:
        candidate = Path(raw)
        if not candidate.is_absolute() or ".." in candidate.parts or os.fspath(candidate) != raw:
            raise RunnerError(
                security.REPOSITORY_VALIDATION_FAILED, git_module.TARGET_REPOSITORY_INVALID_ERROR
            )
        canonical = security.canonical_owned_directory(
            candidate,
            "target repository",
            git_module.TARGET_REPOSITORY_INVALID_ERROR,
        )
        if not security.is_safe_repository_name(canonical.name):
            raise RunnerError(
                security.REPOSITORY_VALIDATION_FAILED, git_module.TARGET_REPOSITORY_INVALID_ERROR
            )
        runner_repository = _validated_runner_worktree_path()
        if security.paths_overlap(canonical, runner_repository):
            raise RunnerError(
                security.REPOSITORY_VALIDATION_FAILED, git_module.TARGET_REPOSITORY_INVALID_ERROR
            )
        return canonical, canonical.name, runner_repository
    except (OSError, RuntimeError, ValueError) as exc:
        raise RunnerError(
            security.REPOSITORY_VALIDATION_FAILED, git_module.TARGET_REPOSITORY_INVALID_ERROR
        ) from exc


def _prepare_git_preflight(
    target: git_module.ValidatedTargetRepository,
    git: str,
    sealed_commits: tuple[str, ...],
) -> None:
    try:
        git_module.preflight_git_capabilities(
            target.path,
            target.target_identity.paths.git_dir,
            target.target_identity.paths.git_common_dir,
            git,
            runner_git_dir=(
                target.runner_identity.paths.git_dir
                if target.runner_identity is not None
                else target.target_identity.paths.git_dir
            ),
            runner_git_common_dir=(
                target.runner_identity.paths.git_common_dir
                if target.runner_identity is not None
                else target.target_identity.paths.git_common_dir
            ),
            sealed_commits=sealed_commits,
            expected_fingerprint=target.capability_fingerprint,
        )
    except RunnerError:
        raise
    except SecurityError as exc:
        raise RunnerError(security.GIT_PREFLIGHT_FAILED, "Git capability preflight failed") from exc
    except Exception as exc:
        raise _unexpected_error(exc, "Git capability preflight") from None


def _load_staged_snapshot_artifact(
    snapshot_id: str,
    staging: Path,
    repository_root: Path,
) -> model_module.SnapshotArtifact:
    try:
        return store_module._load_snapshot_directory(
            snapshot_id, staging, repository_root=repository_root
        )
    except TypeError:
        return store_module._load_snapshot_directory(snapshot_id, staging)


def _load_existing_snapshot_artifact(
    snapshot_id: str,
    repository_root: Path,
) -> model_module.SnapshotArtifact:
    try:
        return store_module._load_snapshot(
            snapshot_id, repository_root, repository_root=repository_root
        )
    except TypeError:
        try:
            return store_module._load_snapshot(snapshot_id, repository_root)
        except TypeError:
            return store_module._load_snapshot(snapshot_id)


def _prepare_snapshot(
    task: str,
    task_argument: str | None,
    target: git_module.ValidatedTargetRepository,
    git: str,
    *,
    initial_publish_evidence: bool = False,
    generated_trees: tuple[str, ...] = (),
    review_scope: tuple[str, ...] = (),
) -> model_module.SnapshotArtifact:
    with store_module.active_repository_root(target.path):
        return _prepare_snapshot_guarded(
            task,
            task_argument,
            target,
            git,
            initial_publish_evidence=initial_publish_evidence,
            generated_trees=generated_trees,
            review_scope=review_scope,
        )


def _prepare_snapshot_guarded(
    task: str,
    task_argument: str | None,
    target: git_module.ValidatedTargetRepository,
    git: str,
    *,
    initial_publish_evidence: bool = False,
    generated_trees: tuple[str, ...] = (),
    review_scope: tuple[str, ...] = (),
) -> model_module.SnapshotArtifact:
    staging: Path | None = None
    identity = target.target_identity
    try:
        if task == "test-triage":
            if task_argument is None:
                raise RunnerError(
                    security.SNAPSHOT_COLLECTION_FAILED,
                    "test-triage requires a repository-local log path",
                )
            snapshot = collect_module.collect_test_triage(target.path, task_argument)
        else:
            capability_fingerprint = target.capability_fingerprint
            if capability_fingerprint is None:
                raise RunnerError(security.GIT_PREFLIGHT_FAILED, "Git capability preflight failed")
            target_evidence = git_module.TargetGitEvidence(
                identity.current_ref,
                identity.head_state,
                identity.head,
                identity.empty_tree_oid,
            )
            conversion_policy = capability_fingerprint.conversion_policy
            if task == "repo-status":
                snapshot = collect_module.collect_repo_status(
                    target.path,
                    target_evidence,
                    conversion_policy,
                    git,
                    git_dir=identity.paths.git_dir,
                )
            elif task == "diff-audit":
                snapshot = collect_module.collect_diff_audit(
                    target.path,
                    target_evidence,
                    conversion_policy,
                    git,
                    initial_publish_evidence=initial_publish_evidence,
                    generated_trees=generated_trees,
                    review_scope=review_scope,
                )
            elif task == "branch-review":
                if task_argument is None:
                    raise RunnerError(
                        security.SNAPSHOT_COLLECTION_FAILED,
                        "branch-review requires a local base branch or tag",
                    )
                if identity.head_state == git_module.HEAD_STATE_UNBORN:
                    raise RunnerError(
                        security.SNAPSHOT_COLLECTION_FAILED,
                        BRANCH_REVIEW_UNBORN_ERROR,
                    )
                forbidden_base_ref = (
                    target.runner_identity.current_ref
                    if target.shared_common_dir and target.runner_identity is not None
                    else None
                )
                snapshot = collect_module.collect_branch_review(
                    target.path,
                    task_argument,
                    target_evidence,
                    conversion_policy,
                    git,
                    forbidden_base_ref=forbidden_base_ref,
                )
            else:
                raise RunnerError(security.SNAPSHOT_COLLECTION_FAILED, "unknown snapshot task")
    except RunnerError:
        raise
    except SecurityError as exc:
        raise RunnerError(
            security.SNAPSHOT_COLLECTION_FAILED, "snapshot collection failed"
        ) from exc
    except Exception as exc:
        raise _unexpected_error(exc, "snapshot collection") from None
    branch_review_seal = snapshot.branch_review_seal if task == "branch-review" else None
    if task == "branch-review":
        if branch_review_seal is None:
            raise RunnerError(
                security.SNAPSHOT_COLLECTION_FAILED, git_module.BRANCH_REVIEW_STATE_CHANGED_ERROR
            )
        sealed_commits = (
            branch_review_seal.base_commit,
            branch_review_seal.merge_base_commit,
            branch_review_seal.target_head,
        )
        git_module._revalidate_branch_review_seal(target, branch_review_seal, git)
    elif snapshot.branch_review_seal is not None:
        raise RunnerError(
            security.SNAPSHOT_COLLECTION_FAILED,
            "non-branch snapshot carried branch-review state",
        )
    elif task != "test-triage":
        sealed_commits = (identity.head,) if identity.head is not None else ()
    try:
        if snapshot.task != task or snapshot.repository != target.name:
            raise RunnerError(
                security.ARTIFACT_VALIDATION_FAILED,
                "snapshot repository does not match validated target",
            )
        envelope = store_module._sanitize_validate_snapshot(
            snapshot.as_envelope(),
            target.path,
            expected_scan_manifest=snapshot.scan_manifest,
        )
        snapshot_bytes = artifact_module._serialize_snapshot(envelope)
        snapshot_id = hashlib.sha256(snapshot_bytes).hexdigest()
        preview_bytes = views_module._build_preview_summary(snapshot_id, envelope).encode("utf-8")
        if len(preview_bytes) > model_module.MAX_PREVIEW_BYTES:
            raise RunnerError(
                security.ARTIFACT_VALIDATION_FAILED,
                "hard output limit exceeded: preview.txt",
            )
        meta = legacy_v2_module._validate_snapshot_meta_schema(
            artifact_module._snapshot_meta(
                snapshot_id, task, target.name, snapshot_bytes, preview_bytes
            )
        )
        meta_bytes = artifact_module._serialize_snapshot_meta(meta)
        target_bytes = os.fspath(target.path).encode("utf-8")
        if any(
            target_bytes in artifact for artifact in (snapshot_bytes, preview_bytes, meta_bytes)
        ):
            raise RunnerError(
                security.ARTIFACT_VALIDATION_FAILED,
                "target repository path escaped artifact sanitization",
            )
    except RunnerError:
        raise
    except SecurityError as exc:
        raise RunnerError(
            security.ARTIFACT_VALIDATION_FAILED,
            "snapshot artifact validation failed",
        ) from exc
    except Exception as exc:
        raise _unexpected_error(exc, "artifact validation") from None
    staging: Path | None = None
    try:
        root = store_module.snapshot_output_root(target.path)
        store_module._ensure_private_state_directory(root, "snapshot store", target.path)
        staging = store_module._create_private_staging_directory(root, "snapshot")
        store_module._atomic_write(
            staging / "snapshot.json", snapshot_bytes, model_module.MAX_SNAPSHOT_BYTES
        )
        store_module._atomic_write(
            staging / "preview.txt", preview_bytes, model_module.MAX_PREVIEW_BYTES
        )
        store_module._atomic_write(staging / "meta.json", meta_bytes, model_module.MAX_META_BYTES)
        store_module._fsync_directory(staging)
        staged_artifact = _load_staged_snapshot_artifact(snapshot_id, staging, target.path)
        if staged_artifact.snapshot_bytes != snapshot_bytes:
            raise RunnerError(
                security.ARTIFACT_PUBLISH_FAILED,
                "staged content-addressed snapshot differs from prepared bytes",
            )
        if branch_review_seal is not None:
            git_module._revalidate_branch_review_seal(target, branch_review_seal, git)
        if task != "test-triage":
            _prepare_git_preflight(target, git, sealed_commits)
        destination = root / snapshot_id
        try:
            os.rename(staging, destination)
        except OSError as exc:
            if not destination.exists():
                raise RunnerError(
                    security.ARTIFACT_PUBLISH_FAILED,
                    "unable to atomically publish snapshot",
                ) from exc
            existing = _load_existing_snapshot_artifact(snapshot_id, target.path)
            if existing.snapshot_bytes != snapshot_bytes:
                raise RunnerError(
                    security.ARTIFACT_PUBLISH_FAILED,
                    "existing content-addressed snapshot differs from prepared bytes",
                ) from exc
            store_module._discard_known_staging(staging, model_module.SNAPSHOT_FILE_NAMES)
            return existing
        artifact = model_module.SnapshotArtifact(
            staged_artifact.snapshot_id,
            staged_artifact.task,
            staged_artifact.snapshot_bytes,
            staged_artifact.envelope,
            destination,
        )
        try:
            store_module._fsync_directory(root)
        except OSError as exc:
            raise RunnerError(
                security.ARTIFACT_PUBLISH_FAILED,
                model_module.SNAPSHOT_PUBLISH_DURABILITY_ERROR,
            ) from exc
        return artifact
    except RunnerError:
        raise
    except Exception as exc:
        raise RunnerError(
            security.ARTIFACT_PUBLISH_FAILED,
            f"snapshot publication failed ({_safe_exception_type(exc)})",
        ) from None
    finally:
        if staging is not None:
            with contextlib.suppress(OSError, RunnerError):
                if staging.exists():
                    store_module._discard_known_staging(staging, model_module.SNAPSHOT_FILE_NAMES)


def _run_prepare(arguments: argparse.Namespace) -> int:
    try:
        target_path, target_name, runner_path = _validate_target_repository_path(arguments.repo)
        state_home = store_module._state_home(target_path)
        git = git_module._find_executable("git")
        target = git_module._validate_target_repository_context(
            target_path,
            target_name,
            runner_path,
            state_home,
            git,
            arguments.task,
            allow_installed_runner=_installed_runner_root() == runner_path,
        )
    except RunnerError:
        raise
    except SecurityError as exc:
        raise RunnerError(
            security.REPOSITORY_VALIDATION_FAILED,
            "repository validation failed",
        ) from exc
    except Exception as exc:
        raise _unexpected_error(exc, "repository validation") from None
    try:
        review_scope = tuple(arguments.scope_path)
        if review_scope:
            expected_head = target.target_identity.head
            if expected_head is None:
                raise RunnerError(
                    security.SNAPSHOT_COLLECTION_FAILED,
                    "isolated diff-audit requires one stable source HEAD",
                )
            with isolation_module.isolated_diff_repository(
                target.path,
                target.name,
                expected_head,
                review_scope,
                git,
            ) as isolated_path:
                isolated_target = git_module._validate_target_repository_context(
                    isolated_path,
                    target.name,
                    runner_path,
                    state_home,
                    git,
                    arguments.task,
                    allow_installed_runner=_installed_runner_root() == runner_path,
                )
                artifact = _prepare_snapshot(
                    arguments.task,
                    arguments.task_argument,
                    isolated_target,
                    git,
                    review_scope=review_scope,
                )
        else:
            artifact = _prepare_snapshot(
                arguments.task,
                arguments.task_argument,
                target,
                git,
                initial_publish_evidence=arguments.initial_publish_evidence,
                generated_trees=tuple(arguments.generated_tree),
            )
    except RunnerError:
        raise
    except SecurityError as exc:
        raise RunnerError(
            security.SNAPSHOT_COLLECTION_FAILED,
            "snapshot preparation failed",
        ) from exc
    except Exception as exc:
        raise _unexpected_error(exc, "snapshot preparation") from None
    if getattr(arguments, "summary", False):
        sys.stdout.buffer.write(views_module._build_summary_output(artifact, __version__))
    else:
        print(f"snapshot_id: {artifact.snapshot_id}")
        print(f"snapshot: {artifact.directory / 'snapshot.json'}")
        print(f"preview: {artifact.directory / 'preview.txt'}")
        print(f"security_boundary: {model_module.SECURITY_NOTICE}")
        print("manual_workflow:")
        print(f"  1. review {artifact.directory / 'preview.txt'}")
        print("  2. inspect snapshot.json with your coding agent or automation")
        print("  3. save the analysis result in the project record")
    return 0


def _run_read(arguments: argparse.Namespace) -> int:
    if arguments.repo is None:
        raise RunnerError(ARGUMENT_ERROR, READ_TARGET_REPOSITORY_REQUIRED_ERROR)
    if arguments.field is not None and arguments.path is not None:
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if model_module.SNAPSHOT_ID_RE.fullmatch(arguments.snapshot_id) is None:
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    evidence_path: str | None = None
    if arguments.path is not None:
        try:
            (evidence_path,) = isolation_module.validate_scope_paths([arguments.path])
        except RunnerError:
            raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR) from None
    try:
        target_path, target_name, _runner_repository = _validate_target_repository_path(
            arguments.repo
        )
        directory = store_module.snapshot_output_root(target_path) / arguments.snapshot_id
        try:
            directory.lstat()
        except FileNotFoundError as exc:
            raise RunnerError(security.ARTIFACT_NOT_FOUND, SNAPSHOT_NOT_FOUND_ERROR) from exc
        try:
            artifact = store_module._load_snapshot(
                arguments.snapshot_id, repository_root=target_path
            )
        except RunnerError as exc:
            if exc.code == security.ARTIFACT_PUBLISH_FAILED:
                raise RunnerError(security.ARTIFACT_VALIDATION_FAILED, exc.message) from None
            raise
        if artifact.envelope.get("repository") != target_name:
            raise RunnerError(
                security.ARTIFACT_VALIDATION_FAILED,
                "snapshot repository does not match validated target",
            )
        data = artifact.envelope.get("data")
        if arguments.field is not None and isinstance(data, dict) and arguments.field not in data:
            raise RunnerError(ARGUMENT_ERROR, EVIDENCE_FIELD_MISSING_ERROR)
        output = views_module._build_evidence_output(
            artifact,
            __version__,
            repository_root=target_path,
            field=arguments.field,
            path=evidence_path,
        )
    except RunnerError:
        raise
    except Exception as exc:
        raise _unexpected_error(exc, "snapshot evidence read") from None
    sys.stdout.buffer.write(output)
    return 0
