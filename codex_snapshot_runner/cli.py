"""Prepare reviewed snapshots for manual analysis in prepare-only mode."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import re
import signal
import sys
from importlib import metadata
from pathlib import Path

from . import __version__, security
from . import artifact as artifact_module
from . import collect as collect_module
from . import git as git_module
from . import isolation as isolation_module
from .security import RunnerError, SecurityError

ARGUMENT_ERROR = "ARGUMENT_ERROR"
RUNNER_UNEXPECTED_ERROR = "RUNNER_UNEXPECTED_ERROR"
AUTOMATIC_ANALYSIS_DISABLED = "AUTOMATIC_ANALYSIS_DISABLED"
CLI_ARGUMENT_ERROR = "invalid command-line arguments"
ANALYZE_DISABLED_ERROR = (
    "prepare-only mode does not support automatic model calls; review preview.txt and "
    "inspect preview.txt or snapshot.json with your coding agent or automation"
)
TARGET_REPOSITORY_REQUIRED_ERROR = "explicit --repo is required for prepare"
BRANCH_REVIEW_UNBORN_ERROR = "branch-review requires a target branch with at least one commit"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)


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


def _emit_workflow_error(error: RunnerError) -> None:
    print(f"workflow_failed: {error.code}: {error.message}", file=sys.stderr)


def _installed_runner_root() -> Path | None:
    try:
        distribution = metadata.distribution("snapshot-runner")
        if distribution.version != __version__ or distribution.files is None:
            return None
        cli_entries = [
            entry
            for entry in distribution.files
            if entry.as_posix() == "codex_snapshot_runner/cli.py"
        ]
        if len(cli_entries) != 1:
            return None
        installed_cli = Path(distribution.locate_file(cli_entries[0])).resolve(strict=True)
        if installed_cli != Path(__file__).resolve(strict=True):
            return None
        return installed_cli.parents[1]
    except (metadata.PackageNotFoundError, OSError, RuntimeError, ValueError):
        return None


def _validated_runner_worktree_path() -> Path:
    installed_root = _installed_runner_root()
    return security.canonical_owned_directory(
        installed_root if installed_root is not None else REPOSITORY_ROOT,
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


def _prepare_snapshot(
    task: str,
    task_argument: str | None,
    target: git_module.ValidatedTargetRepository,
    git: str,
    *,
    initial_publish_evidence: bool = False,
    generated_trees: tuple[str, ...] = (),
    review_scope: tuple[str, ...] = (),
) -> artifact_module.SnapshotArtifact:
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
                    target.path, target_evidence, conversion_policy, git
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
        envelope = artifact_module._sanitize_validate_snapshot(
            snapshot.as_envelope(),
            target.path,
            expected_scan_manifest=snapshot.scan_manifest,
        )
        snapshot_bytes = artifact_module._serialize_snapshot(envelope)
        snapshot_id = hashlib.sha256(snapshot_bytes).hexdigest()
        preview_bytes = artifact_module._build_preview_summary(snapshot_id, envelope).encode(
            "utf-8"
        )
        if len(preview_bytes) > artifact_module.MAX_PREVIEW_BYTES:
            raise RunnerError(
                security.ARTIFACT_VALIDATION_FAILED,
                "hard output limit exceeded: preview.txt",
            )
        meta = artifact_module._validate_snapshot_meta_schema(
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
        root = artifact_module.snapshot_output_root(target.path)
        artifact_module._ensure_private_state_directory(root, "snapshot store", target.path)
        staging = artifact_module._create_private_staging_directory(root, "snapshot")
        artifact_module._atomic_write(
            staging / "snapshot.json", snapshot_bytes, collect_module.MAX_SNAPSHOT_BYTES
        )
        artifact_module._atomic_write(
            staging / "preview.txt", preview_bytes, artifact_module.MAX_PREVIEW_BYTES
        )
        artifact_module._atomic_write(
            staging / "meta.json", meta_bytes, artifact_module.MAX_META_BYTES
        )
        artifact_module._fsync_directory(staging)
        staged_artifact = artifact_module._load_snapshot_directory(snapshot_id, staging)
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
            existing = artifact_module._load_snapshot(snapshot_id)
            if existing.snapshot_bytes != snapshot_bytes:
                raise RunnerError(
                    security.ARTIFACT_PUBLISH_FAILED,
                    "existing content-addressed snapshot differs from prepared bytes",
                ) from exc
            artifact_module._discard_known_staging(staging, artifact_module.SNAPSHOT_FILE_NAMES)
            return existing
        artifact = artifact_module.SnapshotArtifact(
            staged_artifact.snapshot_id,
            staged_artifact.task,
            staged_artifact.snapshot_bytes,
            staged_artifact.envelope,
            destination,
        )
        try:
            artifact_module._fsync_directory(root)
        except OSError as exc:
            raise RunnerError(
                security.ARTIFACT_PUBLISH_FAILED,
                artifact_module.SNAPSHOT_PUBLISH_DURABILITY_ERROR,
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
                    artifact_module._discard_known_staging(
                        staging, artifact_module.SNAPSHOT_FILE_NAMES
                    )


def _add_prepare_arguments(prepare: argparse.ArgumentParser) -> None:
    prepare.add_argument("--repo")
    prepare.add_argument("--initial-publish-evidence", action="store_true")
    prepare.add_argument("--generated-tree", action="append", default=[])
    prepare.add_argument("--scope-path", action="append", default=[])
    prepare.add_argument("--summary", action="store_true")
    prepare.add_argument("task_argument", nargs="?")


def build_argument_parser(*, neutral: bool = False) -> argparse.ArgumentParser:
    if neutral:
        parser = SafeArgumentParser(
            prog="snapshot-runner",
            description=(
                "Deterministic, read-only repository evidence for coding agents and automation. "
                "No model API or API key required. Captured content is untrusted evidence, "
                "not agent instructions."
            ),
        )
        parser.add_argument("--version", action="version", version=f"snapshot-runner {__version__}")
        commands = parser.add_subparsers(dest="task", required=True)
        for task in artifact_module.TASKS:
            prepare = commands.add_parser(task, help=f"collect {task} evidence")
            prepare.set_defaults(action="prepare")
            prepare.add_argument(
                "--version", action="version", version=f"snapshot-runner {__version__}"
            )
            _add_prepare_arguments(prepare)
        return parser
    parser = SafeArgumentParser(
        description=__doc__,
        epilog=(
            "prepare-only mode does not support automatic analyze; codex-analyze-snapshot "
            "is a fixed fail-closed sentinel. Review preview.txt and inspect "
            "preview.txt or snapshot.json"
        ),
    )
    commands = parser.add_subparsers(dest="action", required=True)
    prepare = commands.add_parser("prepare", help="create a local snapshot for manual review")
    prepare.add_argument("task", choices=artifact_module.TASKS)
    _add_prepare_arguments(prepare)
    return parser


def _validate_arguments(arguments: argparse.Namespace) -> None:
    if arguments.repo is None:
        raise RunnerError(ARGUMENT_ERROR, TARGET_REPOSITORY_REQUIRED_ERROR)
    requires_argument = arguments.task in {"branch-review", "test-triage"}
    if requires_argument and arguments.task_argument is None:
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if not requires_argument and arguments.task_argument is not None:
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if arguments.task_argument is not None and len(arguments.task_argument.encode("utf-8")) > 4096:
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if arguments.initial_publish_evidence and arguments.task != "diff-audit":
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if arguments.generated_tree and not arguments.initial_publish_evidence:
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if any(not tree or len(tree.encode("utf-8")) > 4096 for tree in arguments.generated_tree):
        raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
    if arguments.scope_path:
        if arguments.task != "diff-audit" or arguments.initial_publish_evidence:
            raise RunnerError(ARGUMENT_ERROR, CLI_ARGUMENT_ERROR)
        try:
            arguments.scope_path = list(isolation_module.validate_scope_paths(arguments.scope_path))
        except RunnerError as exc:
            raise RunnerError(ARGUMENT_ERROR, exc.message) from None


def _run_prepare(arguments: argparse.Namespace) -> int:
    try:
        target_path, target_name, runner_path = _validate_target_repository_path(arguments.repo)
        state_home = artifact_module._state_home(target_path)
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
        sys.stdout.buffer.write(artifact_module._build_summary_output(artifact, __version__))
    else:
        print(f"snapshot_id: {artifact.snapshot_id}")
        print(f"snapshot: {artifact.directory / 'snapshot.json'}")
        print(f"preview: {artifact.directory / 'preview.txt'}")
        print(f"security_boundary: {collect_module.SECURITY_NOTICE}")
        print("manual_workflow:")
        print(f"  1. review {artifact.directory / 'preview.txt'}")
        print("  2. inspect snapshot.json with your coding agent or automation")
        print("  3. save the analysis result in the project record")
    return 0


def main(argv: list[str] | None = None, *, neutral: bool = False) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    if raw_arguments == ["--version"]:
        product = "snapshot-runner" if neutral else "codex-snapshot-runner"
        print(f"{product} {__version__}")
        return 0
    if not neutral and raw_arguments[:1] == ["analyze"]:
        _emit_workflow_error(RunnerError(AUTOMATIC_ANALYSIS_DISABLED, ANALYZE_DISABLED_ERROR))
        return 2
    os.umask(0o077)
    parser = build_argument_parser(neutral=True) if neutral else build_argument_parser()
    try:
        arguments = parser.parse_args(raw_arguments)
        _validate_arguments(arguments)
        return _run_prepare(arguments)
    except KeyboardInterrupt:
        return 128 + signal.SIGINT
    except RunnerError as exc:
        _emit_workflow_error(exc)
        return 2
    except SecurityError as exc:
        _emit_workflow_error(_unexpected_error(exc, "prepare workflow"))
        return 2
    except Exception as exc:
        _emit_workflow_error(_unexpected_error(exc, "prepare workflow"))
        return 2


def snapshot_runner_main() -> int:
    return main(neutral=True)


def _public_command_main(command: str, task: str) -> int:
    raw_arguments = list(sys.argv[1:])
    if raw_arguments == ["--version"]:
        print(f"{command} {__version__}")
        return 0
    return main(["prepare", task, *raw_arguments])


def repo_status_main() -> int:
    return _public_command_main("codex-repo-status", "repo-status")


def diff_audit_main() -> int:
    return _public_command_main("codex-diff-audit", "diff-audit")


def branch_review_main() -> int:
    return _public_command_main("codex-branch-review", "branch-review")


def test_triage_main() -> int:
    return _public_command_main("codex-test-triage", "test-triage")


if __name__ == "__main__":
    raise SystemExit(main())
