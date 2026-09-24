# Changelog

This file records public source and package changes. Version 1.4.0 established the
public source baseline; it was not tagged or published to PyPI.

## Unreleased

## 2.3.1 - 2026-09-24

- Fixed: absolute-path and `file://` redaction no longer consumes the backslash of a following
  quote escape, which previously downgraded an escaped quote to a bare one and corrupted captured
  nested JSON bodies (stored `.json`/`.jsonl` evidence that no longer parses). A path match may
  still cross interior backslashes — they stay fully redacted — but ends at an escape sequence
  exactly as it ends at a bare quote; the `<ABS_PATH:…>` / `[REDACTED_FILE_URI]` forms, the
  credential gates and every refusal gate are otherwise unchanged.
- Fixed: `redactions["ABSOLUTE_PATH"]` counts only genuine replacement events (generic-path
  markers and explicit out-of-repository path substitutions). Deterministic removal of the
  repository's own root prefix is relativization of in-repo paths and no longer inflates the
  security-redaction count, so the counter reconciles with the placeholders actually emitted.
- Preserve: previously published snapshots are unchanged and remain readable; a body captured
  with the old escaping behaviour is transported verbatim by `read` index/field/path selectors.

## 2.3.0 - 2026-09-23

- Changed: `summary.next_action` is now derived from the evidence actually available instead of
  from "there is something to review". `open_artifact` is kept for genuinely whole-artifact
  cases — incomplete evidence, any recorded evidence gap, a mid-flight Git operation, or a
  collected test log — while complete evidence that only awaits review now reports
  `read_targeted`, pointing the reviewer at the existing `read --path`/`--field` selectors
  rather than at the entire `snapshot.json`. `continue` still means nothing needs review.
  `snapshot_id` and the artifact path stay in every summary, so no recommendation removes
  access to evidence and no gap is downgraded. This is marked by
  `summary_schema_version` **2**; stored snapshots, `contract_version` and the canonical
  artifact layer are unchanged.
- Fixed: `.mjs`, `.cjs`, `.mts` and `.cts` sources are now collected as bounded text evidence
  instead of producing a `file_refused` evidence gap; `.js`, `.jsx`, `.ts` and `.tsx` were
  already accepted. Sensitive-path, NUL/binary, UTF-8, size and safe-open checks still apply
  unchanged, and the scan-mode classifier semantics are untouched, so
  `SCAN_CLASSIFIER_VERSION` and previously published artifacts are unaffected.

## 2.2.0 - 2026-09-22

- Added: the `read` subcommand for on-demand evidence from an existing content-addressed
  snapshot, so callers no longer consume the whole `snapshot.json` after a summary points to
  it: `snapshot-runner read <snapshot-id> --repo <path>` prints a bounded evidence index,
  `--field <name>` prints one snapshot data field verbatim, and `--path <relative-path>`
  prints the evidence attributed to one file (file context, diff sections with rename-aware
  attribution, deleted-file metadata, conversion and initial-publication records, and gaps).
  Evidence reads use a new `evidence_schema_version` 1 single-line JSON output that repeats
  the snapshot's trust boundary and security notice. Adding the reader moves the public CLI
  contract to `contract_version` 3.
- Security: `read` re-validates the artifact through the existing canonical loader, never
  executes Git or any repository operation, never re-collects or rebuilds evidence, requires an
  explicit validated absolute `--repo`, refuses artifacts whose repository name does not match
  the validated target, and fails closed with exit code 2 (`ARTIFACT_NOT_FOUND`,
  `ARGUMENT_ERROR`, or `ARTIFACT_VALIDATION_FAILED`).
- Fixed: reading a snapshot no longer depends on the current worktree. The canonical loader
  and `--path` attribution skip the live content probe for `.csv`/`.gitattributes` diff paths,
  so evidence stays readable after those files are deleted or moved; capture-time validation,
  the scan-mode classification and the content-hash canonical invariant are unchanged, so a
  tampered or malformed artifact still fails closed.

## 2.1.0

- Added: structured active Git operation detection in `repo-status` (`active_operation`).
  Detects merge, cherry-pick, revert, rebase (`rebase-merge` and `rebase-apply`),
  bisect, and am states using Git metadata without executing repository-controlled
  code or mutating repository state.
- Changed: repositories with an active Git operation now trigger `open_artifact: true`
  and an `active_operation: <type>` line in human-readable and JSON summaries,
  ensuring downstream reviewers are immediately alerted.
- Security: enforces bounded reads, strict file type and permission checks, and
  fails closed with exit code 2 on ambiguous, conflicting, symlinked, or malformed
  operation metadata.

## 2.0.2

- Fixed: `_ACTIVE_REPOSITORY_ROOT` ContextVar lifecycle is now strictly guarded
  by a context manager, guaranteeing reset on every success/failure path. Staged
  and existing snapshot artifact loading explicitly propagates `repository_root`.
- Fixed: strict artifact schema validation now consistently rejects unknown
  task-data fields regardless of value type (`int`, `bool`, `None`, list, dict,
  string, etc.).
- Fixed: isolated bounded-diff security regressions to a temporary repository,
  avoiding writing fixed temporary files to the source root.

## 2.0.1

- Fixed: `_validate_bounded_diff_text` no longer bypasses bounded diff file
  validation when executed against the Snapshot Runner repository itself. Symlink,
  size, safe-open, binary, and UTF-8 checks now apply uniformly across all
  target repositories.

## 2.0.0

Provider-neutral naming. This release removes public interfaces; read the migration notes.

- **Removed (breaking):** the four provider-named console scripts `codex-repo-status`,
  `codex-diff-audit`, `codex-branch-review` and `codex-test-triage`, and their
  `codex_snapshot_runner.cli` entrypoint functions. Use `snapshot-runner <command>`:
  `repo-status`, `diff-audit`, `branch-review`, `test-triage`. The primary command, its
  options, exit codes, JSON summaries and canonical artifacts are unchanged.
- **Changed (breaking):** the Python import name is now `snapshot_runner`. The previous
  `codex_snapshot_runner` module is gone; no compatibility shim is shipped.
- **Changed (breaking):** artifacts are published under
  `$XDG_STATE_HOME/snapshot-runner/snapshots/<snapshot-id>/` instead of
  `codex-exec/snapshots/`. Artifacts already written under the old namespace are not moved
  or read; they remain on disk and can be inspected directly.
- **Changed (breaking):** the scoped-audit temporary namespace is now
  `/tmp/snapshot-runner-<uid>/` instead of `/tmp/codex-snapshot-runner-<uid>/`.
- Changed: the public CLI contract is `contract_version` 2. Commands are named by
  subcommand, `primary_command.subcommands` is a plain list, and `command_invocation`
  records `snapshot-runner <command>`. No compatibility-alias descriptors remain.
- Changed: help text, the analyze fail-closed sentinel description, the `just` recipe names
  and the documentation no longer name any specific coding agent or vendor.
- Preserved: snapshot schema **2**, summary schema **1**, security epoch **4**, determinism,
  read-only guarantees, YAML fail-closed handling, path/symlink/secret protections, bounded
  limits and every refusal semantic. `OPENAI_TOKEN`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY` and
  `GOOGLE_API_KEY` remain redaction-category labels naming the credential types they match.


## 1.6.1

- Fixed: A `config.worktree` file that cannot carry any setting no longer blocks Git
  capability preflight. Git reads that file only when `extensions.worktreeConfig` is
  enabled, and an absent or zero-byte ordinary file carries nothing under either state,
  so only that positively provable shape is treated as inert. Any content, a symlink, a
  directory, a special file, or a path that cannot be inspected still fails closed,
  because content would become live the moment the extension were enabled. Git itself
  leaves the empty form behind: setting a `--worktree` key and unsetting it truncates
  the file rather than removing it, and disabling the extension afterwards leaves it in
  place, so ordinary repositories accumulate inert residue that previously refused all
  read-only evidence collection.
- Changed: Release-record closure (`record`, `verify`, and the Gitea closure route) now
  waits out normal PyPI propagation with a bounded retry (12 attempts, 15 s apart) instead
  of failing the moment a just-published version is not yet visible. Build and
  pending-upload paths still read PyPI once. Only a missing document is retried; identity
  conflicts and other API errors still fail closed immediately.

## 1.6.0

- Fixed: Exact-path (`--scope-path`) diff audits now reproduce the source index as well as
  the source worktree, so `staged`, `unstaged`, `status_short`, and the staged/unstaged
  diffs match the real repository state. Previously every scoped change was reported as an
  unstaged worktree modification, and a staged change whose worktree matched HEAD was
  refused as unchanged.
- Fixed: Unified-diff header path classification no longer grows quadratically with the
  number of `" b/"` sequences in a path name. Candidate expansion now has a hard bound
  (`MAX_DIFF_PATH_CANDIDATES`, 128) and fails closed above it, and sensitive-component
  detection no longer constructs a path object per component. Collection of a hostile
  1441-occurrence path header went from 36.0 s to 0.16 s.
- Changed: Scoped audits accept the staged-deletion-plus-untracked state, which Git
  reports as two porcelain entries for one path; every other multi-entry shape stays
  refused as ambiguous.
- Changed: Scoped audits fail closed on unmerged (conflicted) index entries and on index
  entries that are not regular non-symlink blobs.
- Changed: The `codex-*` aliases and the legacy Python module command now print the same
  vendor-neutral guidance as `snapshot-runner`. Exit codes, JSON summaries, canonical
  artifacts, and the public CLI contract are unchanged.
- Preserved: Snapshot schema 2, summary schema 1, security epoch 4, YAML fail-closed
  handling, path/symlink/secret protections, and read-only guarantees.

## 1.5.0

- Changed: Vendor-neutral product and distribution identity: Snapshot Runner / `snapshot-runner`.
- Added: The `snapshot-runner` command with `repo-status`, `diff-audit`, `branch-review`,
  and `test-triage` subcommands, sharing the existing collectors and validation.
- Preserved: All four `codex-*` command aliases, their output/error behavior, the Python
  import name, the existing state/artifact paths, snapshot schema 2, and security epoch 4.
- Changed: The main command's human-readable guidance now addresses coding agents and
  automation. Existing aliases retain their historical guidance for compatibility.
- Changed: Installation and release automation use the new distribution name and 1.5.0
  version. No model API, API key, SDK, or agent-specific integration is required.

## 1.4.0

- Public source baseline of the mature prepare-only Snapshot Runner core under Apache-2.0.
- Four stable commands collect local repository status, staged/unstaged changes,
  sealed branch-review evidence, and bounded existing test logs.
- Supports unborn and linked worktrees, exact-path scoped diff audits, initial
  publication evidence, and bounded deterministic JSON summaries.
- Preserves snapshot schema 2, security epoch 4, private atomic artifacts, SHA-256
  verification, and explicit absolute repository boundaries.
- Standard-library-only runtime with isolated wheel/sdist installation.
- Shared quality checks; GitHub-only package builds and approved PyPI Trusted Publishing;
  matching GitHub/Gitea annotated tag identities and resumable Release records.
