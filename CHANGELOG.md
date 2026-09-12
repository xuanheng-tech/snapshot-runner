# Changelog

This file records public source and package changes. Version 1.4.0 established the
public source baseline; it was not tagged or published to PyPI.

## Unreleased

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
