# Changelog

This file records public source and package changes. Version 1.4.0 established the
public source baseline; it was not tagged or published to PyPI.

## Unreleased

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
