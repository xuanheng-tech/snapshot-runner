# Changelog

This file records public source and package changes. Version 1.4.0 established the
public source baseline; it was not tagged or published to PyPI.

## Unreleased

- Fixed: a wide changeset of non-ASCII or quoted paths no longer prevents a `diff-audit` snapshot
  from existing. Git is queried with `-c core.quotePath=true`, which writes one non-ASCII path byte
  as four (`\346`), and `collect_diff_audit` asked for each workspace direction in a single
  whole-tree `git diff … --` command whenever no path had to be routed away from the diff. One
  command may return at most `MAX_GIT_OUTPUT_BYTES` (2 MiB) and that budget is charged *after* the
  escaping, so a large enough path set crosses it on its own headers: on one scratch tree 8,000
  staged `q"uote's/目录_*.py` files measured 1,672,000 raw bytes as 2,536,000 escaped, and
  `_decode_unified_diff` refused the run with `truncated unified diff evidence was refused`,
  publishing nothing. Both directions now always go through `_bounded_path_batches` — at most 256
  paths and 32 KiB of path bytes per command, already shared with conversion attribute inspection —
  and one `:(top,literal)` pathspec diff per batch, concatenated in the order Git reported the
  paths, which is the route `diff-audit` already took whenever a path had been routed away. Scratch
  trees that publish now, each holding its complete diff: 300 paths / 1,503,600 bytes, 4,000 paths
  / 3,964,000 bytes, 8,000 paths / 2,864,000 bytes, and 3,015,000 staged together with 3,015,000
  unstaged.
- A batch whose escaped bodies still overrun the per-command bound is halved and retried in place,
  so the command count follows the diff and not only the path count: 257 CJK paths carrying
  2,828,653 escaped bytes are admitted as three bounded commands after one 256-path command
  overruns. Division stops at a single path, where halving cannot help and the pre-existing refusal
  still applies, and it stops once the collected diff has grown past `SNAPSHOT_CONTENT_BUDGET`,
  since the artifact could not carry the rest. On a 15,448,000-byte tree that second stop holds
  peak resident memory at 44 MiB rather than 165 MiB and returns in 0.4 s rather than 3.7 s, with
  the same `truncated unified diff evidence was refused` diagnostic 2.3.2 produced.
- No evidence content, schema, `summary_schema_version`, `contract_version`, classifier version or
  canonical serialization changed, and batching is not a re-rendering: for a diff that fits, the
  batches only re-partition the same path set, so their concatenation is the byte stream one
  whole-tree command would have produced. Measured with a scratch A/B harness against the
  pre-change code — `diff-audit` artifacts identical in snapshot ID and `snapshot.json` bytes for
  seven trees (including a 303-path repository spanning two batches, 480,034 B) and `repo-status`
  identical for all eight (empty, unborn, clean, typechange, gitlink, backslash and tab in name,
  quote-heavy, conflicted); the conflicted tree refused `diff-audit` identically on both sides for
  a pre-existing sanitization reason. `tests/test_workspace_diff_batching.py` asserts the same
  equality from the artifact side: `staged_diff` and `unstaged_diff` each equal the single whole-tree
  `git diff` their own reference command produces. Other artifact fields are not compared by that
  test. `branch-review` still collects its range diff in one command and `git status --short` still
  reports an over-bound command as a `git_output_limit` evidence gap rather than a refusal; neither
  route changed, and wide changesets now simply issue more small Git commands.
- Ceiling of this fix, stated because collecting large diffs at all makes it visible: a workspace
  diff that does not fit alongside the rest of the evidence is still cut at a raw byte offset by
  `add_text`, and a cut landing inside a diff header pair makes `finish()` refuse the snapshot with
  `snapshot builder invariant failed closed` (one 20,000-path tree whose staged diff measured
  7,160,000 bytes — below `SNAPSHOT_CONTENT_BUDGET` on its own — fails this way because of the
  evidence collected around it). That truncation behaviour belongs to the budget mechanism, not to
  batching: the same `add_text`-then-`finish()` sequence refuses identically on 2.3.2, where such
  a repository never reached it because its whole-tree command was refused for truncating first.
  Either way no artifact was published before or is published now. Aligning that cut to a complete
  diff entry is separate work.
- Added: a version-pinned artifact verifier registry, `snapshot_runner/verifiers.py`. Reading a
  stored snapshot now resolves the rules it was written under from the versions that snapshot
  declares in its own `meta.json` (`schema_version` and `producer_security_epoch`) instead of
  comparing them against the constants of whichever release happens to be running. The row supplies
  `trust_boundary`, `security_notice`, the scan classifier version and both schema versions, and an
  unregistered version is refused with `ARTIFACT_PUBLISH_FAILED` and
  `snapshot declares an unsupported artifact version` before the snapshot bytes are hashed,
  sanitized or trusted. Nothing was migrated and no artifact was rewritten: the one era in
  existence -- schema 2, meta schema 2, epoch 4, classifier 2, declared by all 549 snapshots in this
  machine's private store -- is registered as `CURRENT_VERIFIER` with its declarations copied as
  literals, so every one of those 549 still loads with an identical re-derived envelope, measured by
  loading each artifact under the previous code and the current one.
- Changed: the reversed half of that guarantee. `test_snapshot_reload_rejects_scan_classifier_version_drift`
  asserted that raising `SCAN_CLASSIFIER_VERSION` makes a stored snapshot unreadable, and it was
  true: with the constant bumped to 3, four sampled real artifacts each failed with
  `snapshot scan classifier invariant failed`, and editing only the notice text that embeds that
  version failed the same four with `snapshot threat-model declarations are invalid`, because
  `security_notice` is compared literally while `SECURITY_NOTICE` interpolates the classifier
  version. The same bump now leaves those reads intact, which is what makes a future classifier
  change possible without orphaning the store. Refusal is kept where it belongs: an era the
  sanitizer will not run at all is still refused, an unregistered version is refused, and
  `tests/test_verifier_registry.py` pins that `CURRENT_VERIFIER` still equals what this release
  writes, so a bump must register the era it replaces instead of silently reinterpreting history.
- Boundary of this change, stated because it is not the whole problem: the registry pins
  *declarations*, not the sanitizer. Current redaction rules still run over historical bodies, so a
  newly added token pattern that matches text an old artifact already contains makes that artifact
  fail its canonical re-serialization -- measured as two of four sampled artifacts refusing with
  `snapshot hash or canonical artifact validation failed` after one extra pattern was registered.
  Pinning the pattern set, the task tables and the budget limits per era is the remaining work, and
  whether a stricter current rule *should* keep old artifacts readable is a product decision about
  secret exposure, not something this entry decides.

## 2.3.2 - 2026-09-25

- Fixed: a repository-relative path that the redactor rewrites no longer destroys the whole
  snapshot. `ABSOLUTE_PATH_RE` anchors on any `/` that does not follow a word character, so an
  ordinary directory ending in punctuation or a space (`docs/foo(bar)/notes.md`,
  `my dir (1)/leaf.py`, `notes!/x.py`, `文档（新）/a.py`, `a/b!/c/long.py`) was redacted as if it were
  absolute; the credential rules do the same to a token-shaped segment. `_append_context` stored
  such a path verbatim while `SnapshotBuilder.finish` re-sanitises every field and refuses on any
  change, so one such file ended `prepare` with
  `SNAPSHOT_COLLECTION_FAILED: snapshot builder data changed during final sanitization` and left no
  artifact. `_append_context` now refuses only the affected file — a `file_refused` evidence gap,
  after the existing classifier so every prior refusal still fires first and no unsanitised name
  enters a gap subject — while every other file, diff and status keeps its evidence and the snapshot
  publishes (`status: partial`, `evidence_gap: true`, `next_action: open_artifact`). The guard is
  strictly additive: before it, any repository that reached this point produced no artifact at all,
  so no collected body was lost to it. No field, schema, `summary_schema_version`,
  `contract_version`, classifier version or canonical serialization changed, so artifacts published
  by 2.3.x keep reading byte-for-byte.
- Boundary of that fix, measured rather than assumed: a tracked file under a rewritten path stays
  selectable, because the unified-diff channel keeps its real `a/…`/`b/…` headers and
  `read --path docs(x)/notes.md` still reports `found: true` with its diff section; an *untracked*
  file under such a path has no diff channel, so after this fix its refusal is visible through the
  evidence index and `--summary` while `read --path` for it returns `found: false`. The
  `--initial-publish-evidence` route is untouched by this change and still fails closed on a
  rewritten path (`publication evidence requires a stable regular file`, no artifact published, now
  pinned by a test): its records are read back from disk by name, so a redacted name cannot
  round-trip, and publication completeness is deliberately not weakened here. The same holds for
  `--generated-tree`, whose manifest is validated before any context is collected.

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
