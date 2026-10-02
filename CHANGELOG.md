# Changelog

This file records public source and package changes. Version 1.4.0 established the
public source baseline; it was not tagged or published to PyPI.

## Unreleased

## 2.5.6 - 2026-10-03

- Release control: recognize premature EOF in declared-length HTTP responses after
  bounded reads and reuse the existing incomplete-response classification and safe GET
  retry. Partial responses are discarded and closed before another attempt. The 8 MiB
  response limit, HTTP framing semantics, write-request boundary and identity checks
  retain their existing behavior. Tests exercise real HTTPResponse parsing with
  in-memory wire data rather than relying only on injected exceptions.

## 2.5.5 - 2026-10-02

- Release control: GET requests without a body retry typed timeouts, connection resets
  and incomplete responses once, including failures while reading the response. Other
  failures and write requests still stop immediately; diagnostics withhold private
  details. PyPI propagation polling retains its missing-document-only contract and
  bounded attempt count, without rebuilding or reuploading original artifacts.

## 2.5.4 - 2026-10-02

- Fixed: branch-review captures complete unified diffs beyond the default 2 MiB Git
  command bound when they fit the shared 8 MiB snapshot quota. A single global rename
  candidate set preserves rename matching and existing patch bytes; metadata and JSON
  escaping consume the same quota, and oversized diffs still refuse publication.
- Release control: validate selected release notes against the receipt's 1–8192 character
  bound before building or writing artifacts, receipts or workflow outputs. Empty note
  overrides retain the source changelog fallback.

## 2.5.3 - 2026-10-02

- Fixed: README contract and artifact declarations match the current producer security
  epoch 5. Contract tests compare the documented current schema versions and epoch
  with runtime declarations; historical epoch-4 compatibility remains unchanged.
- Internal: share context-path count limits across ordinary text, extensionless text
  and raster-image evidence, and combine identical prepared branch-context handling.
  Path order, quotas, gap wording and canonical snapshot bytes remain unchanged.

## 2.5.2 - 2026-10-02

- Fixed: bounded worktree and Git-blob file context preserves complete UTF-8 characters
  when a size cut lands inside a character, rather than refusing the entire valid file.
  Omitted-byte counts include the incomplete character; malformed retained text and
  unsafe secret boundaries remain refused.
- Development and release control: explicitly validate and extract the original sdist
  outside Git, check required source/build/license files and package identity, and build
  a separate PEP 517 test wheel without local source overrides. Run the installed-command
  and read-only acceptance checks on both wheels across all supported Python minors.
  Acceptance preserves both original artifact hashes and gates the receipt and upload.
- Development: check installed wheels in isolated environments outside the source checkout
  on Python 3.12, 3.13 and 3.14 in both CI providers. Exercise all public commands and
  evidence reads, and verify that target repository bytes and modes remain unchanged.
- Release control: test the original built wheel before creating its source-bound receipt
  or allowing upload. Classify HTTP and typed network failures with safe recovery guidance;
  a bare 403 remains an unknown forbidden cause. Verified identity conflicts have a
  separate error type and original-receipt recovery guidance.

## 2.5.1 - 2026-10-01

- Fixed: each collection command's help lists only its supported flags. `branch-review`
  shows the required `BASE`, and `test-triage` shows the required `TEST_LOG`.
- Fixed: argument errors include static usage or constraint guidance while keeping the
  bounded single-line error format and withholding user-supplied argument values.
- Compatibility: valid primary and legacy `prepare` invocations retain their evidence
  behavior and read-only boundary; public CLI and artifact schema versions are unchanged.

## 2.5.0 - 2026-10-01

- Changed: scoped review clones initialize the baseline index without expanding unrelated
  worktree files. Selected index and worktree copies share a 16 MiB quota, and conversion
  metadata stays inside the exact review scope; baseline attribute and ignore rules remain active.
- Compatibility: source installation accepts CPython 3.13 and 3.14 as well as the existing
  3.12 baseline. GitHub and Gitea quality jobs check all three supported minors.
- Fixed: workspace diff batches and recursive splits enforce the shared JSON-encoded content
  budget before retaining more evidence; staged content is charged before unstaged capture.
- Fixed: Git status and diff output use stable formats regardless of repository display settings.
  Preview and JSON summary share status/diff counters; truncated records cannot crash preview,
  and hunk lines starting with `+++` or `---` are counted as content.
- Fixed: bounded CSV and `.gitattributes` diffs validate the actual Git/worktree versions,
  including deletions and sealed branch reviews; unsafe versions remain refused.
- Changed: repository-status accepts YAML metadata without reading bodies. Generated-tree
  traversal stops at file, directory and depth quotas, including ignored entries.
  Scoped review clones omit unrelated branch histories.
- Added: Unicode and space-containing repository directories use portable artifact display
  names. Common C/C++, Go, Rust, Java, Kotlin, Swift, Ruby and C# source suffixes are text
  under producer epoch 5; epoch-4 artifacts keep their frozen sanitizer rules and format.
- Development: regenerate the lockfile against public PyPI and check that index explicitly.
  Document the fixed system-Git boundary and contributor/security reporting workflow.
  Check CLI and summary versions against package metadata instead of pinned version literals.
- Internal: share the existing Runner source root between CLI and store validation, and keep
  read-only boundary guards scanning every package module, including absolute `from` imports.
- Release control: identify the failing Git operation without echoing arguments or diagnostics.
  Retry only transient reads of the public GitHub repository, at most three attempts with a
  60-second timeout each; permissions, identity conflicts and pushes stop immediately.

## 2.4.1 - 2026-09-29

- Fixed: test-log capture sanitizes the complete bounded input before retaining a UTF-8-safe
  head and tail. The scan limit is 16 MiB and the retained-text limit remains 2 MiB; unsafe or
  oversized input is refused, and redaction counts cover the scanned input.
- Fixed: truncated Git output with an unsafe sensitive-text boundary is withheld with an
  explicit evidence gap instead of publishing a credential fragment.
- Fixed: unresolved merges accept Git's empty default merge mode. Unmerged paths retain working-tree
  context and a dedicated gap while ordinary staged and unstaged paths still receive unified diffs.
- Changed: format 2 structural validators, read budgets and sanitizer rule data are independently
  pinned. The era guard checks every package module, including imported aliases and qualified names.
  Stored artifact schemas and declared scan versions are unchanged.
- Fixed: an internal validation TypeError fails closed without retrying validation with fewer arguments.
- Fixed: active-operation metadata reads reject symlink races and handle short reads; annotated release
  tags require exact headers. Local Qoder session data is ignored during isolated Git audits.

## 2.4.0 - 2026-09-29

- Added: a version-pinned artifact verifier registry (`snapshot_runner/verifiers.py`). Reading a stored snapshot
  now resolves its rules and declarations from the versions the snapshot declares in its own `meta.json`
  rather than the installed release, and an unregistered pair is refused before the bytes are hashed or
  sanitized. Each era carries its own `security.SanitizerRules`
  literals (`SCAN_RULES_V2`) instead of aliasing the live `CURRENT_RULES`; the registry compares the two
  by value and `resolve_verifier` refuses to write while they differ, so a tightened rule cannot stamp a
  new artifact with this release's declarations while scanning it with the previous ones. Measured: one added
  token pattern with no era registered stops writes and leaves stored artifacts readable, where the same
  edit against aliased rules orphaned ten with a green suite; raising `SCAN_CLASSIFIER_VERSION` used to
  refuse all 559 at once.
- Preserved: pinning is rule data, not identity. The snapshot id must still equal the SHA-256 of the
  stored bytes, `meta.json` must still serialize canonically, the directory must still hold exactly the
  three published names at mode `0600` inside a `0700` tree with no symlink ancestor, and the sanitizer
  still runs on every read. Structural tables and inline sanitizer literals remain release-relative.
- Fixed: one file whose body cannot be sanitized no longer costs the whole snapshot. Such a body aborted `prepare`
  and published nothing at all: no diff, no status, no other context. It is now
  one `file_refused` gap naming that path, its body dropped whole with no prefix or excerpt and
  `omitted_bytes` reporting its size, while everything else publishes. Where the body was also cut by the
  read budget the two losses stay separately counted and partition the file exactly: `file_limit` for
  bytes never read, `file_refused` for bytes read then dropped. Body refusals are kept ahead of the
  `MAX_EVIDENCE_GAPS` cap, because branch review records per-file diff refusals before reading
  any blob, and enough of them would otherwise bury the dropped bodies.
- Changed: gap reasons use a controlled vocabulary instead of quoting the sanitizer's own sentence, which measurement
  forced: that message is itself matched by the bearer pattern, so quoting it would publish
  `residual Bearer [REDACTED_BEARER]` as the explanation. One mapping is now both the allow-list and the
  reason text, so an allowed message cannot become an unexpected `KeyError` mid-collection, and every
  refusal outside that six-message list still aborts the run -- unified diff, `status_short`, YAML and
  sensitive-path classification, generated-tree member scanning.
- Fixed: a wide changeset of non-ASCII or quoted paths no longer prevents a `diff-audit` snapshot from
  existing. Git writes one non-ASCII path byte as four (`-c core.quotePath=true`) and the whole-tree
  command was charged against a 2 MiB budget *after* that escaping: 8 000 staged paths measured
  1 672 000 raw bytes as 2 536 000 escaped and were refused, publishing nothing. Both directions now go through
  bounded path batches, halving a batch that still overruns the bound. Measured A/B against the
  previous code: identical snapshot ids and `snapshot.json` bytes across scratch trees. A diff that cannot fit alongside the rest of the evidence is still cut at a raw
  byte offset and refuses, as before.
- Fixed: a private key that the read budget cut in half no longer reaches a `file_context` as ordinary
  text. Both file-context readers cut a body to its budget and handed *only the retained prefix* to the
  sanitizer, while the private-key rule refuses only a block it can see closed. Measured on the parent: a
  379 270-byte file whose `-----BEGIN OPENSSH PRIVATE KEY-----` opened at offset 240 000 published its
  whole 262 144-byte prefix with **22 108 bytes of key body**, and the same shape published 17 characters of a
  `ghp_` token and 5 of a bearer value under a benign `file_limit` gap. `security.truncated_secret_boundary()` now interrogates the prefix the reader is about to
  hand on -- a private-key opener with no closer in it, counted per label, or a credential run reaching
  the last retained byte -- and the body is withheld **whole** as one `file_refused` gap at the file's
  full size (379 270 / 262 189 / 262 158 measured; markers absent from all three stored files).
  No budget was widened and nothing bypassed: widening it only moves the cut. The credential rule tests
  *reach*, not length, because `AKIA`/`ASIA` are a fixed 16 characters behind a word boundary and a
  never-terminated 20-character run measured `redactions: {}` with the raw slice published. Withholding
  has a price, recorded here: a 262 333-byte file whose prefix carried three complete redactable tokens
  published 262 093 characters and `GITHUB_TOKEN: 3` before, and 0 characters with `redactions: {}` now.
- Fixed: that check costs one strip and one bounded scan rather than a backtracking pass per marker
  candidate. A single expression combining a marker, an unbounded character run and an end anchor took
  27 s to answer `None` on a 300 201-character prefix holding 60 000 `=AKIA` candidates and 170 s at
  750 201, while the sanitizer over the same bytes needs 0.03 s , and one prepare asks up to 64 times over audited files. The rewrite answers a 4 000 201-character, 800 000-candidate
  prefix in 0.015 s, and is held against the expression it replaced: over 16 544 generated inputs per
  seed the two disagree 63 times, every one toward withholding, none toward publishing.
- Fixed: a file context is read until the budget is actually reached. One `os.read` was trusted to return
  the whole budget, and POSIX leaves it free to hand back less, so a short read published a partial body
  as if complete, since `truncated` came from the file's size, not what the reader obtained: a
  330 000-byte file with reads capped at 4 096 published 4 096 bytes while its gap claimed 67 856,
  leaving 325 904 bytes unaccounted, and an 111 036-byte body straddling a key published 86 507 bytes
  with not one evidence gap. The reader now loops, refuses when the delivered bytes disagree with the size
  it stat'ed, and counts what it actually held.
- Boundary that remains, each measured identically on the parent and none introduced here: `test-triage`
  logs keep a head and a tail and drop the middle, so a 2 940 072-byte log published 1 311 copies of a
  37-byte key line under a lone `test_log_limit` gap; truncated `git log --oneline` output tolerates the
  2 MiB bound and published 58 226 key-line copies across 2 097 152 characters of `recent_commits`; an uncut body that opens a block without closing it is published, because
  the rule keys on a visible closer; labels the PEM expression does not know (PGP, 597 copies across a cut), base64 with no envelope (2 000 copies) and a credential glued to a preceding
  word character are invisible to both rules; a credential the file split with a newline is missed by the
  patterns; and a diff hunk showing only interior key lines carries them as context: 8 copies in a
  493-character hunk of the same path whose body was withheld. The unified diff cannot straddle:
  truncated diff evidence is refused outright.
- No artifact schema, meta schema, security epoch, scan classifier version, `contract_version` or CLI
  surface change, and no migration: it adds no command, flag, format choice or precondition and stores no field. Every artifact in the project's store at release-prep (695, a growing count)
  loaded under both codes with unchanged bytes and a matching snapshot id, no read wrote to the store,
  and tampering is still refused. The suite stands at 748 passing, 48 in
  `tests/test_truncated_secret_boundary.py` and 23 in `tests/test_file_context_fail_soft.py`.

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
