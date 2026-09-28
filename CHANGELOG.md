# Changelog

This file records public source and package changes. Version 1.4.0 established the
public source baseline; it was not tagged or published to PyPI.

## Unreleased

- Fixed: one file whose body cannot be sanitized no longer costs the whole snapshot. A
  `file_context` body that the sanitizer cannot prove safe -- a pasted private key block, a
  byte-order mark outside the start of the text, or a credential that survived redaction -- aborted
  `prepare` outright. Measured on a scratch repository holding two healthy evidence files
  plus one untracked `key.txt` containing an OpenSSH key: 2.3.2 refused with
  `unable to sanitize file context; prepare refused` and published **nothing at all** -- no diff, no
  `status_short`, no other file context. It now records one `file_refused` gap naming that path,
  drops that body completely with no prefix or excerpt, reports its size in `omitted_bytes`, and
  publishes everything else; `truncated` becomes `true` as it does for any gap. The refused text
  appears nowhere in the artifact, and the drop is not counted as a redaction, so
  `redactions` stays `{}` rather than inflating.
- Fixed: three things an independent review found in the change above. A body that was also
  truncated by the per-file read cap reported one number and lost the other: the refusal returned
  before the `file_limit` gap was written, so a 360 095-byte file whose first 256 KiB held an
  unusable key said `omitted_bytes: 262144` and stayed silent about the 97 951 bytes the reader
  never returned.
  The two are now recorded separately and partition the file exactly, because folding them would
  overstate one and hide the other. Body refusals could also be evicted by the existing
  `MAX_EVIDENCE_GAPS` cap -- branch review records its per-file diff refusals *before* it reads any
  blob, so a run with enough of them buried the fact that bodies had been dropped and published
  evidence that looked complete while files had quietly vanished -- and `Snapshot._gaps_within_cap`
  now keeps them first, filling the remaining slots in recording order. And the allow-list and the
  reason table were two structures free to drift: an allowed message with no reason turns the
  intended refusal into `RUNNER_UNEXPECTED_ERROR: unexpected KeyError during snapshot collection`,
  so one mapping is now both, and a test asserts every reason survives the sanitizer that publishes
  it. The two routes sharing the helper were untested -- a mutant special-casing either one kept all
  the whole suite green -- and are covered now: the versioned extensionless route, and branch review's blob
  route, where a mode-only change carries no content lines at all and still refuses exactly one file.
- Preserved: every refusal that is not about one body's text. The fail-soft is an explicit allow-list
  of the six messages reachable from a plain-text file body -- every file context is classified
  `PLAIN_TEXT`, so no unified-diff grammar refusal can reach it -- and anything outside that list
  still aborts the run, because such a failure says the artifact's shape is wrong, not that one file
  was unsafe. Measured consequences of that boundary: the unified-diff, `status_short` and other
  top-level fields still go through `add_text` unchanged, so a repository whose *diff* carries the
  same private key block still publishes nothing (`unable to sanitize unstaged-diff`, store
  unchanged); generated-tree member scanning still refuses; `yaml_content_refused` still refuses the
  run; and a sensitive path such as `secret.pem` keeps its existing `sensitive or unsupported file
  type refused` gap. `read --path` needed no change and behaves exactly as it does for every other
  `file_refused` gap: the path is `found`, its `file_context` is empty, and the gap carries the
  reason.
- Changed: a gap reason is written in a controlled vocabulary instead of quoting the sanitizer's own
  sentence. This was forced by measurement rather than taste -- the message `text contains a residual
  bearer credential` is itself matched by the bearer pattern, so the case-insensitive
  `\bBearer\s+[A-Za-z0-9._~+/=-]{8,}` redacted the reason on its way into the artifact and would
  have published `residual Bearer [REDACTED_BEARER]` as the explanation a reviewer is supposed to
  read. The stored reason is now asserted as it comes back out of the artifact, not as it was built.
- No artifact schema, security epoch, contract version or CLI surface change: `file_refused` and the
  `evidence_gaps` entry shape already existed, and every artifact already published on this machine still
  reads (a growing count, deliberately not quoted as a constant). The suite stood at 700 passing when
  that landed, 23 of them in `tests/test_file_context_fail_soft.py`.

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
  sanitized or trusted. Nothing was migrated and no artifact was rewritten: one era exists today --
  schema 2, meta schema 2, epoch 4, classifier 2 -- and a census of this machine's private store
  found every one of its directories declaring exactly that tuple, with the three published file
  names, mode `0600` and a self-consistent hash. The full-store measurement is given once, in the
  next-but-one entry.
- Changed: the reversed half of that guarantee. The test that stood here before,
  `test_snapshot_reload_rejects_scan_classifier_version_drift`, asserted that raising
  `SCAN_CLASSIFIER_VERSION` makes a stored snapshot unreadable, and the store-wide effect was real:
  bumping the version to 3 on a released tree refused **all 559** artifacts, because `SECURITY_NOTICE`
  interpolates the classifier version, `security_notice` is compared literally, and that comparison
  runs before the scan manifest is ever built -- so every read failed with `snapshot threat-model
  declarations are invalid`, not with a classifier error. (The classifier invariant is the reason only
  when the two are perturbed separately, which is what that old test did by patching one module's
  copy; the wording here said "four sampled artifacts failed with the classifier invariant" and that
  was not a measurement any release path produces.) The same bump now leaves those reads intact,
  which is what makes a future classifier change possible without orphaning the store. Refusal is kept
  where it belongs: an era the sanitizer will not run at all is still refused, an unregistered version
  is refused before the snapshot bytes are hashed or sanitized (at the module boundary as
  `ARTIFACT_PUBLISH_FAILED`; the `read` route re-maps it to `ARTIFACT_VALIDATION_FAILED` as it does
  for other artifact refusals), and `tests/test_verifier_registry.py` pins that `CURRENT_VERIFIER`
  still equals what this release writes, so a bump must register the era it replaces instead of
  silently reinterpreting history.
- Added: the era now pins the sanitizer as well as the declarations. Each registered era carries a
  `security.SanitizerRules` -- the token patterns, the authorization/bearer/PEM/file-URI and
  absolute-path expressions, the sensitive suffix and exact-name sets, the text-eligibility and YAML
  refusal sets, the raster image types and their evidence grammar, the recursion, element and
  diff-path candidate limits, and the classifier version that goes with those values. `CURRENT_RULES`
  reads the live constants, while `SCAN_RULES_V2` holds the era-4 values as its own literals: the two
  are deliberately *not* one object, because an era that reads the live constants moves with them and
  is not frozen at all. `tests/test_verifier_registry.py` compares them by value, so tightening a rule
  without registering the era that replaces it fails there, and `resolve_verifier` refuses to write in
  that state at all -- publishing would otherwise stamp a new artifact with this release's declarations
  while scanning it with the previous rules, leaving raw text in the caller's own store. A read that
  names its era is unaffected. Measured: with one pattern added and no era registered, publishing
  stops with `SNAPSHOT_COLLECTION_FAILED`, zero artifacts are written, and an already-published
  artifact still reads. A read installs its era's rules with
  `security.era_rules()` for the duration of re-scanning that artifact, and the targeted-evidence
  route uses the same era as the load that validated the bytes, so attributing a stored diff no longer
  answers differently depending on which release is installed.
  Measured: publishing a body whose text matches nothing today and then adding a pattern for it leaves
  the older artifact readable byte for byte while a new write under the later era redacts the same
  text, both in one process (`test_a_tightened_sanitizer_...`,
  `test_targeted_evidence_attribution_uses_the_era_that_wrote_the_artifact`). Before the literals
  were separated, that same single-pattern edit was reproduced against this machine's real store as
  ten artifacts refusing their own canonical bytes with the whole test suite passing; with them
  separated, all ten read byte-exactly and the registry test fails until an era is registered.
  Across the whole store, every artifact loaded under released 2.3.2 and under this code with
  unchanged bytes and an identical parsed envelope -- 597 directories at the last run, which is a
  growing number, not a constant. The envelope claim is not independent of the load claim: the
  loader refuses unless the canonical serialization reproduces the stored bytes, so a successful load
  already entails it.
- Preserved: what pinning rules does not touch. Identity validation is not era-relative and was not
  relaxed to accommodate history -- the snapshot id must still equal the SHA-256 of the stored bytes,
  `meta.json` must still serialize canonically, the directory must still hold exactly the three
  published names with mode `0600` inside a `0700` tree with no symlink ancestor, and the sanitizer
  still runs on every read; only *which* rules run changed.
  `test_identity_guards_are_not_part_of_the_era_dispatch` refuses a loosened mode, an extra file, a
  missing file, a rewritten preview, an appended byte and an unregistered epoch, asserting the reason
  as well as the refusal. An era whose classifier the sanitizer has not been told to support is still
  refused, so a half-finished bump fails closed instead of scanning old bodies under the wrong rules.
  `test_no_sanitizer_rule_is_read_bypassing_the_era_policy` walks the module and rejects any function
  body that names a rule constant directly, which covers the sites a behavioural test cannot perturb.
- Chosen, and worth stating plainly: freezing rules means an artifact published before a secret
  pattern existed stays readable with that text intact. That is the same decision as keeping history
  readable, made on the read side only -- writes always use `CURRENT_VERIFIER`, nothing new is
  published under superseded rules, and `preview.txt` still requires human review before any upload.
- Boundary that remains: the registry pins declarations and sanitizer *rule data*, not the
  sanitizer's code and not the structural tables. The per-task required fields, the evidence-gap key
  sets, `REDACTION_CATEGORIES`, the size budgets and the two shapes a read also matches a name against
  -- `REPOSITORY_NAME_RE`, which bounds the recorded repository name, and `SNAPSHOT_GIT_OID_RE`, which
  accepts the 40-hex object ids stored in `base_commit`, `target_head`, `merge_base_commit`, `head`
  and deleted-file blobs -- are still read from this release, so a future tightening of any of them
  can still refuse an old artifact. Some rule values are inline literals inside the sanitizer (a
  `.env.` prefix, a `.gitattributes` name, the basename substitution and its 64-character bound, the
  quoted-path escape table) and cannot be pinned without becoming data, and the *shape* of what the
  sanitizer emits -- how many digest characters an `<ABS_PATH:...>` marker carries, for instance -- is
  code every era shares. Measured both ways: widening that digest from 12 to 20 characters leaves the
  suite green and the store readable, because an already-redacted body never re-derives a marker,
  while removing the `.gitattributes` literal refuses an artifact published moments earlier. Treating
  either as era data would be a schema decision, not a rule edit. The same blindness reaches one shape
  further: a token the file itself split with a newline -- `ghp_A1b2C3d4E5f6` then a newline then the
  rest -- is published unredacted by the sanitizer in a three-line file as readily as across a cut
  (measured: `redactions: {}`), and no rule anchored at the end of a retained prefix can see it; that
  belongs to the token patterns, not to truncation.
- Fixed: two gaps an independent review of this seam found, both about what the tests could see. The
  structural guard rejected a read site reaching a rule through a bare constant but not one reaching
  it through the live rules *object*, so four sites -- `max_extensionless_text_bytes`,
  `max_diff_path_candidates` and both raster rules -- could be reverted to this release's values with
  a fully green suite; the guard now forbids naming the live rules object inside any function of the
  modules that sanitize, except the one function whose job is to say what "live" means, and it checks
  `artifact.py` as well as `security.py`. Building the registry was a dict comprehension, so two eras
  claiming one `(meta schema, epoch)` pair silently dropped the earlier row and orphaned every
  artifact written under it while the registry checks still passed; the index now refuses a collision.
  Three assertions were shaped to a single-era world: one let an era row pass by aliasing the live
  rules -- the exact defect the freeze commit removed -- and two hardcoded epoch `5` as
  "unregistered", which is the value the next release legitimately claims, disarming an identity guard
  at the moment it would matter; all three now derive from the registry. Corrected two claims the
  review disproved: the raster rules *are* consulted on any read carrying image evidence (two
  artifacts in this store do), and the era pins rule data rather than sanitizer code.
- Fixed: a private key that the read budget cut in half no longer reaches a `file_context` as
  ordinary text. Both
  file-context readers -- the worktree reader and branch review's sealed-target blob reader -- return
  *only the prefix they kept* to the sanitizer, while the PEM rule refuses a block it can see closed.
  A key whose closing marker lay in the bytes the reader never returned therefore looked like safe text:
  measured on a scratch repository, a 379 270-byte file whose `-----BEGIN OPENSSH PRIVATE KEY-----`
  opened at offset 240 000 published its whole 262 144-byte retained prefix, **22 108 bytes of it key
  body**, with nothing to show for it but a `file_limit` gap reading "file context truncated at 256
  KiB". The same shape published 17 characters of a `ghp_` token and 5 of a bearer value from two other
  files, because a credential cut at the boundary also fails its pattern's own minimum length.
- Fixed: a file context is now read until the budget is actually reached. One `os.read` was trusted to
  return the whole 256 KiB, and POSIX leaves it free to hand back less: measured on a 330 000-byte file
  with reads capped at 4 096 bytes, the artifact published **4 096 bytes**, recorded `file_limit: 67 856`
  -- the number the *stat* implies -- and left 325 904 bytes unpublished unaccounted for, understating the
  loss by 258 048. Worse for this change, `truncated` was computed from the file's size rather than from
  what the reader obtained, so a body cut short by the filesystem reported no gap at all and the
  secret-boundary gate was never asked: the same shape holding an OpenSSH key published 86 507 of an
  111 036-byte body with nothing in `evidence_gaps`. The reader now loops to the budget and refuses when
  the bytes delivered disagree with the size it stat'ed, reusing `file changed while reading` rather than
  inventing a second vocabulary for a lost body, which is how the byte-exact readers beside it already
  behave (`_read_complete_regular`, image evidence, publication evidence). Artifact bytes for ordinary
  reads are unaffected: the same scratch repository yields the same snapshot id across this change, and a
  short read of any kind now costs that file rather than silently shipping half of it. Three tests cover
  the loop, the gate across a multi-piece cut, and the refusal.
- Added: `security.truncated_secret_boundary()`, asked by the readers of the prefix they are about to
  hand on. A retained body that opens a private key and does not close it, or whose last characters are
  an unbroken credential run reaching the cut at a word boundary, is now withheld **whole** and
  recorded as one `file_refused` gap carrying the file's full size. Measured on the same three files:
  no prefix is published, `omitted_bytes` is 379 270 for the key, 262 189 for the bearer file and
  262 158 for the `ghp_` one, and the markers appear in none of the three stored files. Neither the read budget nor the sanitizer was widened or bypassed --
  widening the budget would only move the cut, since the secret can as easily start one byte later.
- Chosen, and stated because it is a judgement: the credential rule tests *reach*, not length. Three of
  the four token patterns match an unbounded tail and would redact a long slice, but `AKIA`/`ASIA` are
  a fixed 16 characters behind a word boundary, so a 20-character run that never terminates matches
  nothing -- measured as `redactions: {}` with the raw slice published. "This run ends where the file
  was cut" is the whole signal, so a value that happens to complete exactly at the cut is now withheld
  rather than redacted in place, and prose ending in "… bearer of" is classified as a credential. Both
  over-refusals need a file already past 256 KiB and are recorded as a gap naming it. Withholding is not
  free and the cost is measured too: a 262 333-byte file whose retained prefix carried three complete
  redactable tokens published **0 characters and `redactions: {}`** with this guard, against 262 093
  characters and `GITHUB_TOKEN: 3` without it. The file's whole context goes, including the parts that
  were never sensitive, because the collector cannot tell which half of a body the cut went through
  without reading more of it than the budget allows.
- Fixed: the credential test is a strip and one bounded marker scan, not a single expression, after a
  review found the first version cost a backtracking pass per marker candidate in the text it was
  handed. The prompt is repository content chosen by whoever is being audited, and the shape that
  triggers it is one long run of token characters with markers inside it: measured on a 300 201-character
  prefix carrying 60 000 `=AKIA` candidates the combined pattern needed 27 s to answer `None` and 170 s
  at 750 201 characters, while the sanitizer that reads those same bytes needs 0.03 s -- and a prepare
  asks up to 64 files. The split version answers the same 4 000 201-character, 800 000-candidate prefix
  in 0.015 s, and `tests/test_truncated_secret_boundary.py` keeps a loose time bound on it because the
  regression it guards is four orders of magnitude, not milliseconds. The rewrite is also held against
  the expression it replaced: over 16 544 generated inputs per seed -- every arrangement of prefix,
  marker, separator and tail plus a seeded fuzz -- the two disagree 63 times, all of them a text ending
  exactly on a marker where the expression needed at least one value character, and none in the direction
  of publishing. The old pattern is kept in the test file as that oracle and nowhere else, because
  nothing in the shipped code should ever run it again.
- Preserved: everything the guard does not concern. A block that closes inside the retained prefix keeps
  its existing sanitizer refusal (`private key boundary could not be proven`) with the two loss counts
  partitioning the file, an ordinary large file still publishes its 262 144-byte prefix under
  `file_limit`, a credential sitting whole in a small file is still redacted with `GITHUB_TOKEN: 1`, the
  D6 single-file fail-soft still costs one file and not the snapshot, and the truncation gap is filed
  under the body-refusal prefix so the `MAX_EVIDENCE_GAPS` cap keeps it. The unified diff cannot
  straddle through truncation: truncated diff evidence was already refused outright, and that refusal is
  unchanged -- a narrower claim than the diff route being safe, which the entry below answers.
- Boundary that remains, measured on this change so the claim above is read at the right width: the
  guard is asked of the two `file_context` readers, and only of a body they actually cut. Six shapes
  still publish key material, none of them new here and none of them a regression -- each was reproduced
  on `f3fdc12` and on this commit with the same result. A `test-triage` log keeps a head and a tail and
  drops the middle, so a 2 940 072-byte `build.log` published 1 311 copies of a 37-byte key line under a
  lone `test_log_limit` gap; the cut is not at the end of the retained text there, so the credential
  half of the new probe would be anchored to a file end that was never a cut, and a block lying wholly
  inside the dropped middle is invisible from either side. `git log --oneline` output
  tolerates the 2 MiB per-command bound with a `git_output_limit` gap and publishes what it got: 20
  commits carrying a 122 436-byte subject put 58 226 copies of that key line into `recent_commits`,
  2 097 152 characters of it. An untruncated body that opens a block and never closes it is handed to
  the sanitizer whole and refused only if the block also closes, so a 74 036-byte file published 2 000
  copies with no gap and no redaction -- widening that is a sanitizer rule decision, and applying the
  probe to every body would additionally make this repository's own `CHANGELOG.md`, which quotes an
  opening marker with no closing one, vanish from its own evidence. And a label the PEM expression does
  not know (`-----BEGIN PGP PRIVATE KEY BLOCK-----`, measured leaking 597 copies across the cut), raw
  base64 key material with no envelope at all (measured 2 000 copies from a 74 000-byte body, cut or
  not), and a value glued to a preceding word character (`…yyghp_MKGLUE…` reaching the last byte), which
  neither rule sees because both look for a word boundary first -- the same value after ` = ` is
  withheld, measured. Relaxing that boundary would make `ask-` or `EUROPEASIA` enough to lose a file.
  The last shape is not about truncation at all: a diff hunk that shows only *interior* lines of a key
  carries them as context, measured 8 copies of a key line in a 493-character `unstaged_diff` of the
  very path whose body the guard withheld in the same artifact. Widening the guard's reach is a token
  and diff rule decision, recorded here rather than made quietly.
  `tests/test_truncated_secret_boundary.py` pins
  the gate itself -- that an uncut body is *not* asked -- so widening either half is a decision someone
  has to make on purpose.
- No artifact schema, security epoch, contract version or CLI surface change. The guard is a write-time
  decision, and identity validation and read-time sanitization were not touched: every artifact in this
  machine's private store -- 672 directories at the last pass, a growing count rather than a constant --
  loaded under both the previous and this code with unchanged bytes and a matching snapshot id, the store
  fingerprint (mode, device, inode, size, mtime, ctime, link count for every file) is unchanged across
  both passes, and tampering is still refused.
  `tests/test_truncated_secret_boundary.py` adds 47 tests and the suite stands at 747 passing.

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
