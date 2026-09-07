# Codex Snapshot Runner

Read-only, bounded Git evidence for manual review. Snapshot Runner collects repository
state, changes, branch history, or an existing test log into local artifacts. It does
not modify your code, fix problems, run tests, call a model, commit, or push.

## Requirements and installation

- Python **3.12.13 or later in the 3.12 series** (`>=3.12.13,<3.13`).
- Git on `PATH`; the verified baseline is **Git 2.43.0**.
- Verified platform: **Ubuntu 24.04 LTS**. Other Linux/POSIX platforms have not been
  verified; Windows is unsupported. Run as an ordinary user, not root.
- Runtime dependencies: Python standard library only. No Codex account or service is needed.

Install the published package into a separate virtual environment:

```bash
python3.12 -m venv /absolute/path/to/runner-venv
/absolute/path/to/runner-venv/bin/python -m pip install codex-snapshot-runner==1.4.0
export PATH="/absolute/path/to/runner-venv/bin:$PATH"
```

To install from reviewed source before publication, use `pip install .` in that virtual
environment. Source builds use `uv build`; installing a wheel does not need `uv` or `just`.

All four commands support `--help` and `--version`:

| Command | Evidence collected |
| --- | --- |
| `codex-repo-status` | Local branch, HEAD, upstream relationship, worktree status, recent commits |
| `codex-diff-audit` | Staged and unstaged changes, untracked files, bounded file context |
| `codex-branch-review` | Sealed base/HEAD identities, commits and changes relative to a local base |
| `codex-test-triage` | An existing repository-relative UTF-8 test log, with explicit size limits |

## A real local example

The shell commands below deliberately create and change a disposable example repository.
The four Runner commands only read it. Choose new, canonical absolute paths for each
directory; keep the state directory separate from the target and Runner installation.

```bash
install -d -m 0700 /absolute/path/to/runner-state
export XDG_STATE_HOME=/absolute/path/to/runner-state

git init -b main /absolute/path/to/example-repo
cd /absolute/path/to/example-repo
git config user.name 'Example User'
git config user.email 'example@example.invalid'
printf 'value = 1\n' > example.py
git add example.py
git commit -m 'Add example'

codex-repo-status --repo /absolute/path/to/example-repo

printf 'value = 2\n' > example.py
codex-diff-audit --repo /absolute/path/to/example-repo --summary

git switch -c example-change
git add example.py
git commit -m 'Change example'
codex-branch-review --repo /absolute/path/to/example-repo main

python -m unittest discover > test-output.log 2>&1
codex-test-triage --repo /absolute/path/to/example-repo test-output.log
```

`--repo` must name the exact, canonical absolute root of a non-bare Git worktree.
Linked worktrees are supported. A repository without its first commit is supported by
`repo-status`, `diff-audit`, and `test-triage`; `branch-review` requires committed history.
Upstream information uses local refs and configuration. Runner never fetches or queries
the live remote.

**Successful test-log collection does not mean the tests passed.** `test-triage` does not
interpret a framework's result or decide whether a log is complete. A failed or interrupted
test run can produce a successfully collected log. Read the log artifact and the original
test process exit status.

For a focused audit, repeat exact repository-relative file paths:

```bash
codex-diff-audit --repo /absolute/path/to/example-repo \
  --scope-path example.py --summary
```

This mode uses an isolated temporary clone and cleans its own temporary resources. It
rejects directories, unchanged paths, traversal, symlinks, and sensitive paths. It cannot
be combined with `--initial-publish-evidence`.

For an entirely untracked, unborn repository, `--initial-publish-evidence` raises the
bounded handwritten-file coverage limit from 64 to 128 files. Optional repeated
`--generated-tree` arguments identify JSON directories containing a sorted `manifest.json`
with exact path, size, and SHA-256 records. Runner verifies those records and all files;
it does not execute a generator. See `codex-diff-audit --help` for the command interface.

## Artifacts and determinism

`XDG_STATE_HOME` must already exist, belong to the current user, have mode `0700`, and
be outside the target repository and Runner installation. Without an explicit value,
Runner uses the same requirements for the user's `.local/state` directory.

A successful collection atomically publishes a directory under
`$XDG_STATE_HOME/codex-exec/snapshots/<snapshot-id>/`:

- `snapshot.json`: canonical full evidence, schema **2**, security epoch **4**.
- `preview.txt`: short human-readable summary.
- `meta.json`: sizes and SHA-256 hashes used to verify the artifacts.

Artifact directories have mode `0700`; these three files have mode `0600`. The snapshot
ID is the SHA-256 of the canonical `snapshot.json` bytes. Writes use private staging,
hash/size revalidation, and atomic publication.

With the same Runner version, command/options, collected repository state and contents,
and path-sanitization context, canonical evidence and snapshot IDs are deterministic.
This is a local evidence property: changes to refs, configuration, working files, logs,
or collection limits can change the result. The state-directory path affects printed
artifact references. A collection is not a filesystem-wide transaction; keep the target
quiescent while collecting. Branch review explicitly seals its base and target identities.

`--summary` emits bounded JSON derived from the canonical artifact. It does not change
the snapshot, exit status, or safety checks. Inspect `complete`/`partial`, `truncated`,
`evidence_gap`, warnings, and the next action. Open `snapshot.json` when evidence is partial
or the summary requests it. Test-log summaries always require reading the artifact.

## Boundaries

Runner disables external diff, text conversion, filters, hooks, paging, and terminal
prompts in its Git operations. It rejects unsupported repository capabilities rather
than running repository-controlled programs. Path traversal, symlinks, special files,
obvious sensitive paths, invalid text, and size limits produce a refusal or an explicit
evidence gap. YAML handling remains fail closed.

Changed JPEG, PNG, and WebP files yield type, size, and SHA-256 evidence, not image bytes
or visual interpretation. Unknown extensionless files have a bounded UTF-8 fallback;
arbitrary binary and unknown-extension contents are not collected as text.

Content protection covers a few explicit high-confidence forms. This is not a general
secret detector, DLP system, or security audit. Review artifacts before sharing them.
Automatic analysis is intentionally unavailable.

## Development and releases

Use Python 3.12.13, `uv` 0.12.1 or later in the 0.12 series, and `just`:

```bash
uv sync --frozen
just check
uv build
```

`just check` validates the lockfile, runs Ruff lint/format checks and the complete test
suite. Tests use synthetic repositories; no credentials or real services are required.
The public CLI contract is recorded in `tool_cli_contract.json`.

GitHub is the only release-package build and PyPI publishing authority. An annotated
`vX.Y.Z` tag must match both package version declarations. The build job runs `just check`
before building a wheel and sdist; a separate job uses OIDC Trusted Publishing after
approval in the `pypi` environment. Gitea uses the same quality gate and records the
identical public tag and Release without building or uploading a second package.

`scripts/release.py` verifies tag, package, checksum, and PyPI provenance claims before
closing Release records. Identity conflicts fail closed. To recover a missing GitHub
Release after successful PyPI publication, dispatch `release-record` with the existing
tag; to close Gitea records, dispatch its `release` workflow with that tag. These routes
do not rebuild or upload packages. If an upload was interrupted, rerun the original
failed publish job so it reuses the original Actions artifact and selects only missing
files. Never move a published tag or upload replacement files.

## License

Apache-2.0. See [LICENSE](LICENSE).
