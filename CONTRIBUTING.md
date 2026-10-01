# Contributing

Use the Python, Git, `uv` and `just` versions described in [README.md](README.md).
This project has no runtime dependency beyond the standard library.

```bash
uv sync --frozen --no-config --default-index https://pypi.org/simple
just check
uv build
```

Keep changes focused and add a synthetic regression test for changed behavior. Tests
must not use credentials, real services or the caller's Git configuration. Preserve
the target repository's read-only boundary and the private artifact-store checks.
Explain the trigger, resulting behavior and validation in a pull request.

When changing sanitizer rules, register a new producer era in `verifiers.py`; never
edit the frozen values that historical artifacts use. Incompatible format changes
need a versioned validator. Check stored-artifact fixtures as well as new collection.
Keep `tool_cli_contract.json` consistent with the CLI and package metadata.

Commit `uv.lock` changes only when dependencies or index metadata intentionally change.
Regenerate with `uv lock --no-config --default-index https://pypi.org/simple`; local
mirror configuration is not part of the public project lockfile.

Contributions are provided under the project's [Apache-2.0 license](LICENSE).
Follow [SECURITY.md](SECURITY.md) for security reports and README for release controls.
