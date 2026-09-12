set positional-arguments := true

default:
    just --list

# Prepare a bounded local repository-status snapshot for manual review
repo-status *args:
    #!/usr/bin/env bash
    exec uv run --no-cache --frozen --no-sync python -m snapshot_runner.cli prepare repo-status "$@"

# Prepare a bounded local diff-audit snapshot for manual review
diff-audit *args:
    #!/usr/bin/env bash
    exec uv run --no-cache --frozen --no-sync python -m snapshot_runner.cli prepare diff-audit "$@"

# Prepare a bounded local branch-review snapshot for manual review
branch-review *args:
    #!/usr/bin/env bash
    exec uv run --no-cache --frozen --no-sync python -m snapshot_runner.cli prepare branch-review "$@"

# Prepare a bounded local test-log snapshot for manual review
test-triage *args:
    #!/usr/bin/env bash
    exec uv run --no-cache --frozen --no-sync python -m snapshot_runner.cli prepare test-triage "$@"

# prepare-only fixed fail-closed sentinel
analyze-snapshot *args:
    #!/usr/bin/env bash
    exec uv run --no-cache --frozen --no-sync python -m snapshot_runner.cli analyze "$@"

check:
    uv lock --check --no-config
    uv run --frozen ruff check snapshot_runner scripts tests
    uv run --frozen ruff format --check snapshot_runner scripts tests
    uv run --frozen pytest
