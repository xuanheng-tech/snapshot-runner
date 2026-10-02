from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import pytest

from snapshot_runner import artifact, cli, collect

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COMMANDS = {"repo-status", "diff-audit", "branch-review", "test-triage", "read"}


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        (r"Snapshot schema \*\*(\d+)\*\*", collect.SNAPSHOT_SCHEMA_VERSION),
        (r"summary schema \*\*(\d+)\*\*", artifact.SUMMARY_SCHEMA_VERSION),
        (r"evidence-read schema \*\*(\d+)\*\*", artifact.EVIDENCE_SCHEMA_VERSION),
        (r"security\s+epoch \*\*(\d+)\*\*", collect.PRODUCER_SECURITY_EPOCH),
        (
            r"`snapshot\.json`: canonical full evidence, schema \*\*(\d+)\*\*",
            collect.SNAPSHOT_SCHEMA_VERSION,
        ),
    ],
    ids=("snapshot-schema", "summary-schema", "read-schema", "security-epoch", "artifact-schema"),
)
def test_readme_current_evidence_versions_match_runtime(pattern: str, expected: int) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    declarations = re.findall(pattern, readme)
    assert declarations, "README must declare the current evidence contract"
    assert {int(version) for version in declarations} == {expected}


@pytest.mark.parametrize("command", sorted(EXPECTED_COMMANDS))
def test_subcommand_help_matches_public_flags(
    command: str, capsys: pytest.CaptureFixture[str]
) -> None:
    contract = json.loads((ROOT / "tool_cli_contract.json").read_text(encoding="utf-8"))
    specification = next(item for item in contract["commands"] if item["name"] == command)
    with pytest.raises(SystemExit) as raised:
        cli.build_argument_parser(neutral=True).parse_args([command, "--help"])
    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert set(re.findall(r"--[a-z][a-z-]*", captured.out)) == set(specification["flags"])


def test_public_cli_contract_and_package_are_consistent() -> None:
    contract_path = ROOT / "tool_cli_contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]

    assert contract["schema_version"] == 1
    # contract_version 3 records the addition of the targeted-evidence read subcommand.
    assert contract["contract_version"] == 3
    assert contract["tool_name"] == "snapshot-runner"
    assert contract["tool_version"] == project["version"]
    assert {command["name"] for command in contract["commands"]} == EXPECTED_COMMANDS
    assert {command["operation_class"] for command in contract["commands"]} == {"read_only"}
    statuses = {status for command in contract["commands"] for status in command["result_statuses"]}
    assert {"evidence_gap", "truncated"} <= statuses
    commands = {command["name"]: command for command in contract["commands"]}
    assert "--scope-path" in commands["diff-audit"]["flags"]
    assert all(
        "--scope-path" not in command["flags"]
        for name, command in commands.items()
        if name != "diff-audit"
    )
    assert {"--field", "--path"} <= set(commands["read"]["flags"])
    assert set(commands["read"]["result_statuses"]) == {
        "complete",
        "partial",
        "workflow_failed",
    }
    assert all(
        not {"--field", "--path"} & set(command["flags"])
        for name, command in commands.items()
        if name != "read"
    )

    primary = contract["primary_command"]
    assert primary["name"] == "snapshot-runner"
    assert set(primary["subcommands"]) == EXPECTED_COMMANDS
    assert contract["command_invocation"] == "snapshot-runner <command>"

    # The only public console script is the provider-neutral primary command.
    assert set(project["scripts"]) == {"snapshot-runner"}
    raw = contract_path.read_text(encoding="utf-8")
    assert "/home/" not in raw
    assert "codex" not in raw.lower()
