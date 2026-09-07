from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COMMANDS = {
    "codex-repo-status",
    "codex-diff-audit",
    "codex-branch-review",
    "codex-test-triage",
}


def test_public_cli_contract_and_package_are_consistent() -> None:
    contract_path = ROOT / "tool_cli_contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)["project"]

    assert contract["schema_version"] == 1
    assert contract["contract_version"] == 1
    assert contract["tool_name"] == "snapshot-runner"
    assert contract["tool_version"] == project["version"]
    assert {command["name"] for command in contract["commands"]} == EXPECTED_COMMANDS
    assert {command["operation_class"] for command in contract["commands"]} == {"read_only"}
    statuses = {status for command in contract["commands"] for status in command["result_statuses"]}
    assert {"evidence_gap", "truncated"} <= statuses
    commands = {command["name"]: command for command in contract["commands"]}
    assert "--scope-path" in commands["codex-diff-audit"]["flags"]
    assert all(
        "--scope-path" not in command["flags"]
        for name, command in commands.items()
        if name != "codex-diff-audit"
    )
    primary = contract["primary_command"]
    assert primary["name"] == "snapshot-runner"
    assert primary["subcommands"] == {
        name.removeprefix("codex-"): {"compatibility_alias": name} for name in EXPECTED_COMMANDS
    }
    assert set(project["scripts"]) == EXPECTED_COMMANDS | {primary["name"]}
    assert "/home/" not in contract_path.read_text(encoding="utf-8")
