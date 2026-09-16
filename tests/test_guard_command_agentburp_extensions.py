"""Structured AgentBurp command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)


def test_agentburp_project_modifications_reach_review(tmp_path: Path) -> None:
    for cmd in (
        "agentburp project create myapp",
        "agentburp project open myapp",
        "agentburp project delete myapp",
        "agentburp.exe project create demo",
        "agentburp.exe project delete demo",
    ):
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(cmd, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.agentburp"}
        assert "command.agentburp.project-modify" in matched, f"Command did not trigger review: {cmd}"


def test_agentburp_project_list_stays_automatic(tmp_path: Path) -> None:
    assert_safe_command_cases(
        (
            "agentburp project list",
            "agentburp.exe project list",
            "agentburp project list --json",
        ),
        tmp_path,
    )
