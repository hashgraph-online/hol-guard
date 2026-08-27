"""Structured Skill Sunset command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command

_ACTION_CLASS = "Skill Sunset configuration audit command"
_RULE_ID = "command.skill-sunset.audit"


@pytest.mark.parametrize(
    "command",
    (
        "skill-sunset audit",
        "skill-sunset audit ./agent-config",
        "skill-sunset audit --codex --open",
        "skill-sunset audit --claude --lang zh-CN",
        "skill-sunset audit --codex --lang auto --format json --fail-on critical",
        "skill-sunset audit --claude --lang en --format text --fail-on medium",
        "skill-sunset audit ./agent-config --out ./reports --format json --fail-on high",
        "skill-sunset.cmd audit --codex --lang en --out ./reports --format text --fail-on low --open",
    ),
)
def test_skill_sunset_audit_surface_reaches_review(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    matched_rules = {rule["rule_id"] for rule in payload["rules"]}

    assert payload["status"] == "review"
    assert payload["minimum_action"] == "review"
    assert payload["classification"]["action_class"] == _ACTION_CLASS
    assert payload["controlling_rule_id"] == _RULE_ID
    assert _RULE_ID in matched_rules


@pytest.mark.parametrize(
    "command",
    (
        "skill-sunset --help",
        "skill-sunset audit --help",
        "skill-sunset audit -h",
    ),
)
def test_skill_sunset_help_remains_safe(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert payload["classification"]["matched"] is False


@pytest.mark.parametrize(
    "command",
    (
        "skill-sunset test experiment.json --run",
        "npx skill-sunset@latest audit --codex --open",
        "npm exec -- skill-sunset audit --codex --open",
    ),
)
def test_skill_sunset_extension_does_not_own_test_or_package_launchers(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    extension_ids = {extension["extension_id"] for extension in payload["extensions"]}
    rule_ids = {rule["rule_id"] for rule in payload["rules"]}

    assert "command.skill-sunset" not in extension_ids
    assert not any(rule_id.startswith("command.skill-sunset.") for rule_id in rule_ids)


def test_skill_sunset_extension_publishes_canonical_cli_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.skill-sunset")

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/ooocooc/open-skill-sunset/blob/main/src/cli.js",)
    assert {rule.rule_id for rule in extension.rules} == {_RULE_ID}


def test_skill_sunset_audit_action_publishes_runtime_risk_class() -> None:
    assert risk_classes_for_command_action(_ACTION_CLASS) == ("local_secret_read",)
