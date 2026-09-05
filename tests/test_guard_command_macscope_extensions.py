"""Structured MacScope MCP command extension tests."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import (
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

_FEATURE_ACTION = "MacScope feature-write capability command"
_EXPERIMENTAL_ACTION = "MacScope experimental feature-write capability command"
_UTILITY_ACTION = "MacScope utility-write capability command"


def _macscope_rule_ids(payload: dict[str, object]) -> set[str]:
    raw_rules = payload.get("rules")
    assert isinstance(raw_rules, list)
    rule_ids: set[str] = set()
    for rule in cast(list[object], raw_rules):
        if not isinstance(rule, dict):
            continue
        rule_id = cast(dict[str, object], rule).get("rule_id")
        if isinstance(rule_id, str) and rule_id.startswith("command.macscope."):
            rule_ids.add(rule_id)
    return rule_ids


MACSCOPE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "MacScopeMCPServer --allow-feature-writes",
        _FEATURE_ACTION,
        "command.macscope.feature-writes",
    ),
    (
        "MacScopeMCPServer --help && MacScopeMCPServer --allow-feature-writes",
        _FEATURE_ACTION,
        "command.macscope.feature-writes",
    ),
    (
        "'/Applications/MacScope.app/Contents/Resources/MacScopeMCPServer' --allow-feature-writes",
        _FEATURE_ACTION,
        "command.macscope.feature-writes",
    ),
    (
        "MacScopeMCPServer --allow-experimental-feature-writes",
        _EXPERIMENTAL_ACTION,
        "command.macscope.experimental-feature-writes",
    ),
    (
        "MacScopeMCPServer --allow-utility-writes",
        _UTILITY_ACTION,
        "command.macscope.utility-writes",
    ),
)


def test_macscope_write_gates_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(MACSCOPE_REVIEW_CASES, tmp_path)


def test_macscope_experimental_write_gate_remains_distinct(tmp_path: Path) -> None:
    payload = inspect_command(
        "MacScopeMCPServer --allow-experimental-feature-writes",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    macscope_rule_ids = _macscope_rule_ids(payload)
    classification = payload.get("classification")

    assert macscope_rule_ids == {"command.macscope.experimental-feature-writes"}
    assert isinstance(classification, dict)
    assert classification["action_class"] == _EXPERIMENTAL_ACTION


def test_macscope_combined_write_gates_preserve_every_match(tmp_path: Path) -> None:
    payload = inspect_command(
        "MacScopeMCPServer --allow-feature-writes --allow-experimental-feature-writes --allow-utility-writes",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    macscope_rule_ids = _macscope_rule_ids(payload)

    assert macscope_rule_ids == {
        "command.macscope.feature-writes",
        "command.macscope.experimental-feature-writes",
        "command.macscope.utility-writes",
    }
    assert payload["status"] == "review"


MACSCOPE_SAFE_COMMANDS: tuple[str, ...] = (
    "MacScopeMCPServer",
    "MacScopeMCPServer --allow-sensitive-read",
    "MacScopeMCPServer --allow-artifact-read",
    "MacScopeMCPServer --help",
    "MacScopeMCPServer -h",
    "MacScopeMCPServer --version",
    "MacScopeMCPServer -v",
    "MacScopeMCPServer --allow-feature-writes --help",
    "MacScopeMCPServer --allow-experimental-feature-writes -h",
    "MacScopeMCPServer --allow-utility-writes --version",
    "other-server --allow-feature-writes --allow-utility-writes",
    "echo 'MacScopeMCPServer --allow-experimental-feature-writes'",
)


def test_macscope_read_only_and_informational_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(MACSCOPE_SAFE_COMMANDS, tmp_path)


def test_macscope_extension_publishes_pinned_primary_references() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.macscope")

    assert extension is not None
    assert extension.executables == ("MacScopeMCPServer",)
    assert {rule.rule_id for rule in extension.rules} == {
        "command.macscope.feature-writes",
        "command.macscope.experimental-feature-writes",
        "command.macscope.utility-writes",
    }
    assert len(extension.permissions) == 3
    assert all(url.startswith("https://github.com/rsm23/macscope/blob/") for url in extension.reference_urls)
