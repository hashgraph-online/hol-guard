"""Structured knot command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

KNOT_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    # knot init cases
    (
        "knot init",
        "knot initialization command",
        "command.knot.init",
    ),
    # knot sync cases
    (
        "knot sync",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync -i",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync --non-interactive",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync -n",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync --notifications",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync -c /path/to/config.toml",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync --config-path /path/to/config.toml",
        "knot synchronization command",
        "command.knot.sync",
    ),
    (
        "knot sync -i -n -c ./workspace",
        "knot synchronization command",
        "command.knot.sync",
    ),
)


KNOT_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("exec knot init", "command.knot.init"),
    ("xargs knot init", "command.knot.init"),
    ("xargs -n 1 knot init", "command.knot.init"),
    ("exec knot sync", "command.knot.sync"),
    ("xargs knot sync", "command.knot.sync"),
    ("xargs -n 1 knot sync", "command.knot.sync"),
    ("xargs -n 1 knot sync -c /path/to/config", "command.knot.sync"),
)


def test_knot_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Wrapper invocations reach review and attribute to knot rules."""
    for command, expected_rule in KNOT_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.knot"}
        assert expected_rule in matched, command


def test_knot_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Ensure knot rules are not enforced when disabled by default configuration."""
    for command, _action_class, rule_id in KNOT_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.knot" for item in evaluation.extension_observations)


KNOT_SAFE_COMMANDS: tuple[str, ...] = (
    "knot init --help",
    "knot init -h",
    "knot sync --help",
    "knot sync -h",
)


def test_knot_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    """Ensure safe variants like help flags pass without review triggers."""
    assert_safe_command_cases(KNOT_SAFE_COMMANDS, tmp_path)


def test_knot_extension_publishes_official_reference() -> None:
    """Verify that the Knot extension is registered and contains valid HTTPS references."""
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.knot")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
