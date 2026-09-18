"""Structured apex command extension tests."""

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

APEX_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "apex compress ./src -o backup.apx",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex c ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apexcompress compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "python -m apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex extract archive.apx -d ./out",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "apex x archive.apx",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "apex decompress archive.apx",
        "apex decompress command",
        "command.apex.decompress",
    ),
    (
        "apex repair damaged.apx",
        "apex repair command",
        "command.apex.repair",
    ),
    (
        "apex fix damaged.apx",
        "apex repair command",
        "command.apex.repair",
    ),
    (
        "exec apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "xargs apex compress ./src",
        "apex compress command",
        "command.apex.compress",
    ),
    (
        "apex compress ./src $DEST",
        "apex compress command",
        "command.apex.compress",
    ),
)


def test_apex_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect module and wrapper invocations reach review and attribute to apex rules."""
    for command, _action_class, expected_rule in APEX_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.apex"}
        assert expected_rule in matched, f"{command} failed to match {expected_rule}"


def test_apex_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in APEX_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.apex" for item in evaluation.extension_observations)


APEX_SAFE_COMMANDS: tuple[str, ...] = (
    "apex list",
    "apex test",
    "apex diff a.apx b.apx",
    "apex info",
    "apex benchmark f --full",
    "apex compress --help",
    "apex --help",
    "apex compress -h",
    "apex decompress --help",
    "apex repair --help",
)


def test_apex_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(APEX_SAFE_COMMANDS, tmp_path)


def test_apex_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.apex")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
