"""Structured Noodle command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

NOODLE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "noodle request run users/get --collection ./my-api --env staging",
        "Noodle request execution command",
        "command.noodle.run",
    ),
    (
        "noodle collection run ./my-api --tag smoke --json",
        "Noodle request execution command",
        "command.noodle.run",
    ),
    (
        "noodle.exe request run health --collection ./my-api",
        "Noodle request execution command",
        "command.noodle.run",
    ),
    (
        "noodle.cmd collection run ./my-api auth/ users/get --json",
        "Noodle request execution command",
        "command.noodle.run",
    ),
)


def test_noodle_run_commands_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(NOODLE_REVIEW_CASES, tmp_path)


NOODLE_SAFE_COMMANDS = (
    "noodle request run --help",
    "noodle collection run --help",
    "noodle request create users/get --url https://api.example.test/users",
    "noodle collection audit ./my-api --json",
    "grep 'noodle request run|noodle collection run' docs",
)


def test_noodle_help_and_non_execution_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(NOODLE_SAFE_COMMANDS, tmp_path)


def test_noodle_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.noodle")

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/wilfredinni/noodle",)
    assert risk_classes_for_command_action("Noodle request execution command") == (
        "execution",
        "network_egress",
    )
