"""Structured batterycontrol command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)
from tests.native_command_test_support import real_native_command_evaluation

BATTERYCONTROL_CHARGING_ACTION_CLASS = "batterycontrol charging policy command"
BATTERYCONTROL_MAINTENANCE_ACTION_CLASS = "batterycontrol privileged maintenance command"

BATTERYCONTROL_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "batterycontrol limit set 80",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.limit-set",
    ),
    (
        "batterycontrol limit set 80 --resume 70",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.limit-set",
    ),
    (
        "batterycontrol limit set 55 --resume 48",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.limit-set",
    ),
    (
        "batterycontrol limit off",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.limit-off",
    ),
    (
        "batterycontrol limit off --confirm",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.limit-off",
    ),
    (
        "batterycontrol discharge start 60",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.discharge-start",
    ),
    (
        "batterycontrol discharge start 55 --floor 20",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.discharge-start",
    ),
    (
        "batterycontrol discharge start 10 --allow-below-floor",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.discharge-below-floor",
    ),
    (
        "batterycontrol discharge start 12 --allow-below-floor --floor 10",
        BATTERYCONTROL_CHARGING_ACTION_CLASS,
        "command.batterycontrol.discharge-below-floor",
    ),
    (
        "batterycontrol uninstall --confirm",
        BATTERYCONTROL_MAINTENANCE_ACTION_CLASS,
        "command.batterycontrol.uninstall",
    ),
    (
        "batterycontrol uninstall --confirm --remove-data",
        BATTERYCONTROL_MAINTENANCE_ACTION_CLASS,
        "command.batterycontrol.uninstall",
    ),
)


def test_batterycontrol_policy_and_maintenance_commands_reach_review(
    tmp_path: Path,
) -> None:
    """State-changing batterycontrol commands reach review with the expected rule evidence."""

    for command, expected_action_class, expected_rule in BATTERYCONTROL_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.batterycontrol", "enabled"),),
        ).evaluation
        observations = evaluation.extension_observations
        matched = {
            item.rule.rule_id for item in observations if item.extension.extension_id == "command.batterycontrol"
        }
        assert expected_rule in matched, command
        action_classes = {
            action_class
            for item in observations
            if item.extension.extension_id == "command.batterycontrol"
            for action_class in item.rule.action_classes
        }
        assert expected_action_class in action_classes, command


def test_batterycontrol_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in BATTERYCONTROL_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(
            item.extension.extension_id != "command.batterycontrol" for item in evaluation.extension_observations
        )


BATTERYCONTROL_AUTOMATIC_STATUS_COMMANDS: tuple[str, ...] = (
    "batterycontrol status",
    "batterycontrol limit status",
    "batterycontrol limit status --resume",
    "batterycontrol discharge status",
    "batterycontrol calibration status",
    "batterycontrol charge status",
    "batterycontrol diagnostics",
    "batterycontrol compatibility",
    "batterycontrol update-check",
    "batterycontrol version",
    "batterycontrol help",
    "batterycontrol --help",
)

BATTERYCONTROL_REVIEWED_HELP_COMMANDS: tuple[str, ...] = (
    "batterycontrol limit set --help",
    "batterycontrol limit off --help",
    "batterycontrol discharge start --help",
    "batterycontrol uninstall --help",
)


def test_batterycontrol_status_and_diagnostics_commands_remain_automatic(
    tmp_path: Path,
) -> None:
    """Read-only status, diagnostics, and help output stay automatic by design."""

    assert_safe_command_cases(
        BATTERYCONTROL_AUTOMATIC_STATUS_COMMANDS + BATTERYCONTROL_REVIEWED_HELP_COMMANDS,
        tmp_path,
    )


def test_batterycontrol_lookalike_executables_do_not_match(tmp_path: Path) -> None:
    for command in (
        "batterycontrolx limit set 80",
        "./bin/batterycontrol-helper limit set 80",
    ):
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.batterycontrol", "enabled"),),
        ).evaluation
        assert all(
            item.extension.extension_id != "command.batterycontrol" for item in evaluation.extension_observations
        ), command


def test_batterycontrol_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.batterycontrol")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
