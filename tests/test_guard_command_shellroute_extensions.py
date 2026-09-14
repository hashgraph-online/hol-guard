"""Structured shellroute command safety extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_shellroute_extensions import SHELLROUTE_ACTION_RISK_CLASSES
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from tests.command_extension_contracts import assert_safe_command_cases

_EXTENSION_ID = "command.shellroute"
_RUN_ACTION = "shellroute routed command execution"
_RUN_RULE = "command.shellroute.run"
_PROXY_ACTION = "shellroute proxy lifecycle command"
_PROXY_RULE = "command.shellroute.proxy"
_REVEAL_ACTION = "shellroute api key reveal"
_REVEAL_RULE = "command.shellroute.reveal-key"

SHELLROUTE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("shellroute run US -- curl https://example.com", _RUN_ACTION, _RUN_RULE),
    ("shellroute run --country DE -- python3 scraper.py", _RUN_ACTION, _RUN_RULE),
    ("shellroute run --no-stat US -- curl -s https://example.com", _RUN_ACTION, _RUN_RULE),
    ("shellroute run --iptype datacenter --sticky GB -- wget https://example.com", _RUN_ACTION, _RUN_RULE),
    # Options after `--` belong to the child command and must not disturb the match.
    ("shellroute run US -- curl --silent --show-error https://example.com", _RUN_ACTION, _RUN_RULE),
    # `--help` after `--` is the child's flag, not the documented safe variant.
    ("shellroute run US -- shellroute --help", _RUN_ACTION, _RUN_RULE),
    ("shellroute.exe run US -- curl https://example.com", _RUN_ACTION, _RUN_RULE),
    ("shellroute proxy --country US", _PROXY_ACTION, _PROXY_RULE),
    ("shellroute proxy --country DE --format env", _PROXY_ACTION, _PROXY_RULE),
    ("shellroute proxy", _PROXY_ACTION, _PROXY_RULE),
    ("shellroute proxy stop", _PROXY_ACTION, _PROXY_RULE),
    ("shellroute reveal-key", _REVEAL_ACTION, _REVEAL_RULE),
)

SHELLROUTE_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("exec shellroute run US -- curl https://example.com", _RUN_RULE),
    ("xargs shellroute run US -- curl https://example.com", _RUN_RULE),
    ("xargs -n 1 shellroute proxy stop", _PROXY_RULE),
    ("shellroute --api-key placeholder run US -- curl https://example.com", _RUN_RULE),
    ("shellroute --api-key=placeholder proxy --country US", _PROXY_RULE),
    ("shellroute --skip-version-check reveal-key", _REVEAL_RULE),
)

SHELLROUTE_SAFE_COMMANDS: tuple[str, ...] = (
    "shellroute status",
    "shellroute countries",
    "shellroute cities US",
    "shellroute balance",
    "shellroute --version",
    "shellroute --help",
    "shellroute run --help",
    "shellroute proxy --help",
    "shellroute proxy stop --help",
    "shellroute reveal-key --help",
)


def _control_layer(state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, _EXTENSION_ID),
                state=state,
            ),
        ),
    )


def test_shellroute_rules_are_inert_until_local_admin_enable(tmp_path: Path) -> None:
    """External opt-in: nothing fires by default, every case reviews once enabled, and disable is honored."""

    for command, action_class, rule_id in SHELLROUTE_REVIEW_CASES:
        inert = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(),
        )
        assert all(item.extension.extension_id != _EXTENSION_ID for item in inert.extension_observations), command
        assert all(item.extension.extension_id != _EXTENSION_ID for item in inert.matches), command
        assert inert.controlling_action_class is None, command
        assert inert.controlling_rule_id is None, command

        enabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(_control_layer(ControlState.ENABLED),),
        )
        assert any(item.extension.extension_id == _EXTENSION_ID for item in enabled.extension_observations), command
        assert any(item.extension.extension_id == _EXTENSION_ID for item in enabled.matches), command
        assert enabled.controlling_action_class == action_class, command
        assert enabled.controlling_rule_id == rule_id, command

        disabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(_control_layer(ControlState.DISABLED),),
        )
        assert all(item.extension.extension_id != _EXTENSION_ID for item in disabled.extension_observations), command
        assert all(item.extension.extension_id != _EXTENSION_ID for item in disabled.matches), command
        assert disabled.controlling_action_class is None, command
        assert disabled.controlling_rule_id is None, command


def test_shellroute_wrapper_and_global_option_invocations_reach_review(tmp_path: Path) -> None:
    """Launcher wrappers and persistent flags before the subcommand still attribute to shellroute rules."""

    for command, expected_rule in SHELLROUTE_WRAPPER_REVIEW_COMMANDS:
        enabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_control_layer(ControlState.ENABLED),),
        )
        matched = {
            item.rule.rule_id for item in enabled.extension_observations if item.extension.extension_id == _EXTENSION_ID
        }
        assert expected_rule in matched, command


def test_shellroute_read_only_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(SHELLROUTE_SAFE_COMMANDS, tmp_path)

    for command in SHELLROUTE_SAFE_COMMANDS:
        enabled = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_control_layer(ControlState.ENABLED),),
        )
        assert all(item.extension.extension_id != _EXTENSION_ID for item in enabled.matches), command
        assert enabled.controlling_action_class is None, command
        assert enabled.controlling_rule_id is None, command


def test_shellroute_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


def test_shellroute_action_classes_publish_risk_classes() -> None:
    for action_class, risk_classes in SHELLROUTE_ACTION_RISK_CLASSES.items():
        assert risk_classes_for_command_action(action_class) == risk_classes
