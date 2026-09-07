"""Structured Routed command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
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

_DOCTOR_FIX_ACTION = "Routed doctor reconciliation command"
_ADAPTER_ACTION = "Routed adapter mutation command"
_UPDATE_ACTION = "Routed update command"

ROUTED_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("routed doctor --fix", _DOCTOR_FIX_ACTION, "command.routed.doctor-fix"),
    ("routed doctor --fix --json", _DOCTOR_FIX_ACTION, "command.routed.doctor-fix"),
    ("routed adapters install", _ADAPTER_ACTION, "command.routed.adapters-install"),
    ("routed adapters install cursor", _ADAPTER_ACTION, "command.routed.adapters-install"),
    ("routed adapters install claude-code", _ADAPTER_ACTION, "command.routed.adapters-install"),
    ("routed adapters uninstall", _ADAPTER_ACTION, "command.routed.adapters-uninstall"),
    ("routed adapters uninstall cursor", _ADAPTER_ACTION, "command.routed.adapters-uninstall"),
    ("routed update", _UPDATE_ACTION, "command.routed.update"),
    ("routed update -q", _UPDATE_ACTION, "command.routed.update"),
    ("routed upgrade", _UPDATE_ACTION, "command.routed.update"),
    ("routed upgrade --json", _UPDATE_ACTION, "command.routed.update"),
    ("/usr/local/bin/routed doctor --fix", _DOCTOR_FIX_ACTION, "command.routed.doctor-fix"),
    ("routed.exe adapters install", _ADAPTER_ACTION, "command.routed.adapters-install"),
    ("zsh -lc 'routed adapters install cursor'", _ADAPTER_ACTION, "command.routed.adapters-install"),
)

ROUTED_SAFE_COMMANDS: tuple[str, ...] = (
    'routed route "how do I run tests"',
    'routed route "fix bug" --json',
    "routed doctor",
    "routed doctor --json",
    "routed update --check",
    "routed update --check --json",
    "routed upgrade --check",
    "routed upgrade --check --json",
    "routed adapters",
    "routed adapters list",
    "routed --help",
    "routed -h",
    "grep 'routed doctor --fix' README.md",
    "printf '%s\\n' 'routed update'",
)


def _routed_control_layer(state: ControlState) -> ExtensionControlLayer:
    """Construct an ExtensionControlLayer that sets the activation state for command.routed."""
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.routed"),
                state=state,
            ),
        ),
    )


def test_routed_commands_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Ensure Routed commands remain inert and unmonitored when the extension is disabled."""
    for command, _action_class, rule_id in ROUTED_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(),
        )
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.routed" for item in evaluation.extension_observations)


def test_routed_rules_match_when_enabled(tmp_path: Path) -> None:
    """Verify mutating Routed commands trigger appropriate review rules when enabled."""
    layer = _routed_control_layer(ControlState.ENABLED)
    for command, action_class, rule_id in ROUTED_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            compatibility_action_class=action_class,
            extension_control_layers=(layer,),
        )
        assert any(item.extension.extension_id == "command.routed" for item in evaluation.extension_observations)
        assert any(item.extension.extension_id == "command.routed" for item in evaluation.matches)
        assert evaluation.controlling_action_class == action_class
        assert evaluation.controlling_rule_id == rule_id


def test_routed_safe_read_only_and_help_commands_remain_safe(tmp_path: Path) -> None:
    """Ensure read-only, diagnostic, and top-level help commands stay safe."""
    assert_safe_command_cases(ROUTED_SAFE_COMMANDS, tmp_path)


def test_routed_safe_commands_remain_unmatched_when_enabled(tmp_path: Path) -> None:
    """Verify read-only and safe commands remain un-flagged even when the extension is enabled."""
    layer = _routed_control_layer(ControlState.ENABLED)
    for command in ROUTED_SAFE_COMMANDS:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(layer,),
        )
        assert all(item.extension.extension_id != "command.routed" for item in evaluation.matches)


def test_routed_extension_publishes_reference_and_action_risks() -> None:
    """Verify extension specification metadata, URLs, and action risk classes."""
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.routed")

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/bshea-1/routed#readme",)
    assert risk_classes_for_command_action(_DOCTOR_FIX_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_ADAPTER_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_UPDATE_ACTION) == ("execution", "network_egress")
