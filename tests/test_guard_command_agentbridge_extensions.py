"""Structured AgentBridge command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
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


def _enable_agentbridge_layer() -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.agentbridge"),
                state=ControlState.ENABLED,
            ),
        ),
    )


AGENTBRIDGE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "AgentBridge forced plugin scaffold command",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "agentbridge scaffold-plugin --backend demo --package-name agentbridge_demo --force ./plugins/demo",
        "AgentBridge forced plugin scaffold command",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "agentbridge run --manifest examples/refund_agent.yaml --backend mock --tool-registry my_app.tools:registry",
        "AgentBridge run with tool registry command",
        "command.agentbridge.run-tool-registry",
    ),
    (
        "agentbridge run --tool-registry my_app.tools:registry --input 'hello'",
        "AgentBridge run with tool registry command",
        "command.agentbridge.run-tool-registry",
    ),
)


def test_agentbridge_commands_reach_extension_observations(tmp_path: Path) -> None:
    for command, _action_class, rule_id in AGENTBRIDGE_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.agentbridge"}
        assert rule_id in matched, command


AGENTBRIDGE_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    (
        "exec agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "xargs -n 1 agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "xargs --max-args=1 --null agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "exec -c -a ab agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "exec agentbridge.exe scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "xargs -n 1 agentbridge.cmd scaffold-plugin plugins/agentbridge-demo --backend demo --force",
        "command.agentbridge.scaffold-plugin-force",
    ),
    (
        "exec agentbridge run --manifest examples/refund_agent.yaml --tool-registry my_app.tools:registry",
        "command.agentbridge.run-tool-registry",
    ),
    (
        "xargs -n 1 agentbridge run --tool-registry my_app.tools:registry",
        "command.agentbridge.run-tool-registry",
    ),
    (
        "xargs --max-args 1 --replace ITEM agentbridge run --tool-registry my_app.tools:registry",
        "command.agentbridge.run-tool-registry",
    ),
    (
        "exec -l agentbridge run --tool-registry my_app.tools:registry",
        "command.agentbridge.run-tool-registry",
    ),
    (
        "exec agentbridge.cmd run --tool-registry my_app.tools:registry",
        "command.agentbridge.run-tool-registry",
    ),
    (
        "xargs -n 1 agentbridge.exe run --tool-registry my_app.tools:registry",
        "command.agentbridge.run-tool-registry",
    ),
)


def test_agentbridge_wrapper_invocations_reach_review_observations(tmp_path: Path) -> None:
    for command, expected_rule in AGENTBRIDGE_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.agentbridge"}
        assert expected_rule in matched, command


def test_agentbridge_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in AGENTBRIDGE_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.agentbridge" for item in evaluation.extension_observations)


def test_agentbridge_enabled_extension_controls_each_rule(tmp_path: Path) -> None:
    for command, action_class, rule_id in AGENTBRIDGE_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_enable_agentbridge_layer(),),
        )
        assert evaluation.controlling_action_class == action_class
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.extension.extension_id == "command.agentbridge" for item in evaluation.extension_observations)


AGENTBRIDGE_SAFE_COMMANDS: tuple[str, ...] = (
    "agentbridge validate --manifest examples/refund_agent.yaml --backend mock",
    "agentbridge compare --manifest examples/refund_agent.yaml --backend mock --backend langgraph",
    "agentbridge list-backends",
    "agentbridge inspect-backend mock --json",
    "agentbridge scaffold-plugin --help",
    "agentbridge run --help",
    "agentbridge run --manifest examples/refund_agent.yaml --backend mock",
    "agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo",
    "xargs --arg-file agentbridge scaffold-plugin plugins/agentbridge-demo --backend demo --force",
)


def test_agentbridge_read_only_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(AGENTBRIDGE_SAFE_COMMANDS, tmp_path)


def test_agentbridge_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.agentbridge")
    assert extension is not None
    assert extension.reference_urls == ("https://agentbridge.readthedocs.io/en/latest/",)
