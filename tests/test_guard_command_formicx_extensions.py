"""Structured Formicx command safety extension tests."""

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
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

FORMICX_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "formicx agent register ./agents/hello-agent",
        "formicx agent registration command",
        "command.formicx.agent-register",
    ),
    (
        "formicx agent register ./agents/hello-agent/agent.yaml",
        "formicx agent registration command",
        "command.formicx.agent-register",
    ),
    (
        "formicx agent start hello-agent",
        "formicx agent process start command",
        "command.formicx.agent-start",
    ),
    (
        "formicx agent stop hello-agent",
        "formicx agent process stop command",
        "command.formicx.agent-stop",
    ),
    (
        "formicx agent restart hello-agent",
        "formicx agent process restart command",
        "command.formicx.agent-restart",
    ),
)

FORMICX_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("python -m formicx agent register ./agents/hello-agent", "command.formicx.agent-register"),
    ("python -u -m formicx agent register ./agents/hello-agent", "command.formicx.agent-register"),
    ("python3 -W ignore -m formicx agent start hello-agent", "command.formicx.agent-start"),
    ("python3 -u -W default -m formicx agent start hello-agent", "command.formicx.agent-start"),
    ("py -X dev -m formicx agent stop hello-agent", "command.formicx.agent-stop"),
    ("exec formicx agent restart hello-agent", "command.formicx.agent-restart"),
    ("exec -a custom_proc formicx agent restart hello-agent", "command.formicx.agent-restart"),
    ("exec -a proc python -u -m formicx agent restart hello-agent", "command.formicx.agent-restart"),
    ("xargs formicx agent start hello-agent", "command.formicx.agent-start"),
    ("xargs -n 1 python -m formicx agent stop hello-agent", "command.formicx.agent-stop"),
    ("xargs -n 1 -P 4 python3 -u -m formicx agent stop hello-agent", "command.formicx.agent-stop"),
    ("xargs -I {} -d \n formicx agent restart hello-agent", "command.formicx.agent-restart"),
)


def _enable_layer(*extension_ids: str) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=tuple(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, extension_id),
                state=ControlState.ENABLED,
            )
            for extension_id in extension_ids
        ),
    )


def test_formicx_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Indirect module and wrapper invocations reach review when enabled."""

    layers = (_enable_layer("command.formicx"),)
    for command, expected_rule in FORMICX_WRAPPER_REVIEW_COMMANDS:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=layers)
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.formicx"
        }
        assert expected_rule in matched, command


def test_formicx_stays_inert_until_explicitly_enabled(tmp_path: Path) -> None:
    """Formicx is an external opt-in extension and stays inert until explicitly enabled."""
    cmd = "formicx agent start hello-agent"
    inert = evaluate_command(cmd, cwd=tmp_path, home_dir=tmp_path)
    assert all(item.extension.extension_id != "command.formicx" for item in inert.extension_observations)

    enabled = evaluate_command(
        cmd,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(_enable_layer("command.formicx"),),
    )
    assert any(item.extension.extension_id == "command.formicx" for item in enabled.extension_observations)
    assert enabled.controlling_rule_id == "command.formicx.agent-start"


def test_formicx_mutation_commands_trigger_review_observations(tmp_path: Path) -> None:
    """Mutation lifecycle commands (register, start, stop, restart) trigger review observations when enabled."""
    layers = (_enable_layer("command.formicx"),)
    for command, _action_class, _rule_id in FORMICX_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=layers)
        is_matched = any(item.extension.extension_id == "command.formicx" for item in evaluation.extension_observations)
        assert is_matched, command


FORMICX_SAFE_COMMANDS: tuple[str, ...] = (
    "formicx agent list",
    "formicx agent status hello-agent",
    "formicx agent resources",
    "formicx daemon health",
    "formicx daemon status",
    "formicx node info",
    "formicx policy list",
    "formicx --help",
    "formicx agent --help",
    "formicx agent register --help",
    "formicx agent start --help",
    "formicx agent stop --help",
    "formicx agent restart --help",
)


def test_formicx_read_only_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(FORMICX_SAFE_COMMANDS, tmp_path)


def test_formicx_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.formicx")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
