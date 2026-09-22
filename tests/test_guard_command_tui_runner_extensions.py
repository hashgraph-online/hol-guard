"""TUI Runner forced-reconfiguration command extension tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.extension_builder.listing import category_for_extension
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import assert_safe_command_cases
from tests.native_command_test_support import real_native_command_evaluation

_RECONFIGURE_ACTION = "tui-runner forced reconfiguration command"
_RECONFIGURE_RULE = "command.tui-runner.reconfigure"

TUI_RUNNER_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("tui-runner --reconfigure", "tui-runner forced reconfiguration command", "command.tui-runner.reconfigure"),
    (
        "tui-runner.exe --reconfigure",
        "tui-runner forced reconfiguration command",
        "command.tui-runner.reconfigure",
    ),
    (
        "tui-runner.cmd --reconfigure",
        "tui-runner forced reconfiguration command",
        "command.tui-runner.reconfigure",
    ),
    (
        "./target/release/tui-runner --reconfigure",
        "tui-runner forced reconfiguration command",
        "command.tui-runner.reconfigure",
    ),
)


def test_tui_runner_rules_are_inert_until_local_admin_enable(tmp_path: Path) -> None:
    for command, _action_class, rule_id in TUI_RUNNER_REVIEW_CASES:
        inert = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert all(item.extension.extension_id != "command.tui-runner" for item in inert.extension_observations)
        assert all(item.extension.extension_id != "command.tui-runner" for item in inert.matches)
        assert inert.controlling_rule_id != rule_id

        enabled = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.tui-runner", "enabled"),),
        ).evaluation
        if enabled.command.confidence != "exact":
            assert enabled.command.uncertainty_reason is not None
            continue
        assert any(item.extension.extension_id == "command.tui-runner" for item in enabled.extension_observations)
        assert any(item.extension.extension_id == "command.tui-runner" for item in enabled.matches)
        assert enabled.controlling_rule_id == rule_id

        disabled = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.tui-runner", "disabled"),),
        ).evaluation
        assert all(item.extension.extension_id != "command.tui-runner" for item in disabled.extension_observations)
        assert all(item.extension.extension_id != "command.tui-runner" for item in disabled.matches)
        assert disabled.controlling_rule_id != rule_id


TUI_RUNNER_SAFE_COMMANDS: tuple[str, ...] = (
    "tui-runner",
    "tui-runner.exe",
    "tui-runner --help",
    "tui-runner --reconfigur",
    "tui-runner reconfigure",
    "echo tui-runner --reconfigure",
    "grep 'tui-runner --reconfigure' docs",
)


def test_tui_runner_launch_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(TUI_RUNNER_SAFE_COMMANDS, tmp_path)


# Commands that must reach review once the extension is enabled: direct wrapper
# forms (exec/xargs), compound shell forms (separators and pipelines), and
# reordered or quoted arguments. None of these change the destructive meaning of
# --reconfigure, so a bypass here would let an agent adapter route around review.
TUI_RUNNER_BYPASS_REVIEW_COMMANDS: tuple[str, ...] = (
    "exec tui-runner --reconfigure",
    "xargs tui-runner --reconfigure",
    "xargs -n 1 tui-runner --reconfigure",
    "tui-runner --reconfigure; echo done",
    "tui-runner --reconfigure && echo done",
    "echo start && tui-runner --reconfigure",
    "tui-runner --reconfigure | cat",
    "cat notes.txt | tui-runner --reconfigure",
    '"tui-runner" --reconfigure',
    'tui-runner "--reconfigure"',
    "tui-runner --output ./dest --reconfigure",
    "tui-runner --reconfigure --output ./dest",
)


def test_tui_runner_wrapper_and_compound_shell_forms_reach_review_when_enabled(tmp_path: Path) -> None:
    """Wrapper launchers, separators/pipelines, and reordered/quoted args cannot dodge review."""

    for command in TUI_RUNNER_BYPASS_REVIEW_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.tui-runner", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.tui-runner"
        }
        assert _RECONFIGURE_RULE in matched, command


# Unresolved shell expansions can supply --reconfigure at execution time, so
# they must stay fail-secure (reviewed) even though the literal flag never
# appears in the observed argv.
TUI_RUNNER_UNRESOLVED_EXPANSION_REVIEW_COMMANDS: tuple[str, ...] = (
    "tui-runner $RECONFIG_FLAG",
    'tui-runner "$RECONFIG_FLAG"',
    "tui-runner ${RECONFIG_FLAG}",
    "tui-runner $(echo --reconfigure)",
    "tui-runner `echo --reconfigure`",
    "exec tui-runner $RECONFIG_FLAG",
    "xargs -n 1 tui-runner $RECONFIG_FLAG",
    "tui-runner.exe $RECONFIG_FLAG",
    "tui-runner.cmd $RECONFIG_FLAG",
    "exec tui-runner.exe $RECONFIG_FLAG",
    "exec tui-runner.cmd $RECONFIG_FLAG",
    "xargs -n 1 tui-runner.exe $RECONFIG_FLAG",
    "xargs -n 1 tui-runner.cmd $RECONFIG_FLAG",
)


def test_tui_runner_unresolved_expansions_stay_fail_secure_when_enabled(tmp_path: Path) -> None:
    for command in TUI_RUNNER_UNRESOLVED_EXPANSION_REVIEW_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.tui-runner", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.tui-runner"
        }
        assert _RECONFIGURE_RULE in matched, command


# The safe counterparts of the bypass and expansion tables above: the same
# wrapper/compound shapes, but without --reconfigure or any expansion marker,
# must stay unreviewed even while the extension is enabled.
TUI_RUNNER_SAFE_WRAPPER_AND_COMPOUND_COMMANDS: tuple[str, ...] = (
    "exec tui-runner",
    "xargs tui-runner",
    "xargs -n 1 tui-runner --help",
    "tui-runner; echo done",
    "tui-runner && echo done",
    "tui-runner | cat",
    '"tui-runner" --help',
    "tui-runner --output ./dest",
    "exec echo tui-runner --reconfigure",
    "tui-runner --reconfigur",
)


def test_tui_runner_safe_wrapper_and_compound_forms_stay_unreviewed_when_enabled(tmp_path: Path) -> None:
    for command in TUI_RUNNER_SAFE_WRAPPER_AND_COMPOUND_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.tui-runner", "enabled"),),
        ).evaluation
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.tui-runner"
        }
        assert _RECONFIGURE_RULE not in matched, command


def test_tui_runner_evidence_omits_raw_arguments_and_expansion_content(tmp_path: Path) -> None:
    command = "tui-runner --project acme-internal-secret $RECONFIG_FLAG"
    evaluation = real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(("extension", "command.tui-runner", "enabled"),),
    ).evaluation
    tui_runner_matches = [
        item.match for item in evaluation.matches if item.extension.extension_id == "command.tui-runner"
    ]
    assert tui_runner_matches
    serialized = json.dumps(
        [
            {
                "rule_id": match.rule.rule_id,
                "reason": match.reason,
                "action_class": match.action_class,
                "evidence": [item.to_dict() for item in match.matcher_evidence],
            }
            for match in tui_runner_matches
        ]
    )
    for token in ("acme-internal-secret", "RECONFIG_FLAG", str(tmp_path)):
        assert token not in serialized
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.tui-runner")
    assert extension is not None
    catalog = json.dumps(extension.to_dict())
    assert "acme-internal-secret" not in catalog
    assert "RECONFIG_FLAG" not in catalog


def test_tui_runner_action_publishes_risk_classes() -> None:
    assert risk_classes_for_command_action("tui-runner forced reconfiguration command") == ("destructive_shell",)


def test_tui_runner_extension_documents_interactive_coverage_limit() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.tui-runner")

    assert extension is not None
    assert extension.required is False
    description = extension.description.lower()
    assert "interactive" in description
    assert "port cleanup" in description
    assert "scaffolding" in description


def test_tui_runner_extension_is_categorized() -> None:
    assert category_for_extension("command.tui-runner") == "specialized-tools"
