"""Structured Routed CLI command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
    enable_local_admin_extension_layer,
)
from tests.native_command_test_support import real_native_command_evaluation, real_native_review_fixture

_DOCTOR_FIX_ACTION = "Routed doctor reconciliation command"
_ADAPTER_ACTION = "Routed adapter mutation command"
_UNINSTALL_ACTION = "Routed uninstall command"
_UPDATE_ACTION = "Routed update command"

_DOCTOR_FIX_RULE = "command.routed.doctor-fix"
_ADAPTER_INSTALL_RULE = "command.routed.adapters-install"
_ADAPTER_UNINSTALL_RULE = "command.routed.adapters-uninstall"
_UNINSTALL_RULE = "command.routed.uninstall"
_UPDATE_RULE = "command.routed.update"

ROUTED_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("routed doctor --fix", _DOCTOR_FIX_ACTION, _DOCTOR_FIX_RULE),
    ("routed doctor --fix --json", _DOCTOR_FIX_ACTION, _DOCTOR_FIX_RULE),
    ("/usr/local/bin/routed doctor --fix", _DOCTOR_FIX_ACTION, _DOCTOR_FIX_RULE),
    ("routed adapters install", _ADAPTER_ACTION, _ADAPTER_INSTALL_RULE),
    ("routed adapters install cursor", _ADAPTER_ACTION, _ADAPTER_INSTALL_RULE),
    ("routed adapters install claude-code", _ADAPTER_ACTION, _ADAPTER_INSTALL_RULE),
    ("routed.exe adapters install", _ADAPTER_ACTION, _ADAPTER_INSTALL_RULE),
    ("routed adapters uninstall", _ADAPTER_ACTION, _ADAPTER_UNINSTALL_RULE),
    ("routed adapters uninstall cursor", _ADAPTER_ACTION, _ADAPTER_UNINSTALL_RULE),
    ("routed.cmd adapters uninstall cursor", _ADAPTER_ACTION, _ADAPTER_UNINSTALL_RULE),
    ("routed uninstall", _UNINSTALL_ACTION, _UNINSTALL_RULE),
    ("routed uninstall --json", _UNINSTALL_ACTION, _UNINSTALL_RULE),
    ("routed.exe uninstall", _UNINSTALL_ACTION, _UNINSTALL_RULE),
    ("routed update", _UPDATE_ACTION, _UPDATE_RULE),
    ("routed update -q", _UPDATE_ACTION, _UPDATE_RULE),
    ("routed upgrade", _UPDATE_ACTION, _UPDATE_RULE),
    ("routed upgrade --json", _UPDATE_ACTION, _UPDATE_RULE),
    ("zsh -lc 'routed adapters install cursor'", _ADAPTER_ACTION, _ADAPTER_INSTALL_RULE),
)

ROUTED_SAFE_COMMANDS: tuple[str, ...] = (
    'routed route "how do I run tests"',
    'routed route "fix bug" --json',
    "routed doctor",
    "routed doctor --json",
    "routed doctor -- --fix",
    "routed doctor -- --fix --json",
    "routed doctor --fix --help",
    "routed doctor --fix -h",
    "routed doctor --help",
    "routed doctor -h",
    "routed adapters",
    "routed adapters list",
    "routed adapters install --help",
    "routed adapters install -h",
    "routed adapters uninstall --help",
    "routed adapters uninstall -h",
    "routed uninstall --dry-run",
    "routed uninstall --dry-run --json",
    "routed uninstall --help",
    "routed uninstall -h",
    "routed update --check",
    "routed update --check --json",
    "routed update --help",
    "routed update -h",
    "routed upgrade --check",
    "routed upgrade --check --json",
    "routed upgrade --help",
    "routed upgrade -h",
    "routed --help",
    "routed -h",
    "echo routed uninstall",
    "grep 'routed doctor --fix' README.md",
    "printf '%s\\n' 'routed update'",
)


def test_routed_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Ensure Routed commands remain inert and unmonitored when the extension is disabled."""
    for command, _action_class, rule_id in ROUTED_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.routed" for item in evaluation.extension_observations)


def test_enabled_routed_commands_reach_review(tmp_path: Path) -> None:
    """Verify mutating Routed commands trigger appropriate review rules when enabled."""
    for command, action_class, rule_id in ROUTED_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.routed"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason == "transparent_wrapper_not_yet_supported"
            continue
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.routed"
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)


def test_registry_observations_attribute_routed_commands(tmp_path: Path) -> None:
    """Verify production observations attribute to command.routed rules."""
    for command, _action_class, expected_rule in ROUTED_REVIEW_CASES:
        if command.startswith("zsh -lc"):
            fixture = real_native_review_fixture(
                command,
                controls=(("extension", "command.routed", "enabled"),),
            )
            assert fixture.payload["command_extensions"]["evaluation_error"] == "native_command_evaluation_failed"
            assert fixture.payload["command_extensions"]["observations"] == []
            assert fixture.payload["command_model"]["uncertainty_reason"] == "transparent_wrapper_not_yet_supported"
            continue
        observations = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            controls=(("extension", "command.routed", "enabled"),),
        ).evaluation.extension_observations
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.routed"}
        assert expected_rule in matched, command


def test_routed_read_help_and_unrelated_commands_remain_safe(tmp_path: Path) -> None:
    """Ensure read-only, diagnostic, and help commands stay safe."""
    assert_safe_command_cases(ROUTED_SAFE_COMMANDS, tmp_path)


def test_enabled_routed_help_and_safe_commands_do_not_review(tmp_path: Path) -> None:
    """Verify safe Routed commands and safe variants remain quiet when the extension is enabled."""
    safe_test_cases = (
        "routed route 'how do I run tests'",
        "routed doctor",
        "routed doctor --json",
        "routed doctor --help",
        "routed doctor -h",
        "routed doctor --fix --help",
        "routed doctor --fix -h",
        "routed adapters",
        "routed adapters list",
        "routed adapters install --help",
        "routed adapters install -h",
        "routed adapters uninstall --help",
        "routed adapters uninstall -h",
        "routed uninstall --dry-run",
        "routed uninstall --dry-run --json",
        "routed uninstall --help",
        "routed uninstall -h",
        "routed update --check",
        "routed update --check --json",
        "routed update --help",
        "routed update -h",
        "routed upgrade --check",
        "routed upgrade --check --json",
        "routed upgrade --help",
        "routed upgrade -h",
        "routed --help",
        "routed -h",
        "routed doctor -- --fix",
        "routed doctor -- --fix --json",
        "routed doctor -q -- --fix",
        "routed doctor --host localhost -- --fix",
    )
    for command in safe_test_cases:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.routed"),),
        ).evaluation
        assert evaluation.controlling_rule_id not in {
            _DOCTOR_FIX_RULE,
            _ADAPTER_INSTALL_RULE,
            _ADAPTER_UNINSTALL_RULE,
            _UNINSTALL_RULE,
            _UPDATE_RULE,
        }
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.routed"
        )


def test_routed_uninstall_coverage(tmp_path: Path) -> None:
    """Comprehensive regression coverage for mutating routed uninstall and safe --dry-run/help variants."""
    mutating_cases = (
        "routed uninstall",
        "routed uninstall --json",
        "routed uninstall -q",
        "routed uninstall --quiet",
        "routed uninstall --host local",
        "routed.exe uninstall",
        "routed.cmd uninstall",
    )
    for command in mutating_cases:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.routed"),),
        ).evaluation
        assert evaluation.controlling_rule_id == _UNINSTALL_RULE, f"Expected {command} to match uninstall rule"
        assert evaluation.controlling_action_class == _UNINSTALL_ACTION
        assert any(
            item.rule.rule_id == _UNINSTALL_RULE
            for item in evaluation.extension_observations
        )
        assert any(
            item.match.action_class == _UNINSTALL_ACTION
            for item in evaluation.matches
        )

    safe_cases = (
        "routed uninstall --dry-run",
        "routed uninstall --dry-run --json",
        "routed uninstall --json --dry-run",
        "routed uninstall --dry-run -q",
        "routed uninstall --help",
        "routed uninstall -h",
        "routed uninstall --dry-run --help",
    )
    for command in safe_cases:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.routed"),),
        ).evaluation
        assert evaluation.controlling_rule_id != _UNINSTALL_RULE, f"Expected {command} not to match uninstall rule"
        assert all(
            item.rule.rule_id != _UNINSTALL_RULE or not item.effective_evidence
            for item in evaluation.extension_observations
        )


def test_routed_extension_publishes_references_and_action_risks() -> None:
    """Verify extension specification metadata, URLs, and action risk classes."""
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.routed")
    assert extension is not None
    assert extension.reference_urls == ("https://github.com/bshea-1/routed#readme",)
    assert extension.executables == ("routed",)
    assert extension.ecosystem_ids == ("routed",)
    assert risk_classes_for_command_action(_DOCTOR_FIX_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_ADAPTER_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_UNINSTALL_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_UPDATE_ACTION) == ("execution", "network_egress")
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["publisher"]["id"] == "community.bshea-1"
