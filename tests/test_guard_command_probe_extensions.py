"""Structured Probe command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.redaction import redact_sensitive_text
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import assert_safe_command_cases

_RUN_ACTION = "Probe request execution command"
_WRITE_ACTION = "Probe workspace mutation command"
_DELETE_ACTION = "Probe destructive command"

PROBE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("probe request run api.yml items/0", _RUN_ACTION, "command.probe.request-run"),
    (
        "probe request run api.yml items/0 --environment production",
        _RUN_ACTION,
        "command.probe.request-run",
    ),
    (
        "probe request run api.yml items/0 --var userId=123",
        _RUN_ACTION,
        "command.probe.request-run",
    ),
    (
        "probe request run api.yml items/0 --var userId=123 --var token=abc",
        _RUN_ACTION,
        "command.probe.request-run",
    ),
    (
        "probe request run api.yml items/0 --output response.json",
        _RUN_ACTION,
        "command.probe.request-run",
    ),
    (
        "probe request create api.yml --name Health --method GET --url https://api.example.test/health",
        _WRITE_ACTION,
        "command.probe.request-write",
    ),
    ("probe request set api.yml items/0 --method POST", _WRITE_ACTION, "command.probe.request-write"),
    ("probe request rename api.yml items/0 --name Health", _WRITE_ACTION, "command.probe.request-write"),
    ("probe request move api.yml items/0 --parent items/1", _WRITE_ACTION, "command.probe.request-write"),
    ("probe request reorder api.yml items/0 --index 1", _WRITE_ACTION, "command.probe.request-write"),
    ("probe request delete api.yml items/0", _DELETE_ACTION, "command.probe.request-delete"),
    ("probe folder create api.yml --name Users", _WRITE_ACTION, "command.probe.folder-write"),
    ("probe folder rename api.yml items/0 --name Accounts", _WRITE_ACTION, "command.probe.folder-write"),
    ("probe folder move api.yml items/0 --parent items/1", _WRITE_ACTION, "command.probe.folder-write"),
    ("probe folder reorder api.yml items/0 --index 1", _WRITE_ACTION, "command.probe.folder-write"),
    ("probe folder delete api.yml items/0", _DELETE_ACTION, "command.probe.folder-delete"),
    ("probe environment create api.yml --name production", _WRITE_ACTION, "command.probe.environment-write"),
    (
        "probe environment set api.yml --environment production --name baseUrl --value https://api.example.test",
        _WRITE_ACTION,
        "command.probe.environment-write",
    ),
    (
        "probe environment unset api.yml --environment production --name baseUrl",
        _WRITE_ACTION,
        "command.probe.environment-write",
    ),
    (
        "probe environment rename api.yml --environment production --name prod",
        _WRITE_ACTION,
        "command.probe.environment-write",
    ),
    (
        "probe environment delete api.yml --environment production",
        _DELETE_ACTION,
        "command.probe.environment-delete",
    ),
    ("/usr/local/bin/probe request run api.yml items/0", _RUN_ACTION, "command.probe.request-run"),
    ("probe.exe folder delete api.yml items/0", _DELETE_ACTION, "command.probe.folder-delete"),
    (
        "zsh -lc 'probe environment create api.yml --name staging'",
        _WRITE_ACTION,
        "command.probe.environment-write",
    ),
)


def test_probe_commands_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in PROBE_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.probe" for item in evaluation.extension_observations)


PROBE_SAFE_COMMANDS = (
    "probe request list api.yml",
    "probe request get api.yml items/0",
    "probe request variables api.yml items/0",
    "probe request variables api.yml items/0 --environment production",
    "probe folder list api.yml",
    "probe environment list api.yml",
    "probe collection validate api.yml",
    "probe collection create api.yml --name Example",
    "probe collection import postman collection.json api.yml",
    "probe request run --help",
    "probe folder delete --help",
    "runner request run api.yml items/0",
    "probe-tool request set api.yml items/0 --method POST",
    "grep 'probe request run|probe environment set|probe folder delete' docs",
    "printf '%s\\n' 'run set delete'",
)


def test_probe_read_only_help_and_unrelated_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(PROBE_SAFE_COMMANDS, tmp_path)


PROBE_CHAINED_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "probe request delete api.yml items/0; probe --help",
        _DELETE_ACTION,
        "command.probe.request-delete",
    ),
    (
        "probe --help; probe request delete api.yml items/0",
        _DELETE_ACTION,
        "command.probe.request-delete",
    ),
    (
        "probe folder delete --help && probe request delete api.yml items/0",
        _DELETE_ACTION,
        "command.probe.request-delete",
    ),
    (
        "probe request delete api.yml items/0; probe folder delete --help",
        _DELETE_ACTION,
        "command.probe.request-delete",
    ),
    (
        "probe request run --help; probe request run api.yml items/0",
        _RUN_ACTION,
        "command.probe.request-run",
    ),
)


def test_probe_chained_commands_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in PROBE_CHAINED_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.probe" for item in evaluation.extension_observations)


def test_probe_output_adds_local_write_evidence_without_replacing_run_classification(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command

    command = parse_shell_command(
        "probe request run api.yml items/0 --output response.json",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    rule_ids = {
        item.rule.rule_id
        for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(command)
        if item.extension.extension_id == "command.probe"
    }
    assert rule_ids >= {
        "command.probe.request-run",
        "command.probe.request-output",
    }


def test_probe_runtime_variables_use_existing_secret_shaped_redaction() -> None:
    command = "probe request run api.yml items/0 --var userId=123 --var token=abc"
    scrubbed = redact_sensitive_text(command)

    assert "userId=123" in scrubbed
    assert "token=abc" not in scrubbed
    assert "[redacted]" in scrubbed


def test_probe_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.probe")

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/crizant/probe/blob/main/docs/CLI.md",)
    assert risk_classes_for_command_action(_RUN_ACTION) == ("execution", "network_egress")
    assert risk_classes_for_command_action(_WRITE_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_DELETE_ACTION) == ("destructive_shell",)
