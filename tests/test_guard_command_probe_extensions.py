"""Structured Probe command extension tests."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.redaction import redact_sensitive_text
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

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


def test_probe_commands_feed_runtime_hooks(tmp_path: Path) -> None:
    assert_reviewed_command_cases(PROBE_REVIEW_CASES, tmp_path)


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


def test_probe_help_segment_cannot_hide_chained_destructive_command(tmp_path: Path) -> None:
    assert_reviewed_command_cases(PROBE_CHAINED_REVIEW_CASES, tmp_path)


def test_probe_output_adds_local_write_evidence_without_replacing_run_classification(tmp_path: Path) -> None:
    payload = inspect_command(
        "probe request run api.yml items/0 --output response.json",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    classification = payload["classification"]
    rules = payload["rules"]
    assert isinstance(classification, dict)
    assert isinstance(rules, list)
    assert classification["action_class"] == _RUN_ACTION
    rule_ids: set[str] = set()
    for rule in cast(list[object], rules):
        if not isinstance(rule, dict):
            continue
        typed_rule = cast(dict[str, object], rule)
        if isinstance(rule_id := typed_rule.get("rule_id"), str):
            rule_ids.add(rule_id)
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
