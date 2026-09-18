"""Structured PromptBranch command extension tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
    enable_local_admin_extension_layer,
)

_PUBLISH_ACTION = "PromptBranch prompt publication command"
_IMPORT_ACTION = "PromptBranch shared prompt import command"
_ADD_NOTE_ACTION = "PromptBranch prompt note write command"
_REPORT_RUN_ACTION = "PromptBranch prompt run report command"
_PUBLISH_RULE = "command.promptbranch.publish"
_IMPORT_RULE = "command.promptbranch.import"
_ADD_NOTE_RULE = "command.promptbranch.add-note"
_REPORT_RUN_RULE = "command.promptbranch.report-run"
_SENSITIVE_TOKENS = ("security-audit", "works well", "found 2 issues", "example.test")

PROMPTBRANCH_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ('promptbranch publish "security-audit"', _PUBLISH_ACTION, _PUBLISH_RULE),
    (
        'promptbranch publish "security-audit" --full-history --yes --json',
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        'promptbranch publish --portal https://example.test "security-audit" --description "release checklist"',
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    ("promptbranch.exe publish security-audit", _PUBLISH_ACTION, _PUBLISH_RULE),
    ("promptbranch.cmd publish security-audit --yes", _PUBLISH_ACTION, _PUBLISH_RULE),
    ("npx @promptbranch/cli publish security-audit --yes", _PUBLISH_ACTION, _PUBLISH_RULE),
    ("npx -y @promptbranch/cli publish security-audit", _PUBLISH_ACTION, _PUBLISH_RULE),
    (
        "npx --yes @promptbranch/cli@latest publish security-audit",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "bunx @promptbranch/cli publish security-audit --full-history",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "zsh -lc 'promptbranch publish security-audit --yes'",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "exec promptbranch publish security-audit --yes",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "xargs -n 1 promptbranch publish security-audit --yes",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "promptbranch list --json && promptbranch publish security-audit --yes",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "promptbranch publish --unknown-flag security-audit",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "promptbranch import https://example.test/p/share-id",
        _IMPORT_ACTION,
        _IMPORT_RULE,
    ),
    (
        "promptbranch import --portal https://example.test share-id --json",
        _IMPORT_ACTION,
        _IMPORT_RULE,
    ),
    ("npx @promptbranch/cli import https://example.test/p/share-id", _IMPORT_ACTION, _IMPORT_RULE),
    (
        'promptbranch add-note --prompt "security-audit" --body "works well on small diffs"',
        _ADD_NOTE_ACTION,
        _ADD_NOTE_RULE,
    ),
    (
        'promptbranch add-note --body "works well" --prompt "security-audit" --json',
        _ADD_NOTE_ACTION,
        _ADD_NOTE_RULE,
    ),
    (
        "npx -y @promptbranch/cli add-note --prompt security-audit --body works-well",
        _ADD_NOTE_ACTION,
        _ADD_NOTE_RULE,
    ),
    (
        'promptbranch report-run --prompt "security-audit" --tool kimi-cli '
        '--model k2 --outcome 4 --summary "found 2 issues"',
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
    (
        'promptbranch report-run --summary "found 2 issues" --prompt "security-audit" --tool cli',
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
    (
        "npx @promptbranch/cli report-run --prompt security-audit --tool cli",
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
    (
        "promptbranch report-run --unknown-flag --prompt security-audit",
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
)


def test_promptbranch_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in PROMPTBRANCH_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.promptbranch" for item in evaluation.extension_observations)


def test_enabled_promptbranch_write_and_sharing_commands_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in PROMPTBRANCH_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.promptbranch"),),
        )
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.promptbranch"
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)


def test_registry_observations_attribute_promptbranch_operations(tmp_path: Path) -> None:
    for command, _action_class, expected_rule in PROMPTBRANCH_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.promptbranch"}
        assert expected_rule in matched, command


PROMPTBRANCH_SAFE_COMMANDS: tuple[str, ...] = (
    "promptbranch list",
    "promptbranch list --tag security --json",
    "promptbranch get security-audit",
    "promptbranch get security-audit --version 2 --json",
    'promptbranch search "sql injection"',
    "promptbranch search audit --limit 5",
    "promptbranch suggestions",
    "promptbranch suggestions --json",
    'promptbranch publish "security-audit" --preview',
    'promptbranch publish "security-audit" --full-history --preview --json',
    "npx @promptbranch/cli publish security-audit --preview",
    "npx -y @promptbranch/cli get security-audit",
    "echo promptbranch publish security-audit",
    "grep 'promptbranch publish security-audit' docs",
    "notpromptbranch publish security-audit",
)


def test_promptbranch_read_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(PROMPTBRANCH_SAFE_COMMANDS, tmp_path)


def test_enabled_promptbranch_read_and_preview_commands_do_not_review(tmp_path: Path) -> None:
    for command in PROMPTBRANCH_SAFE_COMMANDS:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer("command.promptbranch"),),
        )
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.promptbranch"
        )


def test_promptbranch_evidence_omits_prompt_names_notes_and_raw_arguments(tmp_path: Path) -> None:
    command = 'promptbranch add-note --prompt "security-audit" --body "works well"'
    evaluation = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer("command.promptbranch"),),
    )
    promptbranch_matches = [
        item.match for item in evaluation.matches if item.extension.extension_id == "command.promptbranch"
    ]
    assert promptbranch_matches
    serialized = json.dumps(
        [
            {
                "rule_id": match.rule.rule_id,
                "reason": match.reason,
                "action_class": match.action_class,
                "evidence": [item.to_dict() for item in match.matcher_evidence],
            }
            for match in promptbranch_matches
        ]
    )
    for token in _SENSITIVE_TOKENS:
        assert token not in serialized


def test_promptbranch_extension_publishes_references_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.promptbranch")
    assert extension is not None
    assert extension.reference_urls == ("https://promptbranch.app/docs/integrations/cli",)
    assert risk_classes_for_command_action(_PUBLISH_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_IMPORT_ACTION) == ("network_egress",)
    assert risk_classes_for_command_action(_ADD_NOTE_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_REPORT_RUN_ACTION) == ("destructive_shell",)
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
