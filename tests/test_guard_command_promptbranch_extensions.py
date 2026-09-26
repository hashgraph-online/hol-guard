"""Structured PromptBranch command extension tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)
from tests.native_command_test_support import real_native_command_evaluation

_PUBLISH_ACTION = "PromptBranch prompt publication command"
_IMPORT_ACTION = "PromptBranch shared prompt import command"
_ADD_NOTE_ACTION = "PromptBranch prompt note write command"
_REPORT_RUN_ACTION = "PromptBranch prompt run report command"
_SUGGEST_ACTION = "PromptBranch prompt suggestion write command"
_SUGGEST_FILE_ACTION = "PromptBranch prompt suggestion local file read command"
_PUBLISH_RULE = "command.promptbranch.publish"
_IMPORT_RULE = "command.promptbranch.import"
_ADD_NOTE_RULE = "command.promptbranch.add-note"
_REPORT_RUN_RULE = "command.promptbranch.report-run"
_SUGGEST_RULE = "command.promptbranch.suggest"
_SUGGEST_FILE_RULE = "command.promptbranch.suggest-file"
_SENSITIVE_TOKENS = (
    "security-audit",
    "works well",
    "found 2 issues",
    "example.test",
    "rewritten secret prompt",
    "private rewrite.md",
)

PROMPTBRANCH_VERSIONED_LAUNCHER_OPTION_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "bunx --bun @promptbranch/cli@0.2.8 publish security-audit",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "npx --prefer-offline @promptbranch/cli@0.2.8 publish security-audit",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "npx -p helper @promptbranch/cli@0.2.8 import https://example.test/p/share-id",
        _IMPORT_ACTION,
        _IMPORT_RULE,
    ),
    (
        "exec npx --package helper @promptbranch/cli@0.2.8 add-note --prompt security-audit --body works-well",
        _ADD_NOTE_ACTION,
        _ADD_NOTE_RULE,
    ),
    (
        "xargs -n 1 npx --registry https://registry.example.test "
        "@promptbranch/cli@0.2.8 report-run --prompt security-audit --tool cli",
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
    (
        "exec bunx --verbose @promptbranch/cli@next suggest --prompt security-audit --content rewritten",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "exec bunx --bun @promptbranch/cli@0.2.8 publish security-audit",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "npx --future-launcher-option helper @promptbranch/cli@0.2.8 publish security-audit",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
)

PROMPTBRANCH_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    *PROMPTBRANCH_VERSIONED_LAUNCHER_OPTION_CASES,
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
        "npx @promptbranch/cli@0.2.8 publish security-audit",
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
        "exec bunx @promptbranch/cli publish security-audit --yes",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "xargs -n 1 bunx @promptbranch/cli publish security-audit --yes",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "exec promptbranch.exe publish security-audit --yes",
        _PUBLISH_ACTION,
        _PUBLISH_RULE,
    ),
    (
        "xargs -n 1 promptbranch.cmd publish security-audit --yes",
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
    ("bunx @promptbranch/cli@next import https://example.test/p/share-id", _IMPORT_ACTION, _IMPORT_RULE),
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
        "exec npx @promptbranch/cli@0.2.8 add-note --prompt security-audit --body works-well",
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
        "xargs -n 1 bunx @promptbranch/cli@0.2.8 report-run --prompt security-audit --tool cli",
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
    (
        "promptbranch report-run --unknown-flag --prompt security-audit",
        _REPORT_RUN_ACTION,
        _REPORT_RUN_RULE,
    ),
    (
        'promptbranch suggest --prompt "security-audit" --content "rewritten prompt" --rationale "reduce ambiguity"',
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "npx -y @promptbranch/cli@latest suggest --content rewritten --prompt security-audit",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "npx @promptbranch/cli@next suggest --content rewritten --prompt security-audit",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "bunx @promptbranch/cli suggest --prompt security-audit --content rewritten --json",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "zsh -lc 'promptbranch suggest --prompt security-audit --content rewritten'",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "exec bunx @promptbranch/cli suggest --prompt security-audit --content rewritten",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "xargs -n 1 bunx @promptbranch/cli suggest --prompt security-audit --content rewritten",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "exec promptbranch.exe suggest --prompt security-audit --content rewritten",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    (
        "xargs -n 1 promptbranch.cmd suggest --prompt security-audit --content rewritten",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
    ("promptbranch suggest --prompt security-audit", _SUGGEST_ACTION, _SUGGEST_RULE),
    (
        "promptbranch suggest --prompt security-audit --unknown-option",
        _SUGGEST_ACTION,
        _SUGGEST_RULE,
    ),
)

PROMPTBRANCH_SUGGEST_FILE_CASES: tuple[str, ...] = (
    'promptbranch suggest --prompt "security-audit" --file "private rewrite.md"',
    "promptbranch.exe suggest --file rewrite.md --prompt security-audit --json",
    "npx -y @promptbranch/cli suggest --prompt security-audit --file rewrite.md",
    "exec bunx @promptbranch/cli@0.2.8 suggest --prompt security-audit --file rewrite.md",
    "xargs -n 1 bunx --package helper @promptbranch/cli@0.2.8 suggest --prompt security-audit --file rewrite.md",
    "bunx @promptbranch/cli@latest suggest --file rewrite.md --prompt security-audit",
    "zsh -lc 'promptbranch suggest --prompt security-audit --file rewrite.md'",
    "exec promptbranch suggest --prompt security-audit --file rewrite.md",
    "exec bunx @promptbranch/cli suggest --prompt security-audit --file rewrite.md",
    "xargs -n 1 bunx @promptbranch/cli suggest --prompt security-audit --file rewrite.md",
    "exec promptbranch.exe suggest --prompt security-audit --file rewrite.md",
    "xargs -n 1 promptbranch.cmd suggest --prompt security-audit --file rewrite.md",
    "promptbranch suggest --prompt security-audit --file",
    "promptbranch suggest --prompt security-audit --file rewrite.md --content rewritten",
)


def test_promptbranch_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in PROMPTBRANCH_REVIEW_CASES:
        evaluation = real_native_command_evaluation(command, cwd=tmp_path, home_dir=tmp_path).evaluation
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.promptbranch" for item in evaluation.extension_observations)


def test_enabled_promptbranch_write_and_sharing_commands_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in PROMPTBRANCH_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.promptbranch", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        matched = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.promptbranch"
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id
        assert any(item.match.action_class == action_class for item in evaluation.matches)


def test_enabled_promptbranch_file_suggestions_review_the_read_and_write(tmp_path: Path) -> None:
    for command in PROMPTBRANCH_SUGGEST_FILE_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.promptbranch", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        matched_rules = {
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.promptbranch"
        }
        matched_actions = {
            item.match.action_class
            for item in evaluation.matches
            if item.extension.extension_id == "command.promptbranch"
        }
        assert {_SUGGEST_RULE, _SUGGEST_FILE_RULE} <= matched_rules, command
        assert {_SUGGEST_ACTION, _SUGGEST_FILE_ACTION} <= matched_actions, command


def test_registry_observations_attribute_promptbranch_operations(tmp_path: Path) -> None:
    for command, _action_class, expected_rule in PROMPTBRANCH_REVIEW_CASES:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.promptbranch", "enabled"),),
        ).evaluation
        if evaluation.command.confidence != "exact":
            assert evaluation.command.uncertainty_reason is not None
            continue
        observations = evaluation.extension_observations
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
    "npx -y @promptbranch/cli@latest suggestions --json",
    "promptbranch help",
    "npx @promptbranch/cli help",
    'promptbranch publish "security-audit" --preview',
    'promptbranch publish "security-audit" --full-history --preview --json',
    "npx @promptbranch/cli publish security-audit --preview",
    "npx @promptbranch/cli@0.2.8 publish security-audit --preview",
    "bunx --bun @promptbranch/cli@0.2.8 publish security-audit --preview",
    "npx --prefer-offline @promptbranch/cli@0.2.8 publish security-audit --preview",
    "npx -y @promptbranch/cli get security-audit",
    "echo promptbranch publish security-audit",
    "grep 'promptbranch publish security-audit' docs",
    "notpromptbranch publish security-audit",
)

PROMPTBRANCH_EXTENSION_SAFE_COMMANDS = (
    *PROMPTBRANCH_SAFE_COMMANDS,
    "zsh -lc 'promptbranch suggestions --json'",
    "npx @promptbranch/cli-helper@0.2.8 publish security-audit",
    "bunx @promptbranch/client@next import share-id",
    "exec npx @promptbranch/cli@ publish security-audit",
    "xargs -n 1 bunx @promptbranch/cli-tools@beta report-run --prompt security-audit --tool cli",
    "bunx --bun @promptbranch/cli-helper@0.2.8 publish security-audit",
    "npx --prefer-offline @promptbranch/client@0.2.8 publish security-audit",
)


def test_promptbranch_read_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(PROMPTBRANCH_SAFE_COMMANDS, tmp_path)


def test_enabled_promptbranch_read_and_preview_commands_do_not_review(tmp_path: Path) -> None:
    for command in PROMPTBRANCH_EXTENSION_SAFE_COMMANDS:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.promptbranch", "enabled"),),
        ).evaluation
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.promptbranch"
        )


def test_promptbranch_launcher_flags_do_not_satisfy_preview_safe_variant(tmp_path: Path) -> None:
    evaluation = real_native_command_evaluation(
        "npx --preview @promptbranch/cli@0.2.8 publish security-audit",
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(("extension", "command.promptbranch", "enabled"),),
    ).evaluation
    publish = next(
        item
        for item in evaluation.extension_observations
        if item.extension.extension_id == "command.promptbranch" and item.rule.rule_id == _PUBLISH_RULE
    )
    assert publish.effective_evidence
    assert all(variant.variant_id != "preview" for variant in publish.safe_variants)


def test_promptbranch_evidence_omits_prompt_names_notes_and_raw_arguments(tmp_path: Path) -> None:
    commands = (
        'promptbranch add-note --prompt "security-audit" --body "works well"',
        'promptbranch suggest --prompt "security-audit" --content "rewritten secret prompt"',
        'promptbranch suggest --prompt "security-audit" --file "private rewrite.md"',
    )
    for command in commands:
        evaluation = real_native_command_evaluation(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            controls=(("extension", "command.promptbranch", "enabled"),),
        ).evaluation
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
    assert risk_classes_for_command_action(_SUGGEST_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_SUGGEST_FILE_ACTION) == ("local_secret_read",)
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
