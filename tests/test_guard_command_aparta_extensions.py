"""Structured aparta identity-scope command extension tests."""

from __future__ import annotations

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

_EXTENSION = "command.aparta"
_WRITE_ACTION = "aparta identity write command"
_CROSS_ACTION = "aparta identity scope crossing command"
_TOKEN_ACTION = "aparta credential export command"
_WRITE_RULE = "command.aparta.identity-write"
_CROSS_RULE = "command.aparta.scope-crossing"
_TOKEN_RULE = "command.aparta.token-export"

APARTA_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    ("aparta apply client-a", _WRITE_ACTION, _WRITE_RULE),
    ("aparta apply --all", _WRITE_ACTION, _WRITE_RULE),
    ("aparta --verbose apply client-a", _WRITE_ACTION, _WRITE_RULE),
    ("aparta apply", _WRITE_ACTION, _WRITE_RULE),
    ("aparta remove client-a", _WRITE_ACTION, _WRITE_RULE),
    ("aparta remove client-a --yes", _WRITE_ACTION, _WRITE_RULE),
    ("aparta remove --yes client-a", _WRITE_ACTION, _WRITE_RULE),
    ("aparta fallback --secure", _WRITE_ACTION, _WRITE_RULE),
    ("aparta fallback --secure --yes", _WRITE_ACTION, _WRITE_RULE),
    ("aparta fallback --restore", _WRITE_ACTION, _WRITE_RULE),
    ("aparta.exe apply client-a", _WRITE_ACTION, _WRITE_RULE),
    ("aparta.cmd remove client-a", _WRITE_ACTION, _WRITE_RULE),
    ('aparta apply "client a"', _WRITE_ACTION, _WRITE_RULE),
    ("aparta list; aparta apply client-a", _WRITE_ACTION, _WRITE_RULE),
    ("zsh -lc 'aparta apply client-a'", _WRITE_ACTION, _WRITE_RULE),
    ("aparta run --profile client-a -- terraform apply", _CROSS_ACTION, _CROSS_RULE),
    ("aparta run --profile=client-a -- gcloud projects list", _CROSS_ACTION, _CROSS_RULE),
    ("aparta run -p client-a -- ls", _CROSS_ACTION, _CROSS_RULE),
    ("aparta run -- gcloud auth list && aparta run -p client-a -- gcloud auth list", _CROSS_ACTION, _CROSS_RULE),
    ("aparta run --with-gh-token -- gh api user", _TOKEN_ACTION, _TOKEN_RULE),
    ("aparta run -- gh api user --with-gh-token", _TOKEN_ACTION, _TOKEN_RULE),
    ("aparta env --with-gh-token", _TOKEN_ACTION, _TOKEN_RULE),
    ("aparta env client-a --with-gh-token", _TOKEN_ACTION, _TOKEN_RULE),
    ('eval "$(aparta env --with-gh-token)"', _TOKEN_ACTION, _TOKEN_RULE),
)


def test_aparta_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in APARTA_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != _EXTENSION for item in evaluation.extension_observations)


def test_enabled_aparta_writes_crossings_and_exports_reach_review(tmp_path: Path) -> None:
    for command, action_class, rule_id in APARTA_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
        )
        matched = {
            item.rule.rule_id for item in evaluation.extension_observations if item.extension.extension_id == _EXTENSION
        }
        assert rule_id in matched, command
        assert evaluation.controlling_rule_id == rule_id, command
        assert any(item.match.action_class == action_class for item in evaluation.matches), command


def test_registry_observations_attribute_every_aparta_rule(tmp_path: Path) -> None:
    for command, _action_class, expected_rule in APARTA_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == _EXTENSION}
        assert expected_rule in matched, command


APARTA_SAFE_COMMANDS: tuple[str, ...] = (
    "aparta",
    "aparta --version",
    "aparta --help",
    "aparta scan",
    "aparta scan ~/projects",
    "aparta doctor",
    "aparta doctor client-a",
    "aparta status",
    "aparta status --shell",
    "aparta check --quiet",
    "aparta list",
    "aparta help",
    "aparta fallback",
    "aparta login",
    "aparta login client-a --provider gcloud",
    "aparta env",
    "aparta env client-a",
    "aparta env --activate",
    "aparta run -- pytest",
    "aparta run -- gcloud auth list",
    "aparta apply --dry-run client-a",
    "aparta --dry-run apply client-a",
    "aparta --dry-run apply --all",
    "aparta remove client-a --dry-run",
    "aparta fallback --secure --dry-run",
    "aparta --dry-run fallback --restore",
    "aparta apply --help",
    "aparta apply -h",
    "aparta remove --help",
    "aparta run --help",
    "aparta env --help",
    "echo aparta apply client-a",
    "grep 'aparta apply client-a' docs",
    "notaparta apply client-a",
    "aparta-cli apply client-a",
)


def test_aparta_read_only_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(APARTA_SAFE_COMMANDS, tmp_path)


def test_enabled_aparta_read_only_and_preview_commands_do_not_review(tmp_path: Path) -> None:
    for command in APARTA_SAFE_COMMANDS:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
        )
        assert evaluation.controlling_rule_id not in {_WRITE_RULE, _CROSS_RULE, _TOKEN_RULE}, command
        assert all(
            not item.effective_evidence
            for item in evaluation.extension_observations
            if item.extension.extension_id == _EXTENSION
        ), command


def test_independent_git_force_push_still_reviews_when_aparta_is_enabled(tmp_path: Path) -> None:
    command = "aparta apply client-a && git push --force origin main"
    evaluation = evaluate_command(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(enable_local_admin_extension_layer(_EXTENSION),),
    )
    matched = {item.rule.rule_id for item in evaluation.extension_observations}
    assert {_WRITE_RULE, "command.git.force-push"} <= matched


def test_aparta_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION)

    assert extension is not None
    assert extension.reference_urls == ("https://github.com/lucascarvalhal/aparta",)
    assert risk_classes_for_command_action(_WRITE_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_CROSS_ACTION) == ("execution",)
    assert risk_classes_for_command_action(_TOKEN_ACTION) == ("local_secret_read",)
