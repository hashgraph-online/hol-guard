"""Structured Codex Migrate command extension tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import assert_safe_command_cases

_ACTION_CLASS = "Codex Migrate destination-changing operation"
_RULE_ID = "command.codex-migrate.apply"

CODEX_MIGRATE_REVIEW_COMMANDS = (
    "codex-migrate export --target user@new-mac.local --target-home /Users/user --component personal-skills --apply",
    "codex-migrate serve --target user@new-mac.local --target-home /Users/user --apply --no-open",
    "codex-migrate export --a --target user@new-mac.local --target-home /Users/user",
    "codex-migrate export --appl --target user@new-mac.local --target-home /Users/user",
    "codex-migrate serve --target user@new-mac.local --target-home '/Users/New User' --app",
    "exec codex-migrate serve --target user@new-mac.local --target-home /Users/user --apply",
    "xargs -n 1 codex-migrate export --target user@new-mac.local --target-home /Users/user --apply",
    "codex-migrate export --target user@new-mac.local --target-home /Users/user $APPLY_FLAG",
    "codex-migrate export --target user@new-mac.local --target-home /Users/user ${MODE_FLAG}",
    "codex-migrate serve --target user@new-mac.local --target-home /Users/user $(printf -- --apply)",
    "codex-migrate inventory --json; codex-migrate serve --target user@new-mac.local --target-home /Users/user --apply",
)


@pytest.mark.parametrize("command", CODEX_MIGRATE_REVIEW_COMMANDS)
def test_codex_migrate_apply_commands_are_owned_by_extension(command: str, tmp_path: Path) -> None:
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
        parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    )
    matches = [item for item in observations if item.extension.extension_id == "command.codex-migrate"]

    assert matches, command
    assert any(item.rule.rule_id == _RULE_ID for item in matches), command
    assert any(_ACTION_CLASS in item.rule.action_classes for item in matches), command


@pytest.mark.parametrize("command", CODEX_MIGRATE_REVIEW_COMMANDS)
def test_codex_migrate_rules_stay_inert_until_enabled(command: str, tmp_path: Path) -> None:
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert evaluation.controlling_rule_id != _RULE_ID
    assert all(item.extension.extension_id != "command.codex-migrate" for item in evaluation.extension_observations)


CODEX_MIGRATE_SAFE_COMMANDS = (
    "codex-migrate --help",
    "codex-migrate --version",
    "codex-migrate inventory --json",
    "codex-migrate inventory --source-home '/Users/Old User' --workspace ./project",
    "codex-migrate launch --no-open",
    "codex-migrate inspect --target user@new-mac.local --target-home /Users/user --json",
    "codex-migrate inspect --target user@new-mac.local --target-home /Users/user --apply",
    "codex-migrate export --target user@new-mac.local --target-home /Users/user --component personal-skills --json",
    "codex-migrate serve --target user@new-mac.local --target-home /Users/user --no-open",
    "codex-migrate recovery --target user@new-mac.local --target-home /Users/user --json",
    "codex-migrate recovery --target user@new-mac.local --target-home /Users/user --apply",
    "codex-migrate inspect --target '$TARGET' --target-home /Users/user --json",
    "codex-migrate export --target user@new-mac.local --target-home '$TARGET_HOME' --json",
    "codex-migrate export --target user@new-mac.local --target-home /Users/user --apply --help",
    "codex-migrate serve --target user@new-mac.local --target-home /Users/user -h --apply",
    "codex-migrate inspect --target user@new-mac.local --target-home /Users/user -- --apply",
    "printf '%s' 'codex-migrate export --apply'",
    "grep 'codex-migrate serve --apply' docs/guide.md",
)


def test_codex_migrate_read_only_help_and_quoted_examples_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(CODEX_MIGRATE_SAFE_COMMANDS, tmp_path)


def test_codex_migrate_expansion_as_known_option_value_remains_safe(tmp_path: Path) -> None:
    payload = inspect_command(
        "codex-migrate inspect --target $TARGET --target-home $TARGET_HOME --json",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    assert payload["status"] == "no_match"
    assert all(extension["extension_id"] != "command.codex-migrate" for extension in payload["extensions"])


def test_codex_migrate_extension_publishes_reference_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.codex-migrate")

    assert extension is not None
    assert extension.reference_urls == (
        "https://github.com/jsegeren/codex-migrate",
        "https://migrate.segeren.com/how-it-works",
    )
    assert {rule.rule_id for rule in extension.rules} == {_RULE_ID}
    assert risk_classes_for_command_action(_ACTION_CLASS) == (
        "destructive_shell",
        "execution",
        "network_egress",
    )
