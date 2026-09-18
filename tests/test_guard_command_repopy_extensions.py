"""Structured repopy command extension tests."""

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
)

REPOPY_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "repopy clone https://github.com/org/repo.git --install",
        "repopy install command",
        "command.repopy.install",
    ),
    (
        "repopy clone https://github.com/org/repo.git -i",
        "repopy install command",
        "command.repopy.install",
    ),
    (
        "repopy clone --install https://github.com/org/repo.git",
        "repopy install command",
        "command.repopy.install",
    ),
    (
        "repopy clone https://github.com/org/repo.git --theme minimal --install",
        "repopy install command",
        "command.repopy.install",
    ),
    (
        "repopy link https://github.com/org/repo.git",
        "repopy link command",
        "command.repopy.link",
    ),
    (
        'repopy link https://github.com/org/repo.git -m "Initial commit"',
        "repopy link command",
        "command.repopy.link",
    ),
    (
        "repopy init my_project --link https://github.com/org/repo.git",
        "repopy link command",
        "command.repopy.link",
    ),
    (
        "repopy init my_project -l https://github.com/org/repo.git",
        "repopy link command",
        "command.repopy.link",
    ),
    (
        "repopy init my_project --theme web_api --link https://github.com/org/repo.git",
        "repopy link command",
        "command.repopy.link",
    ),
    (
        "repopy init --skip --link https://github.com/org/repo.git",
        "repopy link command",
        "command.repopy.link",
    ),
    (
        "repopy init --link https://github.com/org/repo.git",
        "repopy link command",
        "command.repopy.link",
    ),
)


def test_repopy_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in REPOPY_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.repopy" for item in evaluation.extension_observations)


REPOPY_SAFE_COMMANDS: tuple[str, ...] = (
    "repopy clone https://github.com/org/repo.git",
    "repopy clone https://github.com/org/repo.git --no-install",
    "repopy init my_project",
    "repopy init --theme minimal",
    "repopy init --skip",
    "repopy --help",
    "repopy --install",
    "echo repopy clone https://github.com/org/repo.git --install",
)


def test_repopy_reads_and_previews_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(REPOPY_SAFE_COMMANDS, tmp_path)


def test_repopy_extension_publishes_official_references() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.repopy")

    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


def test_repopy_actions_publish_risk_classes() -> None:
    assert risk_classes_for_command_action("repopy install command") == ("execution",)
    assert risk_classes_for_command_action("repopy link command") == (
        "destructive_shell",
        "network_egress",
    )


def test_repopy_review_cases_match_expected_rules(tmp_path: Path) -> None:
    for command, expected_action_class, expected_rule_id in REPOPY_REVIEW_CASES:
        canonical = parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(canonical)

        matched_rules = {
            item.rule.rule_id: item.rule.action_classes
            for item in observations
            if item.extension.extension_id == "command.repopy"
        }

        assert expected_rule_id in matched_rules, (
            f"Expected {expected_rule_id} to match '{command}', but got: {list(matched_rules.keys())}"
        )
        assert expected_action_class in matched_rules[expected_rule_id], (
            f"Expected action class '{expected_action_class}' for '{command}', "
            f"but got: {matched_rules[expected_rule_id]}"
        )
