"""Structured kim command extension tests.

Runtime review reach for mutation commands is covered natively by the
portable fixture (tests/fixtures/command-source-kim.v1.json), which the
native source compiler evaluates. This module guards the matcher
negatives directly: read-only and near-miss forms must produce no kim
matcher evidence, so they stay automatic.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import (
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_kim_extensions import (
    KIM_ACTION_RISK_CLASSES,
    KIM_COMMAND_RULES,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command

KIM_READONLY_COMMANDS: tuple[str, ...] = (
    "kim list",
    "kim list -o",
    "kim status",
    "kim logs",
    "kim logs -n 100",
    "kim logs --json",
    "kim validate",
    "kim completion bash",
    "kim completion zsh",
    "kim -v",
    "kim export",
    "kim export -f json",
    "kim sound",
    "kim slack",
)

KIM_REVIEW_SPOT_CHECKS: tuple[tuple[str, str], ...] = (
    ('kim add morning -I 8h -t "Stand up" -m "Rise and shine"', "command.kim.add"),
    ("kim remove morning", "command.kim.remove"),
    ("xargs -n1 kim remove morning", "command.kim.remove"),
    ("kim enable morning", "command.kim.enable"),
    ("xargs python3 -m kim enable evening", "command.kim.enable"),
    ("xargs kim import backup.json", "command.kim.import"),
    ("kim export -o reminders.json", "command.kim.export"),
    ("kim export -f ics -o out.ics", "command.kim.export"),
    ("py -m kim sound --set chime", "command.kim.sound"),
    ("kim sound --clear", "command.kim.sound"),
    ("python3 -m kim slack --test", "command.kim.slack"),
    ("exec python -m kim uninstall", "command.kim.uninstall"),
)


def _matched_rule_ids(command: str) -> set[str]:
    """Return kim rule IDs whose matcher fires for one command string."""

    canonical = parse_shell_command(command)
    return {rule.rule_id for rule in KIM_COMMAND_RULES if rule.matcher is not None and rule.matcher.match(canonical)}


def test_kim_readonly_commands_stay_automatic() -> None:
    """Read-only and near-miss forms must not match any kim rule."""

    for command in KIM_READONLY_COMMANDS:
        assert _matched_rule_ids(command) == set(), command


def test_kim_mutation_spot_checks_reach_review() -> None:
    """Mutation forms (including wrappers) must match their kim rule."""

    for command, expected_rule_id in KIM_REVIEW_SPOT_CHECKS:
        assert expected_rule_id in _matched_rule_ids(command), command


def test_kim_action_classes_map_to_runtime_risk_classes() -> None:
    """Every kim action class resolves to the same destructive-shell risk set."""

    for action_class, risk_classes in KIM_ACTION_RISK_CLASSES.items():
        assert risk_classes_for_command_action(action_class) == risk_classes
