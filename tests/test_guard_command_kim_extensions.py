"""Structured kim command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_kim_extensions import (
    KIM_ACTION_RISK_CLASSES,
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

KIM_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        'kim add morning -I 8h -t "Stand up" -m "Rise and shine"',
        "kim reminder add command",
        "command.kim.add",
    ),
    (
        'kim add daily --every 24h -t "Daily sync"',
        "kim reminder add command",
        "command.kim.add",
    ),
    (
        'kim add daily --at 09:30 --tz Asia/Kolkata -m "Standup"',
        "kim reminder add command",
        "command.kim.add",
    ),
    (
        "python -m kim add water --every 6h -m hydrate",
        "kim reminder add command",
        "command.kim.add",
    ),
    ("kim remove morning", "kim reminder remove command", "command.kim.remove"),
    (
        "kim remove evening --oneshot",
        "kim reminder remove command",
        "command.kim.remove",
    ),
    (
        'kim update morning -I 4h -t "Updated" -m "Shifted schedule"',
        "kim reminder update command",
        "command.kim.update",
    ),
    (
        'kim update morning --at 10:00 --enable -t "Later"',
        "kim reminder update command",
        "command.kim.update",
    ),
    ("kim enable morning", "kim reminder enable command", "command.kim.enable"),
    ("xargs python3 -m kim enable evening", "kim reminder enable command", "command.kim.enable"),
    ("kim disable morning", "kim reminder disable command", "command.kim.disable"),
    (
        "kim disable morning --oneshot",
        "kim reminder disable command",
        "command.kim.disable",
    ),
    (
        'kim remind -t "Lunch" -m "Walk"',
        "kim one-shot reminder command",
        "command.kim.remind",
    ),
    ("kim import reminders.json", "kim reminder import command", "command.kim.import"),
    (
        "xargs kim import backup.json",
        "kim reminder import command",
        "command.kim.import",
    ),
    ("kim export -o reminders.json", "kim reminder export command", "command.kim.export"),
    (
        "kim export -f ics -o out.ics",
        "kim reminder export command",
        "command.kim.export",
    ),
    ("kim start", "kim daemon start command", "command.kim.start"),
    ("kim stop", "kim daemon stop command", "command.kim.stop"),
    ("kim edit", "kim config edit command", "command.kim.edit"),
    ("py -m kim sound --set chime", "kim sound settings command", "command.kim.sound"),
    ("kim sound --clear", "kim sound settings command", "command.kim.sound"),
    (
        "kim sound --test",
        "kim sound settings command",
        "command.kim.sound",
    ),
    (
        "python3 -m kim slack --test",
        "kim slack settings command",
        "command.kim.slack",
    ),
    (
        'kim slack --test -t "Greeting" -m "Hello"',
        "kim slack settings command",
        "command.kim.slack",
    ),
    ("kim interactive", "kim interactive command", "command.kim.interactive"),
    ("kim -i", "kim interactive command", "command.kim.interactive"),
    ("exec kim interactive", "kim interactive command", "command.kim.interactive"),
    (
        "kim self-update --channel stable",
        "kim self-update command",
        "command.kim.self-update",
    ),
    ("kim uninstall", "kim uninstall command", "command.kim.uninstall"),
    (
        "exec python -m kim uninstall",
        "kim uninstall command",
        "command.kim.uninstall",
    ),
)


def test_kim_mutations_reach_review_and_readonly_commands_stay_safe(tmp_path: Path) -> None:
    """Mutation commands review; read-only list/status/logs stay automatic."""

    for command, expected_action_class, expected_rule_id in KIM_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = [
            (item.rule.rule_id, item.rule.action_classes[0])
            for item in observations
            if item.extension.extension_id == "command.kim" and item.effective_evidence
        ]
        assert (expected_rule_id, expected_action_class) in matched, command

    for command in KIM_READONLY_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        assert all(item.extension.extension_id != "command.kim" for item in observations), command


def test_kim_action_classes_map_to_runtime_risk_classes() -> None:
    """Every kim action class resolves to the same destructive-shell risk set."""

    for action_class, risk_classes in KIM_ACTION_RISK_CLASSES.items():
        assert risk_classes_for_command_action(action_class) == risk_classes
