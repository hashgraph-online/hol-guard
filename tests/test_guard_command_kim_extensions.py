"""Structured kim command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command

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
        "kim remove morning",
        "kim reminder remove command",
        "command.kim.remove",
    ),
    ("kim remove evening --oneshot", "kim reminder remove command", "command.kim.remove"),
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
    ("kim stop", "kim daemon stop command", "command.kim.stop"),
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


KIM_READONLY_COMMANDS: tuple[str, ...] = (
    "kim list",
    "kim list -o",
    "kim status",
    "kim logs",
    "kim logs -n 100",
    "kim -v",
)
