"""Structured SynapseCTRL command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import assert_safe_command_cases

SYNAPSECTRL_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "synapsectrl switch Naga Siege",
        "SynapseCTRL profile switch command",
        "command.synapsectrl.switch",
    ),
    (
        "synapsectrl hook install",
        "SynapseCTRL hook mutation command",
        "command.synapsectrl.hook-mutation",
    ),
    (
        "synapsectrl hook repair",
        "SynapseCTRL hook mutation command",
        "command.synapsectrl.hook-mutation",
    ),
    (
        "synapsectrl hook uninstall",
        "SynapseCTRL hook mutation command",
        "command.synapsectrl.hook-mutation",
    ),
)

SYNAPSECTRL_LAUNCHER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("synapsectrl.exe switch Naga Siege", "command.synapsectrl.switch"),
    ("python -m synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("python3 -m synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("py -m synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("uv run synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("uv run python -m synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("uv run python3 -m synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("uv tool run synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("uvx synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("exec synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("xargs synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("xargs -n 1 synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("xargs -n 1 python -m synapsectrl switch Naga Siege", "command.synapsectrl.switch"),
    ("python -m synapsectrl hook install", "command.synapsectrl.hook-mutation"),
    ("uv run synapsectrl hook repair", "command.synapsectrl.hook-mutation"),
    ("uv tool run synapsectrl hook uninstall", "command.synapsectrl.hook-mutation"),
)

SYNAPSECTRL_READ_ONLY_COMMANDS: tuple[str, ...] = (
    "synapsectrl status",
    "synapsectrl devices",
    "synapsectrl profiles Naga",
    "synapsectrl resolve device Naga",
    "synapsectrl resolve profile Naga Siege",
    "synapsectrl doctor",
    "synapsectrl hook status",
    "python -m synapsectrl devices",
    "py -m synapsectrl profiles Naga",
    "uv run synapsectrl resolve device Naga",
    "uv tool run synapsectrl hook status",
    "uvx synapsectrl status",
)

SYNAPSECTRL_SAFE_COMMANDS: tuple[str, ...] = (
    "synapsectrl status",
    "synapsectrl devices",
    "synapsectrl profiles Naga",
    "synapsectrl resolve device Naga",
    "synapsectrl resolve profile Naga Siege",
    "synapsectrl doctor",
    "synapsectrl hook status",
    "synapsectrl --help",
    "synapsectrl --version",
    "synapsectrl switch --help",
    "synapsectrl hook install --help",
    "synapsectrl hook repair --help",
    "synapsectrl hook uninstall --help",
)


def _synapsectrl_rule_ids(command: str, tmp_path: Path) -> set[str]:
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
        parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    )
    return {
        item.rule.rule_id
        for item in observations
        if item.extension.extension_id == "command.synapsectrl" and item.effective_evidence
    }


def test_synapsectrl_mutations_match_the_expected_rules(tmp_path: Path) -> None:
    for command, _action_class, expected_rule in SYNAPSECTRL_REVIEW_CASES:
        assert expected_rule in _synapsectrl_rule_ids(command, tmp_path), command


def test_synapsectrl_launcher_variants_reach_review(tmp_path: Path) -> None:
    """Direct, module, uv, and wrapper launchers retain SynapseCTRL policy."""

    for command, expected_rule in SYNAPSECTRL_LAUNCHER_REVIEW_COMMANDS:
        assert expected_rule in _synapsectrl_rule_ids(command, tmp_path), command


def test_synapsectrl_read_only_commands_stay_quiet(tmp_path: Path) -> None:
    """Inspection commands never produce SynapseCTRL mutation evidence."""

    for command in SYNAPSECTRL_READ_ONLY_COMMANDS:
        assert not _synapsectrl_rule_ids(command, tmp_path), command


def test_synapsectrl_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in SYNAPSECTRL_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.synapsectrl" for item in evaluation.extension_observations)


def test_synapsectrl_read_only_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(SYNAPSECTRL_SAFE_COMMANDS, tmp_path)


def test_synapsectrl_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.synapsectrl")
    assert extension is not None
    assert extension.reference_urls == ("https://github.com/gabrielzv1233/SynapseCTRL",)


def test_synapsectrl_actions_publish_risk_classes() -> None:
    assert risk_classes_for_command_action("SynapseCTRL profile switch command") == ("destructive_shell",)
    assert risk_classes_for_command_action("SynapseCTRL hook mutation command") == ("destructive_shell",)
