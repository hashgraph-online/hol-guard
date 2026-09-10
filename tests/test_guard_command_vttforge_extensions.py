"""Structured VTTForge command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

VTTFORGE_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "vttforge init my-system",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "vttforge init my-system --type system --lang ts --yes",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "vttforge init my-module --type module --no-install --no-git",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "vttforge lint ./packages/my-system --fix --no-audit",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "vttforge migrate --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "vttforge migrate ./my-system --write --strict",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "vttforge migrate --data-models --style sdk --lang ts --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "vttforge migrate --sheets --write --json",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    # Unresolved expansions may supply the writing flag, so they are reviewed.
    (
        "vttforge lint $FLAGS",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "vttforge lint ./my-system ${LINT_FLAGS}",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "vttforge migrate $(echo --write)",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "vttforge migrate ./my-system `cat flags`",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
)


def test_vttforge_writing_commands_reach_review_when_enabled(tmp_path: Path) -> None:
    """The scaffold, the lint fix and the written migration attribute to the VTTForge rules."""

    for command, _action_class, expected_rule in VTTFORGE_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.vttforge"}
        assert expected_rule in matched, command


def test_vttforge_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in VTTFORGE_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.vttforge" for item in evaluation.extension_observations)


VTTFORGE_SAFE_COMMANDS: tuple[str, ...] = (
    "vttforge audit",
    "vttforge audit ./my-system --strict --json",
    "vttforge lint",
    "vttforge lint ./my-system --strict",
    "vttforge lint --no-audit",
    "vttforge migrate",  # preview by default: reports, writes nothing
    "vttforge migrate ./my-system --strict",
    "vttforge migrate --json",
    "vttforge migrate --data-models --style sdk",  # still a preview without --write
    "vttforge migrate --sheets --lang ts",
    "vttforge --help",
    "vttforge init --help",
    "vttforge init -h",
    "vttforge lint --help",
    "vttforge migrate --help",
)


def test_vttforge_read_only_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(VTTFORGE_SAFE_COMMANDS, tmp_path)


def test_vttforge_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.vttforge")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
