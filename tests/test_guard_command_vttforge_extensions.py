"""Structured VTTForge command extension tests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import tomllib

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
    # The exec and xargs wrappers keep the executable.
    (
        "exec vttforge init my-system",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "xargs -n 1 vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "exec vttforge migrate --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "xargs vttforge migrate ./my-system $FLAGS",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    # Wrapper options that take a value must not pass their operand off as the executable.
    (
        "exec -a vtt vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "xargs -a targets vttforge migrate --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "xargs --max-args 1 -a targets vttforge init",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "xargs -a targets vttforge lint $FLAGS",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "exec -a vtt vttforge $ARGS --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    # Flag-only wrapper options must not hide the wrapped command.
    (
        "xargs -0 vttforge migrate --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "xargs --null -t vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "xargs -0rt vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "xargs --no-run-if-empty vttforge migrate --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "exec -c vttforge init my-system",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "xargs -0 vttforge lint $FLAGS",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "xargs --verbose vttforge $ARGS --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    # Matching is case-insensitive, so -r / -R and -p / -P read both ways.
    (
        "xargs -r vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "xargs -p vttforge init my-system",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "xargs -R 5 vttforge lint --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "xargs -P 4 vttforge migrate --write",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "xargs -I {} vttforge init {}",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "xargs -L 1 vttforge migrate $FLAGS",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    (
        "xargs -r vttforge.exe lint $FLAGS",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    # An option the matcher does not know may or may not take the next token.
    (
        "xargs --unknown-option vttforge init my-system",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "xargs --unknown-option value vttforge lint $FLAGS",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    # An expanded subcommand next to a literal writing flag goes to that rule.
    (
        "vttforge $SUBCOMMAND --fix",
        "VTTForge lint fix command",
        "command.vttforge.lint-fix",
    ),
    (
        "vttforge $(pick) ./my-system --write --strict",
        "VTTForge migration write command",
        "command.vttforge.migrate-write",
    ),
    # An expanded subcommand with no literal writing flag may still be init.
    (
        "vttforge $VTTFORGE_ARGS",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "vttforge ${SUB} my-system --yes",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "vttforge `cat sub` $FLAGS",
        "VTTForge project scaffold command",
        "command.vttforge.init",
    ),
    (
        "exec vttforge $ARGS",
        "VTTForge project scaffold command",
        "command.vttforge.init",
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
    # --help ends the command before anything runs, whatever else is on the line.
    "vttforge lint --fix --help",
    "vttforge migrate --write --help",
    "vttforge init my-system --yes -h",
    "vttforge lint $FLAGS --help",
    "vttforge migrate ${FLAGS} --help",
    "vttforge $SUBCOMMAND --help",
    "vttforge $(pick) --write --help",
    "exec vttforge $ARGS --help",
    "xargs -n 1 vttforge lint $FLAGS --help",
    # Read-only subcommands take no writing flag, expanded or not.
    "vttforge audit $FLAGS",
    "xargs vttforge audit ./my-system",
    "xargs -a targets vttforge audit",
    "exec -a vtt vttforge migrate --write --help",
    "exec vttforge.cmd lint --fix --help",
    "xargs vttforge.exe audit ./my-system",
    # Flag-only wrapper options leave the read-only forms read-only.
    "xargs -0 vttforge lint",
    "xargs -r vttforge migrate ./my-system",
    "xargs -P 4 vttforge audit",
    "xargs -r vttforge lint --fix --help",
    # A value option's operand is not the wrapped command.
    "xargs -a vttforge lint --fix",
)


def test_vttforge_read_only_and_preview_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(VTTFORGE_SAFE_COMMANDS, tmp_path)


def test_vttforge_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.vttforge")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)


def test_expanded_subcommand_is_attributed_to_one_rule(tmp_path: Path) -> None:
    """A line that may expand into a write is reviewed under exactly one VTTForge rule."""

    for command, expected_rule in (
        ("vttforge $SUBCOMMAND --fix", "command.vttforge.lint-fix"),
        ("vttforge $SUBCOMMAND --write", "command.vttforge.migrate-write"),
        ("vttforge $SUBCOMMAND", "command.vttforge.init"),
    ):
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = sorted(
            item.rule.rule_id
            for item in observations
            if item.extension.extension_id == "command.vttforge" and item.effective_evidence
        )
        assert matched == [expected_rule], command


def test_windows_launcher_names_are_matched_through_an_expansion(tmp_path: Path) -> None:
    """The expansion path reads `.cmd` and `.exe` the same way the literal path does.

    `executable_names` gives every matcher the three portable launcher names. The
    expansion matcher built its own single-name set, so a Windows launcher whose
    writing flag arrives from a shell expansion went unreviewed.
    """

    for command in (
        "vttforge.cmd lint $FLAGS",
        "vttforge.exe lint $FLAGS",
        "vttforge.CMD lint $FLAGS",
        "exec vttforge.cmd lint $FLAGS",
        "xargs -n 1 vttforge.EXE lint $FLAGS",
    ):
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = sorted(
            item.rule.rule_id
            for item in observations
            if item.extension.extension_id == "command.vttforge" and item.effective_evidence
        )
        assert matched == ["command.vttforge.lint-fix"], command


def test_windows_launcher_names_are_matched_through_a_wrapper(tmp_path: Path) -> None:
    """A wrapper passes the launcher as an argument, so `.cmd` and `.exe` are matched there too."""

    for command, expected_rule in (
        ("exec vttforge.cmd init my-system", "command.vttforge.init"),
        ("exec vttforge.CMD $ARGS", "command.vttforge.init"),
        ("xargs vttforge.exe lint --fix", "command.vttforge.lint-fix"),
        ("xargs vttforge.exe migrate --write", "command.vttforge.migrate-write"),
        ("exec -a vtt vttforge.cmd $ARGS --write", "command.vttforge.migrate-write"),
    ):
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = sorted(
            item.rule.rule_id
            for item in observations
            if item.extension.extension_id == "command.vttforge" and item.effective_evidence
        )
        assert matched == [expected_rule], command


_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONTRIBUTION = "contributions/extensions/command.vttforge.json"
_PACKAGED_CONTRIBUTION = "extensions/contributions/command.vttforge.json"


def test_vttforge_contribution_ships_in_wheel_and_frozen_builds() -> None:
    """Packaged builds carry the contribution, so the catalog matches a source checkout."""

    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force_include = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert force_include[_CONTRIBUTION] == f"codex_plugin_scanner/guard/contracts/data/{_PACKAGED_CONTRIBUTION}"

    script = _REPO_ROOT / "scripts/release/stage_guard_cloud_review_artifacts.py"
    spec = importlib.util.spec_from_file_location("stage_guard_cloud_review_artifacts", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._ARTIFACTS[_CONTRIBUTION] == _PACKAGED_CONTRIBUTION

    contribution = json.loads((_REPO_ROOT / _CONTRIBUTION).read_text(encoding="utf-8"))
    assert contribution["id"] == "command.vttforge"
    assert contribution["publisher"]["id"]
    assert contribution["icon"]["name"]
