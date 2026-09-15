"""Structured Blaizio CLI command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

_BLAIZIO_RULE_IDS = frozenset(
    {
        "command.blaizio.add",
        "command.blaizio.update",
        "command.blaizio.remove",
        "command.blaizio.uninstall",
    }
)


def _enable_blaizio() -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.EXTENSION, "command.blaizio"),
                state=ControlState.ENABLED,
            ),
        ),
    )


BLAIZIO_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    (
        "blaizio add button",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add button dialog --namespace MyApp.Components",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add button --overwrite -y",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add button --force-overwrite --json",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add -p corona --defaults",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add https://example.test/registry/button.json",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add button --dry-run=false",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio add button --unknown-option --dry-run",
        "Blaizio component install command",
        "command.blaizio.add",
    ),
    (
        "blaizio update",
        "Blaizio component update command",
        "command.blaizio.update",
    ),
    (
        "blaizio update button --force",
        "Blaizio component update command",
        "command.blaizio.update",
    ),
    (
        "blaizio update -y --json",
        "Blaizio component update command",
        "command.blaizio.update",
    ),
    (
        "blaizio update --cwd ./src/App",
        "Blaizio component update command",
        "command.blaizio.update",
    ),
    (
        "blaizio update --registry https://example.test/registry",
        "Blaizio component update command",
        "command.blaizio.update",
    ),
    (
        "blaizio remove button",
        "Blaizio component remove command",
        "command.blaizio.remove",
    ),
    (
        "blaizio remove button --force -y",
        "Blaizio component remove command",
        "command.blaizio.remove",
    ),
    (
        "blaizio rm button dialog",
        "Blaizio component remove command",
        "command.blaizio.remove",
    ),
    (
        "blaizio uninstall",
        "Blaizio uninstall command",
        "command.blaizio.uninstall",
    ),
    (
        "blaizio uninstall -y",
        "Blaizio uninstall command",
        "command.blaizio.uninstall",
    ),
    (
        "blaizio un --json",
        "Blaizio uninstall command",
        "command.blaizio.uninstall",
    ),
)


BLAIZIO_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    ("dotnet blaizio add button", "command.blaizio.add"),
    ("dotnet tool run blaizio add button", "command.blaizio.add"),
    ("exec blaizio add button", "command.blaizio.add"),
    ("exec dotnet blaizio add button", "command.blaizio.add"),
    ("xargs blaizio add", "command.blaizio.add"),
    ("xargs -n 1 blaizio add", "command.blaizio.add"),
    ("xargs -n 1 dotnet blaizio add", "command.blaizio.add"),
    ("dotnet blaizio update --force", "command.blaizio.update"),
    ("dotnet tool run blaizio update", "command.blaizio.update"),
    ("exec blaizio update", "command.blaizio.update"),
    ("xargs -n 1 blaizio update", "command.blaizio.update"),
    ("dotnet blaizio remove button", "command.blaizio.remove"),
    ("dotnet blaizio rm button", "command.blaizio.remove"),
    ("exec dotnet blaizio remove button", "command.blaizio.remove"),
    ("dotnet blaizio uninstall", "command.blaizio.uninstall"),
    ("dotnet tool run blaizio un", "command.blaizio.uninstall"),
    ("blaizio.exe add button", "command.blaizio.add"),
    ("blaizio.cmd update", "command.blaizio.update"),
    ("cd ./src/App && blaizio add button", "command.blaizio.add"),
    ("blaizio search button | xargs blaizio add", "command.blaizio.add"),
)


def test_blaizio_module_and_wrapper_invocations_reach_review(tmp_path: Path) -> None:
    """Tool-runner and wrapper invocations reach review and attribute to Blaizio rules."""

    for command, expected_rule in BLAIZIO_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.blaizio"}
        assert expected_rule in matched, command


def test_blaizio_direct_invocations_attribute_to_declared_rules(tmp_path: Path) -> None:
    """Every destructive case produces evidence owned by the declared Blaizio rule."""

    for command, _action_class, rule_id in BLAIZIO_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.blaizio"}
        assert rule_id in matched, command


def test_blaizio_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    for command, _action_class, rule_id in BLAIZIO_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.blaizio" for item in evaluation.extension_observations)


def test_blaizio_rules_control_review_once_enabled(tmp_path: Path) -> None:
    """With a local-admin enable, every destructive case is controlled by its declared rule."""

    failures: list[str] = []
    for command, action_class, rule_id in BLAIZIO_REVIEW_CASES:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_enable_blaizio(),),
        )
        if evaluation.controlling_rule_id != rule_id or evaluation.controlling_action_class != action_class:
            actual = (evaluation.controlling_rule_id, evaluation.controlling_action_class)
            failures.append(f"{command!r}: got {actual!r}, expected {(rule_id, action_class)!r}")
    assert not failures, "\n".join(failures)


def test_blaizio_previews_stay_safe_once_enabled(tmp_path: Path) -> None:
    """Safe variants suppress the base match even when the extension is enabled."""

    failures: list[str] = []
    for command in BLAIZIO_SAFE_COMMANDS:
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=(_enable_blaizio(),),
        )
        effective = [
            item.rule.rule_id
            for item in evaluation.extension_observations
            if item.extension.extension_id == "command.blaizio" and item.effective_evidence
        ]
        if effective or evaluation.controlling_rule_id in _BLAIZIO_RULE_IDS:
            failures.append(f"{command!r}: effective={effective!r}, controlling={evaluation.controlling_rule_id!r}")
    assert not failures, "\n".join(failures)


BLAIZIO_SAFE_COMMANDS: tuple[str, ...] = (
    # --dry-run runs the same resolution and local-edit conflict scan as a real run, writes nothing.
    "blaizio add button --dry-run",
    "blaizio add --dry-run button dialog",
    "blaizio add button --overwrite --dry-run",
    "blaizio add button --force-overwrite --dry-run --json",
    "blaizio add button --namespace MyApp.Components --dry-run",
    "blaizio add -p corona --dry-run",
    "blaizio add button --dry-run -y",
    "blaizio add button --dry-run --cwd ./src/App",
    "blaizio add button --dry-run --registry https://example.test/registry",
    "blaizio update --dry-run",
    "blaizio update --dry-run --json",
    "blaizio update button --force --dry-run",
    "blaizio update -y --dry-run",
    "blaizio remove button --dry-run",
    "blaizio remove button --force --dry-run",
    "blaizio rm button --dry-run",
    "blaizio uninstall --dry-run",
    "blaizio un --dry-run --json",
    "dotnet blaizio add button --dry-run",
    "dotnet tool run blaizio update --dry-run",
    "exec blaizio remove button --dry-run",
    "xargs -n 1 blaizio add --dry-run",
    # add --diff compares against upstream (exit 1 on drift); add --view prints an item's files.
    "blaizio add --diff",
    "blaizio add button --diff",
    "blaizio add --diff ./Components/Ui",
    "blaizio add --diff=./Components/Ui --json",
    "blaizio add --view button",
    "blaizio add button --view --json",
    # Read-only commands never carry a Blaizio rule.
    "blaizio view button",
    "blaizio search button",
    "blaizio list",
    "blaizio info --json",
    "blaizio docs button",
    "blaizio contrast",
    "blaizio preset decode 3.abc",
    "blaizio registry list",
    "blaizio tailwind detect",
    "blaizio --help",
    "blaizio add --help",
    "blaizio update --help",
    "blaizio remove --help",
    "blaizio uninstall --help",
    "blaizio add -h",
    "dotnet blaizio add --help",
)


def test_blaizio_preview_and_help_commands_remain_safe(tmp_path: Path) -> None:
    assert_safe_command_cases(BLAIZIO_SAFE_COMMANDS, tmp_path)


def test_blaizio_extension_publishes_official_reference() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.blaizio")
    assert extension is not None
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)
