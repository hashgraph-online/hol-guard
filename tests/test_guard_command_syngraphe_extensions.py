"""Syngraphe command coverage through inspection, runtime, and catalog contracts."""

from __future__ import annotations

import json
from collections.abc import Iterator
from itertools import combinations, permutations
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from tests.command_extension_contracts import assert_reviewed_command_cases, assert_safe_command_cases

_EXTENSION_ID = "command.syngraphe"
_MUTATIONS = (
    ("init", "init", "Syngraphe initialization command"),
    *(
        (f"{category} new example", "document-new", "Syngraphe document creation command")
        for category in ("truth", "decision", "state", "history")
    ),
    ("state archive example", "state-archive", "Syngraphe state archive command"),
)


@pytest.fixture
def syngraphe_enabled() -> Iterator[None]:
    """Exercise an external extension through normal local opt-in authority."""
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, _EXTENSION_ID), ControlState.ENABLED),),
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED, 1, BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest, (layer,)
        )
    )
    with use_extension_control_snapshot(snapshot):
        yield


@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
@pytest.mark.parametrize(("arguments", "rule", "action"), _MUTATIONS)
def test_mutations_require_review(
    executable: str, arguments: str, rule: str, action: str, tmp_path: Path, syngraphe_enabled: None
) -> None:
    commands = (
        f"{executable} {arguments}",
        f"{executable} {arguments} --json",
        f'{executable} --scope "packages/api context" {arguments}',
        f'{executable} {arguments} --scope "packages/api context"',
    )
    if " new " in arguments:
        commands += (
            f'{executable} {arguments} --title "Domain model"',
            f'{executable} {arguments} --title "--dry-run"',
            f'{executable} {arguments} --title "--help"',
            f'{executable} {arguments} --title "-h"',
            f'{executable} {arguments} --title "--version"',
            f'{executable} {arguments} --title "-v"',
            f'{executable} {arguments} --title="--dry-run"',
        )
    assert_reviewed_command_cases(tuple((command, action, f"{_EXTENSION_ID}.{rule}") for command in commands), tmp_path)


@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
@pytest.mark.parametrize(("arguments", "rule", "action"), _MUTATIONS)
def test_every_mutation_has_rule_local_previews_and_help(
    executable: str, arguments: str, rule: str, action: str, tmp_path: Path, syngraphe_enabled: None
) -> None:
    safe_options = ("--dry-run", "--dry-run --json", "--json --dry-run", "--help", "-h", "--version", "-v")
    commands = tuple(
        command
        for flags in safe_options
        for command in (
            f"{executable} {arguments} {flags}",
            f'{executable} --scope "packages/api context" {arguments} {flags}',
            f'{executable} {arguments} {flags} --scope "packages/api context"',
        )
    )
    assert_safe_command_cases(commands, tmp_path)
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
        parse_shell_command(f"{executable} {arguments} --json --dry-run", cwd=tmp_path, home_dir=tmp_path)
    )
    owned = [item for item in observations if item.extension.extension_id == _EXTENSION_ID]
    assert len(owned) == 1
    assert owned[0].rule.rule_id == f"{_EXTENSION_ID}.{rule}"
    assert owned[0].safe_segment_indexes == {0}
    assert not owned[0].effective_evidence
    assert {variant.variant_id for variant in owned[0].safe_variants} == {"dry-run"}


def _flag_combinations(*options: str) -> Iterator[str]:
    for count in range(len(options) + 1):
        for subset in combinations(options, count):
            for order in permutations(subset):
                yield " ".join(order)


@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
def test_complete_read_only_surface(executable: str, tmp_path: Path, syngraphe_enabled: None) -> None:
    commands = [f"{executable} {flag}" for flag in ("-v", "--version", "-h", "--help")]
    for family, flags in (
        ("status", ("--all",)),
        ("check", ("--all", "--json", "--strict")),
        ("stats", ("--all", "--json", "--budget 12000")),
        *((f"{category} list", ()) for category in ("truth", "decision", "state", "history")),
    ):
        for options in _flag_combinations(*flags):
            commands.append(f"{executable} {family} {options}")
            # --all and --scope are mutually exclusive in Syngraphe.
            if "--all" not in options:
                commands.extend(
                    (
                        f'{executable} --scope "packages/api context" {family} {options}',
                        f'{executable} {family} {options} --scope "packages/api context"',
                    )
                )
        commands.extend(f"{executable} {family} {help_flag}" for help_flag in ("-h", "--help"))
    commands.extend(
        (
            f"{executable} decision --help",
            f'printf "%s" "{executable} state new example"',
        )
    )
    assert_safe_command_cases(tuple(commands), tmp_path)


@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
def test_reordered_options_and_quoted_values(executable: str, tmp_path: Path, syngraphe_enabled: None) -> None:
    for options in permutations(('--scope "packages/api context"', '--title "Use PostgreSQL"', "--json", "--dry-run")):
        assert_safe_command_cases((f'{executable} decision new "use-postgres" {" ".join(options)}',), tmp_path)
    assert_safe_command_cases(
        (
            f"{executable} --scope=packages/api decision --dry-run new example --json",
            f'{executable} decision new --title "--dry-run" --dry-run example',
            f"{executable} --dry-run init --json",
        ),
        tmp_path,
    )


@pytest.mark.parametrize("executable", ("syngraphe", "syg", "syngraphe.cmd", "syg.cmd", "syngraphe.exe", "syg.exe"))
@pytest.mark.parametrize(
    "wrapper", ("", "env MODE=test ", "sudo -u nobody ", "command ", "nice -n 5 ", "exec ", "xargs -n 1 ")
)
def test_launchers_and_wrappers(executable: str, wrapper: str, tmp_path: Path, syngraphe_enabled: None) -> None:
    command = f"{wrapper}{executable} state new example"
    assert_reviewed_command_cases(
        ((command, "Syngraphe document creation command", f"{_EXTENSION_ID}.document-new"),), tmp_path
    )
    assert_safe_command_cases((f"{command} --dry-run --json",), tmp_path)


@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
@pytest.mark.parametrize("separator", (";", "&&", "||", "|", "\n"))
def test_safe_segments_cannot_suppress_mutations(
    executable: str, separator: str, tmp_path: Path, syngraphe_enabled: None
) -> None:
    command = f"{executable} state new preview --dry-run {separator} {executable} state new persist"
    assert_reviewed_command_cases(
        ((command, "Syngraphe document creation command", f"{_EXTENSION_ID}.document-new"),), tmp_path
    )
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(parse_shell_command(command))
    owned = next(item for item in observations if item.extension.extension_id == _EXTENSION_ID)
    assert {item.segment_index for item in owned.matcher_evidence} == {0, 1}
    assert owned.safe_segment_indexes == {0}
    assert {item.segment_index for item in owned.effective_evidence} == {1}


@pytest.mark.parametrize(
    "command",
    (
        "syg init --dry-run && rm -rf build",
        "rm -rf build ; syngraphe state new example --dry-run",
        'sh -c "syg state new example --dry-run" && rm -rf build',
        'syg state new example --title "$(rm -rf build)" --dry-run',
    ),
)
def test_other_extensions_keep_their_evidence(command: str, tmp_path: Path, syngraphe_enabled: None) -> None:
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert evaluation.minimum_action in {"review", "block"}
    assert evaluation.controlling_rule_id is not None
    assert not evaluation.controlling_rule_id.startswith(f"{_EXTENSION_ID}.")
    assert any(item.extension.extension_id == "command.filesystem" for item in evaluation.extension_observations)
    assert any(item.extension.extension_id == _EXTENSION_ID for item in evaluation.extension_observations)


@pytest.mark.parametrize(
    "arguments",
    (
        'state new example --scope "--dry-run"',
        'state new example --scope "--help"',
        'state new example --scope "-h"',
        "state new example -- --dry-run",
        "state new example --unknown --dry-run",
        "state new example --unknown --help",
        'state new example --dry-run "unterminated',
        "state new example $OPTIONS --dry-run",
        "state new example ${OPTIONS} --dry-run",
        "state new example --dry-run=false",
        "state new example --dry-run=true",
        "state new example --DRY-RUN",
    ),
)
@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
def test_uncertain_or_non_flag_previews_still_require_review(
    executable: str, arguments: str, tmp_path: Path, syngraphe_enabled: None
) -> None:
    assert_reviewed_command_cases(
        ((f"{executable} {arguments}", "Syngraphe document creation command", f"{_EXTENSION_ID}.document-new"),),
        tmp_path,
    )


def test_external_extension_is_inert_by_default(tmp_path: Path) -> None:
    for arguments, _rule, _action in _MUTATIONS:
        evaluation = evaluate_command(f"syg {arguments}", cwd=tmp_path, home_dir=tmp_path)
        assert all(item.extension.extension_id != _EXTENSION_ID for item in evaluation.extension_observations)
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    assert extension.to_dict()["activation"] == "opt-in"
    assert extension.to_dict()["enabled"] is False


@pytest.mark.parametrize("executable", ("syngraphe", "syg"))
def test_shell_wrappers_suffixes_and_executable_paths(executable: str, tmp_path: Path, syngraphe_enabled: None) -> None:
    for command in (
        f'sh -c "{executable} state new example"',
        f"true && command {executable} state new example",
        f"true ; exec {executable} state new example",
        f"true && env MODE=test {executable} state new example",
        f'"/opt/example tools/{executable}" state new example',
    ):
        assert_reviewed_command_cases(
            ((command, "Syngraphe document creation command", f"{_EXTENSION_ID}.document-new"),), tmp_path
        )
    assert_safe_command_cases(
        (
            f'sh -c "{executable} state new example --dry-run --json"',
            f"true && command {executable} state new example --dry-run",
            f"true ; exec {executable} state new example --dry-run",
            f'"/opt/example tools/{executable}" state new example --dry-run',
        ),
        tmp_path,
    )
    assert_reviewed_command_cases(
        (
            (
                f"xargs -I --dry-run {executable} state new example --dry-run",
                "Syngraphe document creation command",
                f"{_EXTENSION_ID}.document-new",
            ),
        ),
        tmp_path,
    )


def test_metadata_ownership_and_evidence_privacy(tmp_path: Path, syngraphe_enabled: None) -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_EXTENSION_ID)
    assert extension is not None
    assert extension.executables == ("syngraphe", "syg")
    assert set(extension.reference_urls) == {"https://github.com/suffro/syngraphe", "https://syngraphe.dev/"}
    assert {rule.rule_id for rule in extension.rules} == {
        f"{_EXTENSION_ID}.init",
        f"{_EXTENSION_ID}.document-new",
        f"{_EXTENSION_ID}.state-archive",
    }
    for rule in extension.rules:
        assert rule.default_mode == "review"
        assert rule.severity == "medium"
        for action in rule.action_classes:
            assert risk_classes_for_command_action(action) == rule.risk_classes
        assert "--dry-run" in rule.safer_alternatives[0]
    command = '/private/example/syg --scope private-scope state new private-document --title "Private title marker"'
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(parse_shell_command(command))
    assert any(item.extension.extension_id == _EXTENSION_ID for item in observations)
    encoded = json.dumps([extension.to_dict(), *(item.to_dict() for item in observations)])
    for private_value in (command, "/private/example", "private-scope", "private-document", "Private title marker"):
        assert private_value not in encoded
    assert not list(tmp_path.iterdir())
