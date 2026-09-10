"""Dispat release-start coverage through inspection and runtime review."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_dispat_extensions import DispatReleaseMatcher
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import matcher_index_hints
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


@pytest.fixture
def enabled_dispat() -> Iterator[None]:
    """Exercise real local-admin opt-in without changing the user's Guard state."""
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.dispat"), ControlState.ENABLED),
        ),
    )
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(AuthorityHealth.PROTECTED, 1, digest, (layer,))
    )
    with use_extension_control_snapshot(snapshot):
        yield


RELEASE_COMMANDS = (
    "dispat",
    "dispat release",
    "dispat.exe release",
    "dispat.cmd release",
    "'/opt/release tools/dispat' release",
    "dispat --root '/work/my repo' --config release.yaml --log-format json",
    "dispat --package status",
    "dispat --package=status release",
    "dispat release --package status --space tools --group libraries",
    "dispat -pstatus -s tools -glibraries release",
    "dispat release -p=status --strict --require-release",
    "dispat --env-file release.env --concurrency 4,2 --quiet-parser=false",
    "dispat --root --help",
    "dispat -phelp",
    "dispat --help=false",
    "dispat -h=false release",
    "dispat --version=false release",
    "dispat --help --help=false",
    "dispat -h --help=false",
    "dispat --help --help=F",
    "dispat --help=false --version=0 release",
    "dispat release --",
    "dispat --",
    "env CI=1 dispat release",
    "command dispat release",
    "sh -c 'dispat release'",
    "dispat status && dispat release",
    "dispat --help; dispat",
    "dispat release | cat",
)


@pytest.mark.parametrize("command", RELEASE_COMMANDS)
@pytest.mark.usefixtures("enabled_dispat")
def test_release_starts_reach_inspection_and_runtime(command: str, tmp_path: Path) -> None:
    assert_reviewed_command_cases(((command, "Dispat release command", "command.dispat.release"),), tmp_path)


QUIET_COMMANDS = (
    "dispat status",
    "dispat status --strict --require-release",
    "dispat --root '/work/my repo' --package release status",
    "dispat -prelease status --group libraries",
    "dispat --help",
    "dispat -h",
    "dispat release --help",
    "dispat release -h=true",
    "dispat --version",
    "dispat release --version=true",
    "dispat --help=TRUE",
    "dispat --help=T",
    "dispat --version=1",
    "dispat --help=false --help",
    "dispat --help=false -h",
    "dispat -hpapi release",
    "dispat preview --package core",
    "dispat run build",
    "dispat build",
    "dispat Release",
    "dispat init",
    "dispat github",
    "dispat commit --push",
    "dispat self-update",
    "dispat install owner/tool",
    "echo dispat release",
    "grep 'dispat release' README.md",
)


@pytest.mark.parametrize("command", QUIET_COMMANDS)
@pytest.mark.usefixtures("enabled_dispat")
def test_previews_help_and_other_commands_stay_quiet(command: str, tmp_path: Path) -> None:
    assert_safe_command_cases((command,), tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "dispat --root",
        "dispat release extra",
        "dispat --unknown status",
        "dispat release --dry-run",
        "dispat --help=maybe",
        "dispat release -- --help",
        'dispat "release',
    ),
)
@pytest.mark.usefixtures("enabled_dispat")
def test_uncertain_release_shapes_do_not_imply_safety(command: str, tmp_path: Path) -> None:
    parsed = parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
    evidence = DispatReleaseMatcher().match(parsed)
    assert evidence and evidence[0].detail.startswith("Uncertain release invocation:")
    assert_reviewed_command_cases(((command, "Dispat release command", "command.dispat.release"),), tmp_path)


@pytest.mark.usefixtures("enabled_dispat")
def test_preview_does_not_suppress_another_extensions_evidence(tmp_path: Path) -> None:
    parsed = parse_shell_command("dispat status; rm -rf /", cwd=tmp_path, home_dir=tmp_path)
    observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(parsed)
    assert observations
    assert all(item.extension.extension_id != "command.dispat" for item in observations)


def test_metadata_index_and_evidence_contract(tmp_path: Path) -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.dispat")
    assert extension is not None
    assert extension.reference_urls == ("https://github.com/yohimik/dispat", "https://dispat.dev/")
    assert extension.risk_classes == ("execution", "network_egress")
    assert risk_classes_for_command_action("Dispat release command") == ("execution", "network_egress")
    assert extension.permissions
    assert {rule.rule_id for rule in extension.rules} == {"command.dispat.release"}
    hints = matcher_index_hints(DispatReleaseMatcher())
    assert hints.complete and hints.executables == frozenset({"dispat", "dispat.exe", "dispat.cmd"})
    assert not hints.keywords  # The default invocation has no command word to index.
    parsed = parse_shell_command("/private/tools/dispat --root /private/project --package secret-package", cwd=tmp_path)
    evidence = DispatReleaseMatcher().match(parsed)
    encoded = json.dumps([item.to_dict() for item in evidence])
    assert "/private/project" not in encoded
    assert "/private/tools" not in encoded
    assert "secret-package" not in encoded


def test_release_rule_stays_inert_until_local_admin_enable(tmp_path: Path) -> None:
    assert_safe_command_cases(("dispat", "dispat release"), tmp_path)
