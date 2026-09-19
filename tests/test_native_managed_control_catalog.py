"""Actual built-in control catalog and supported command-observation parity."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls


def catalog_payload() -> dict[str, str | list[str]]:
    extensions = tuple(
        extension
        for extension in REGISTRY.extensions
        if extension.source == "built-in" and extension.delegated_protection is None
    )
    known = {extension.extension_id for extension in extensions}
    return {
        "schema": "guard-native-built-in-controls.v1",
        "catalog_digest": REGISTRY.catalog_digest,
        "extension_ids": sorted(known),
        "permission_ids": sorted(
            permission.permission_id for permission in REGISTRY.permissions if permission.extension_id in known
        ),
    }


def test_native_catalog_is_exact_existing_builtin_registry_projection() -> None:
    path = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/policy_scoped_managed_catalog.json"
    assert json.loads(path.read_text()) == catalog_payload()
    assert all("command.package." not in name for name in catalog_payload()["extension_ids"])


def test_supported_generic_commands_have_no_control_observations(tmp_path: Path) -> None:
    commands = (
        "pwd",
        "pwd -P",
        "true",
        "echo Synthetic",
        "echo 'rm -rf /'",
        "printf '%s' Synthetic",
        "whoami",
        "uname -a",
        "ssh synthetic@example.invalid",
    )
    for command in commands:
        result = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert result.extension_observations == (), command
        assert result.matches == (), command
        for lockdown in (False, True):
            for state in (ControlState.ENABLED, ControlState.DISABLED):
                layer = ExtensionControlLayer(
                    schema_version=CONTROL_SCHEMA_VERSION,
                    kind=ControlLayerKind.LOCAL_ADMIN,
                    catalog_digest=REGISTRY.catalog_digest,
                    global_lockdown=lockdown,
                    controls=(
                        ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, "command.filesystem"), state),
                    ),
                )
                resolution = resolve_extension_controls(
                    (layer,), REGISTRY, extension_ids=(), permission_ids=(), surface=ControlSurface.COMMAND_EVALUATION
                )
                assert not resolution.failures
                assert resolution.blocked is lockdown
