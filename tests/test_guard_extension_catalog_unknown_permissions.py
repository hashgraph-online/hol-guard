"""HGP-186: unknown permission and catalog upgrades stay understandable."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_catalog_guidance import catalog_upgrade_status
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls

_OTHER_DIGEST = "ab" * 32


def test_catalog_mismatch_is_not_applied_and_names_the_device_update() -> None:
    permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0].permissions[0]
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=_OTHER_DIGEST,
        global_lockdown=False,
        controls=(
            ExtensionControl(
                target=ControlTarget(ControlTargetKind.PERMISSION, permission.permission_id),
                state=ControlState.DISABLED,
            ),
        ),
    )
    resolution = resolve_extension_controls(
        (layer,),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(),
        permission_ids=(permission.permission_id,),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    status = catalog_upgrade_status(
        resolution,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime_version="test-runtime",
        missing_permission_ids=("command.missing.permission.x",),
    )
    assert status["applied"] is False
    assert ResolverFailureCode.CATALOG_DIGEST_MISMATCH.value in status["failure_codes"]
    assert status["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert status["preserve_approved_restrictions"] is True
    assert "Update this device" in str(status["next_action"])


def test_current_catalog_rejects_unknown_permission_with_specific_guidance() -> None:
    missing = "command.missing.permission.x"
    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    layer = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.SIGNED_CLOUD,
        catalog_digest=registry.catalog_digest,
        global_lockdown=False,
        controls=(
            ExtensionControl(target=ControlTarget(ControlTargetKind.PERMISSION, missing), state=ControlState.DISABLED),
        ),
    )
    resolution = resolve_extension_controls(
        (layer,),
        registry=registry,
        extension_ids=(),
        permission_ids=(missing,),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    status = catalog_upgrade_status(
        resolution, registry=registry, runtime_version="test-runtime", missing_permission_ids=(missing,)
    )
    assert status["applied"] is False
    assert status["failure_codes"] == (ResolverFailureCode.UNKNOWN_PERMISSION_TARGET.value,) * 2
    assert resolution.blocked is True
    assert missing in status["next_action"]
    assert "upgrade" in status["next_action"]
    assert status["preserve_approved_restrictions"] is True
