"""HGP-156: managed restrictions and immutable floors cannot be weakened."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_fields_core import ManagedControlsPolicyError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
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
from codex_plugin_scanner.guard.runtime.extension_control_resolver import (
    compose_control_layers,
    resolve_extension_controls,
)
from tests.test_managed_controls_policy_fields import _document, _parse


def _catalog_ids() -> tuple[str, str]:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions[0]
    return extension.extension_id, extension.permissions[0].permission_id


def _layer(kind: ControlLayerKind, *controls: ExtensionControl, lockdown: bool = False) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=kind,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=lockdown,
        controls=controls,
    )


def test_local_enable_cannot_override_managed_disable() -> None:
    extension_id, permission_id = _catalog_ids()
    composed = compose_control_layers(
        (
            _layer(
                ControlLayerKind.LOCAL_ADMIN,
                ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission_id), ControlState.ENABLED),
            ),
            _layer(
                ControlLayerKind.SIGNED_CLOUD,
                ExtensionControl(ControlTarget(ControlTargetKind.PERMISSION, permission_id), ControlState.DISABLED),
            ),
        )
    )
    assert composed.state_for(ControlTargetKind.PERMISSION, permission_id) is ControlState.DISABLED
    resolution = resolve_extension_controls(
        (
            _layer(
                ControlLayerKind.LOCAL_ADMIN,
                ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, extension_id), ControlState.ENABLED),
            ),
            _layer(
                ControlLayerKind.SIGNED_CLOUD,
                ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, extension_id), ControlState.DISABLED),
            ),
        ),
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(permission_id,),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    assert resolution.blocked is True
    assert resolution.factors[0].reason_code == "control.disabled-extension"


def test_lockdown_trusted_recovery_is_limited() -> None:
    extension_id, permission_id = _catalog_ids()
    layers = (
        _layer(
            ControlLayerKind.SIGNED_CLOUD,
            ExtensionControl(ControlTarget(ControlTargetKind.EXTENSION, extension_id), ControlState.DISABLED),
            lockdown=True,
        ),
    )
    blocked = resolve_extension_controls(
        layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(permission_id,),
        surface=ControlSurface.COMMAND_EVALUATION,
    )
    recovered = resolve_extension_controls(
        layers,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        extension_ids=(extension_id,),
        permission_ids=(permission_id,),
        surface=ControlSurface.TRUSTED_LOCAL_RECOVERY,
    )
    assert blocked.blocked is True
    assert blocked.factors[0].reason_code == "control.global-lockdown"
    assert recovered.blocked is True
    assert recovered.factors[0].reason_code == "control.disabled-extension"


def test_managed_restrictive_enable_is_rejected() -> None:
    document = _document()
    document["x-hol-extension-controls"]["controls"][0]["state"] = "enabled"
    with pytest.raises(ManagedControlsPolicyError, match="cannot enable") as error:
        _parse(document)
    assert error.value.code == "managed_restrictive_broadening"
