"""Privacy-safe extension-control authority event payloads."""

from __future__ import annotations

from .runtime.extension_control_contract import ControlState, ControlTargetKind, ExtensionControlLayer

EXTENSION_CONTROL_CHANGE_SCHEMA = "guard.extension-control-authority-change.v1"


def extension_control_change_payload(
    *,
    revision: int,
    previous_revision: int,
    layers: tuple[ExtensionControlLayer, ...],
) -> dict[str, object]:
    """Summarize a control change without actor, proof, nonce, or command data."""

    controls = tuple(control for layer in layers for control in layer.controls)
    return {
        "schema": EXTENSION_CONTROL_CHANGE_SCHEMA,
        "action": "authority.changed",
        "revision": revision,
        "previousRevision": previous_revision,
        "layerKinds": [layer.kind.value for layer in layers],
        "globalLockdown": any(layer.global_lockdown for layer in layers),
        "disabledExtensionCount": sum(
            control.state == ControlState.DISABLED and control.target.kind == ControlTargetKind.EXTENSION
            for control in controls
        ),
        "disabledPermissionCount": sum(
            control.state == ControlState.DISABLED and control.target.kind == ControlTargetKind.PERMISSION
            for control in controls
        ),
        "blockSource": "extension-control-authority",
    }
