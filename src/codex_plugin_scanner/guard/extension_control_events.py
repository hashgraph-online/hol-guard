"""Privacy-safe extension-control authority event payloads."""

from __future__ import annotations

from .runtime.extension_control_contract import ControlState, ControlTargetKind, ExtensionControlLayer


def extension_control_change_payload(
    *,
    revision: int,
    previous_revision: int,
    catalog_digest: str,
    snapshot_digest: str,
    layers: tuple[ExtensionControlLayer, ...],
) -> dict[str, object]:
    """Summarize a control change without actor, proof, nonce, or command data."""

    controls = tuple(control for layer in layers for control in layer.controls)
    return {
        "schema": "guard.extension-control-authority-change.v1",
        "action": "authority.changed",
        "revision": revision,
        "previousRevision": previous_revision,
        "catalogDigest": catalog_digest,
        "snapshotDigest": snapshot_digest,
        "layerKinds": [layer.kind.value for layer in layers],
        "globalLockdown": any(layer.global_lockdown for layer in layers),
        "disabledExtensionCount": sum(
            control.state is ControlState.DISABLED and control.target.kind is ControlTargetKind.EXTENSION
            for control in controls
        ),
        "disabledPermissionCount": sum(
            control.state is ControlState.DISABLED and control.target.kind is ControlTargetKind.PERMISSION
            for control in controls
        ),
        "blockSource": "extension-control-authority",
    }
