"""Canonical effective-state projection for Extension Control Center clients."""

from __future__ import annotations

from typing import Final

from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_contract import (
    ControlLayerKind,
    ControlSurface,
    ControlTargetKind,
    ExtensionControlLayer,
)
from ..runtime.extension_control_resolver import resolve_extension_controls
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

EFFECTIVE_PROJECTION_SCHEMA: Final = "guard.daemon.extension-control-projection.v1"
_MAX_PROJECTION_EXTENSIONS: Final = 512
_MAX_PROJECTION_PERMISSIONS: Final = 4096


def _explicit_layer_state(
    layers: tuple[ExtensionControlLayer, ...],
    layer_kind: ControlLayerKind,
    target_kind: ControlTargetKind,
    target_id: str,
) -> str:
    for layer in layers:
        if layer.kind is not layer_kind:
            continue
        for control in layer.controls:
            if control.target.kind is target_kind and control.target.target_id == target_id:
                return control.state.value
    return "inherited"


def _reason_codes(resolution: object) -> list[str]:
    # Keep this DTO human-safe and independent from private decision evidence.
    factors = getattr(resolution, "factors", ())
    failures = getattr(resolution, "failures", ())
    values = {str(factor.reason_code) for factor in factors}
    values.update(f"resolver.{failure.code.value}" for failure in failures)
    return sorted(values)


def build_effective_extension_control_projection(
    registry: CommandSafetyExtensionRegistry,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> dict[str, object]:
    """Project authoritative effective state using the production resolver."""

    extension_items: list[dict[str, object]] = []
    for extension in registry.extensions[:_MAX_PROJECTION_EXTENSIONS]:
        resolution = resolve_extension_controls(
            snapshot.layers,
            registry,
            extension_ids=(extension.extension_id,),
            permission_ids=(),
            surface=ControlSurface.COMMAND_EVALUATION,
            authority_failure=snapshot.authority_failure,
        )
        extension_items.append(
            {
                "extension_id": extension.extension_id,
                "effective_state": "blocked" if resolution.blocked else "allowed",
                "local_state": _explicit_layer_state(
                    snapshot.layers,
                    ControlLayerKind.LOCAL_ADMIN,
                    ControlTargetKind.EXTENSION,
                    extension.extension_id,
                ),
                "managed_state": _explicit_layer_state(
                    snapshot.layers,
                    ControlLayerKind.SIGNED_CLOUD,
                    ControlTargetKind.EXTENSION,
                    extension.extension_id,
                ),
                "required": extension.required,
                "reason_codes": _reason_codes(resolution),
            }
        )

    permission_items: list[dict[str, object]] = []
    for permission in registry.permissions[:_MAX_PROJECTION_PERMISSIONS]:
        resolution = resolve_extension_controls(
            snapshot.layers,
            registry,
            extension_ids=(),
            permission_ids=(permission.permission_id,),
            surface=ControlSurface.COMMAND_EVALUATION,
            authority_failure=snapshot.authority_failure,
        )
        permission_items.append(
            {
                "permission_id": permission.permission_id,
                "extension_id": permission.extension_id,
                "effective_state": "blocked" if resolution.blocked else "allowed",
                "local_state": _explicit_layer_state(
                    snapshot.layers,
                    ControlLayerKind.LOCAL_ADMIN,
                    ControlTargetKind.PERMISSION,
                    permission.permission_id,
                ),
                "managed_state": _explicit_layer_state(
                    snapshot.layers,
                    ControlLayerKind.SIGNED_CLOUD,
                    ControlTargetKind.PERMISSION,
                    permission.permission_id,
                ),
                "configurable": permission.configurable,
                "fixed_reason": permission.fixed_reason,
                "reason_codes": _reason_codes(resolution),
            }
        )

    return {
        "schema_version": EFFECTIVE_PROJECTION_SCHEMA,
        "revision": snapshot.revision,
        "catalog_digest": snapshot.catalog_digest,
        "health": snapshot.health.value,
        "extensions": extension_items,
        "permissions": permission_items,
    }
