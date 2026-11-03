"""Canonical effective-state projection for Extension Control Center clients."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from ..native_extension_control import ControlAnswer, ControlItem, ControlScenario, resolve_scenarios
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_contract import (
    ControlLayerKind,
    ControlSurface,
    ControlTargetKind,
    ExtensionControlLayer,
)
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


def _reason_codes(resolution: ControlAnswer) -> list[str]:
    # Keep this DTO human-safe and independent from private decision evidence.
    values = set(resolution.reason_codes)
    values.update(f"resolver.{failure.code.value}" for failure in resolution.failures)
    return sorted(values)


def build_effective_extension_control_projection(
    registry: CommandSafetyExtensionRegistry,
    snapshot: ExtensionControlRuntimeSnapshot,
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Project authoritative effective state using the production resolver."""

    extensions = registry.extensions[:_MAX_PROJECTION_EXTENSIONS]
    permissions = registry.permissions[:_MAX_PROJECTION_PERMISSIONS]
    # Every item resolves against the same layers: one scenario, answered in order. Each item also asks
    # whether its extension (for a permission, its owner) is active.
    items = (
        *(ControlItem((extension.extension_id,), (), extension.extension_id) for extension in extensions),
        *(ControlItem((), (permission.permission_id,), permission.extension_id) for permission in permissions),
    )
    answers = resolve_scenarios(
        registry,
        (ControlScenario(snapshot.layers, items, ControlSurface.COMMAND_EVALUATION, snapshot.authority_failure),),
        guard_home=guard_home,
        trust_classes=True,
    )[0].items
    extension_answers = answers[: len(extensions)]
    permission_answers = answers[len(extensions) :]

    extension_items: list[dict[str, object]] = []
    for extension, resolution in zip(extensions, extension_answers, strict=True):
        active = resolution.active is True
        extension_items.append(
            {
                "extension_id": extension.extension_id,
                "effective_state": "blocked" if resolution.blocked or not active else "allowed",
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
    for permission, resolution in zip(permissions, permission_answers, strict=True):
        # An owner the registry does not know is never active.
        active = resolution.active is True
        permission_items.append(
            {
                "permission_id": permission.permission_id,
                "extension_id": permission.extension_id,
                "effective_state": "blocked" if resolution.blocked or not active else "allowed",
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
