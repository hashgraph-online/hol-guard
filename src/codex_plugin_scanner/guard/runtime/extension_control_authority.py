"""Views and layer encoding for the command-extension control authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import cast

from .extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)


class ExtensionControlAuthorityError(RuntimeError):
    """An extension-control authority invariant could not be satisfied."""


class AuthorityPhase(str, Enum):
    PREPARED = "prepared"
    ANCHORED = "anchored"
    COMMITTED = "committed"


class AuthorityHealth(str, Enum):
    UNENROLLED = "unenrolled"
    PROTECTED = "protected"
    DEGRADED_UNACKNOWLEDGED = "degraded-unacknowledged"
    DEGRADED_ACKNOWLEDGED = "degraded-acknowledged"
    TAMPERED = "tampered"
    RECOVERY_REQUIRED = "recovery-required"


@dataclass(frozen=True, slots=True)
class ExtensionControlAuthorityView:
    health: AuthorityHealth
    revision: int
    catalog_digest: str
    layers: tuple[ExtensionControlLayer, ...]
    managed_revision: int = 0
    # The authority was never read, so this view reports no reading rather than
    # a verdict about it. It grants nothing, and the next read replaces it.
    unread: bool = False

    def layers_for(self, surface: ControlSurface) -> tuple[ExtensionControlLayer, ...]:
        if self.health is AuthorityHealth.PROTECTED:
            return self.layers
        if type(surface) is ControlSurface and surface in {
            ControlSurface.TRUSTED_LOCAL_RECOVERY,
            ControlSurface.TRUSTED_LOCAL_PROOF,
        }:
            return ()
        return (
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=ControlLayerKind.LOCAL_ADMIN,
                catalog_digest=self.catalog_digest,
                global_lockdown=True,
                controls=(),
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthorityAnchor:
    revision: int
    snapshot_digest: str
    phase: AuthorityPhase


def layers_to_json(layers: tuple[ExtensionControlLayer, ...]) -> str:
    return _canonical_json([_layer_to_value(layer) for layer in layers])


def layers_from_json(value: str) -> tuple[ExtensionControlLayer, ...]:
    try:
        raw = cast(object, json.loads(value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ExtensionControlAuthorityError("invalid extension control layers") from exc
    if not isinstance(raw, list):
        raise ExtensionControlAuthorityError("invalid extension control layers")
    return tuple(_layer_from_value(item) for item in cast(list[object], raw))


def _layer_to_value(layer: ExtensionControlLayer) -> dict[str, object]:
    return {
        "schema_version": layer.schema_version,
        "kind": layer.kind.value,
        "catalog_digest": layer.catalog_digest,
        "global_lockdown": layer.global_lockdown,
        "controls": [
            {
                "target_kind": control.target.kind.value,
                "target_id": control.target.target_id,
                "state": control.state.value,
            }
            for control in layer.controls
        ],
    }


def _layer_from_value(raw: object) -> ExtensionControlLayer:
    if not isinstance(raw, dict):
        raise ExtensionControlAuthorityError("invalid extension control layer")
    mapping = cast(dict[object, object], raw)
    if any(not isinstance(name, str) for name in mapping):
        raise ExtensionControlAuthorityError("invalid extension control layer")
    value = cast(dict[str, object], mapping)
    controls_raw = value.get("controls")
    if not isinstance(controls_raw, list):
        raise ExtensionControlAuthorityError("invalid extension controls")
    controls: list[ExtensionControl] = []
    try:
        for item_raw in cast(list[object], controls_raw):
            if not isinstance(item_raw, dict):
                raise ExtensionControlAuthorityError("invalid extension control")
            item = cast(dict[str, object], item_raw)
            target_kind = ControlTargetKind(item.get("target_kind"))
            target_id = item.get("target_id")
            if not isinstance(target_id, str):
                raise ExtensionControlAuthorityError("invalid extension control target")
            controls.append(
                ExtensionControl(
                    ControlTarget(target_kind, target_id),
                    ControlState(item.get("state")),
                )
            )
        schema_version = value.get("schema_version")
        catalog_digest = value.get("catalog_digest")
        lockdown = value.get("global_lockdown")
        if not isinstance(schema_version, str) or not isinstance(catalog_digest, str):
            raise ExtensionControlAuthorityError("invalid extension control layer metadata")
        if type(lockdown) is not bool:
            raise ExtensionControlAuthorityError("invalid extension control lockdown")
        return ExtensionControlLayer(
            schema_version=schema_version,
            kind=ControlLayerKind(value.get("kind")),
            catalog_digest=catalog_digest,
            global_lockdown=lockdown,
            controls=tuple(controls),
        )
    except (TypeError, ValueError) as exc:
        raise ExtensionControlAuthorityError("invalid extension control layer") from exc


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
