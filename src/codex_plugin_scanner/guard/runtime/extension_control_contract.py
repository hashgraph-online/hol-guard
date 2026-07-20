"""Immutable, versioned inputs and outputs for command-extension controls."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from .effect_decision import DecisionFactor

CONTROL_SCHEMA_VERSION: Final = "1.0.0"
_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_TARGET_ID: Final = re.compile(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*")


class ControlLayerKind(str, Enum):
    LOCAL_ADMIN = "local-admin"
    SIGNED_CLOUD = "signed-cloud"


class ControlTargetKind(str, Enum):
    EXTENSION = "extension"
    PERMISSION = "permission"


class ControlState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class ControlSurface(str, Enum):
    COMMAND_EVALUATION = "command-evaluation"
    TRUSTED_LOCAL_RECOVERY = "trusted-local-recovery"
    TRUSTED_LOCAL_PROOF = "trusted-local-proof"


class ResolverFailureCode(str, Enum):
    UNSUPPORTED_CONTROL_SCHEMA = "unsupported-control-schema"
    DUPLICATE_LAYER_KIND = "duplicate-layer-kind"
    DUPLICATE_TARGET_IN_LAYER = "duplicate-target-in-layer"
    CATALOG_DIGEST_MISMATCH = "catalog-digest-mismatch"
    UNKNOWN_EXTENSION_TARGET = "unknown-extension-target"
    UNKNOWN_PERMISSION_TARGET = "unknown-permission-target"
    INVALID_CONTROL_SURFACE = "invalid-control-surface"
    INVALID_OBSERVATION_BINDING = "invalid-observation-binding"
    CATALOG_UNAVAILABLE = "catalog-unavailable"
    INPUT_LIMIT_EXCEEDED = "input-limit-exceeded"
    NON_CANONICAL_TARGET = "non-canonical-target"


@dataclass(frozen=True, slots=True, order=True)
class ControlTarget:
    kind: ControlTargetKind
    target_id: str

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.kind), ControlTargetKind):
            raise ValueError("kind must be an exact ControlTargetKind")
        if _TARGET_ID.fullmatch(self.target_id) is None:
            raise ValueError("target_id must be a canonical command catalog ID")
        if self.kind is ControlTargetKind.PERMISSION and ".permission." not in self.target_id:
            raise ValueError("permission targets must contain a permission segment")
        if self.kind is ControlTargetKind.EXTENSION and ".permission." in self.target_id:
            raise ValueError("extension targets cannot contain a permission segment")


@dataclass(frozen=True, slots=True)
class ExtensionControl:
    target: ControlTarget
    state: ControlState

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.target), ControlTarget):
            raise ValueError("target must be a ControlTarget")
        if not isinstance(cast(object, self.state), ControlState):
            raise ValueError("state must be an exact ControlState")


@dataclass(frozen=True, slots=True)
class ExtensionControlLayer:
    schema_version: str
    kind: ControlLayerKind
    catalog_digest: str
    global_lockdown: bool
    controls: tuple[ExtensionControl, ...]

    def __post_init__(self) -> None:
        if self.schema_version != CONTROL_SCHEMA_VERSION:
            raise ValueError("unsupported control schema version")
        if not isinstance(cast(object, self.kind), ControlLayerKind):
            raise ValueError("kind must be an exact ControlLayerKind")
        if _SHA256.fullmatch(self.catalog_digest) is None:
            raise ValueError("catalog_digest must be a lowercase SHA-256 digest")
        if type(self.global_lockdown) is not bool:
            raise ValueError("global_lockdown must be a boolean")
        controls = cast(object, self.controls)
        if not isinstance(controls, tuple):
            raise ValueError("controls must contain exact ExtensionControl values")
        if any(not isinstance(item, ExtensionControl) for item in cast(tuple[object, ...], controls)):
            raise ValueError("controls must contain exact ExtensionControl values")


@dataclass(frozen=True, slots=True, order=True)
class ControlResolverFailure:
    code: ResolverFailureCode
    layer_kind: ControlLayerKind | None = None

    def __post_init__(self) -> None:
        if not isinstance(cast(object, self.code), ResolverFailureCode):
            raise ValueError("code must be an exact ResolverFailureCode")
        if self.layer_kind is not None and not isinstance(cast(object, self.layer_kind), ControlLayerKind):
            raise ValueError("layer_kind must be an exact ControlLayerKind")


@dataclass(frozen=True, slots=True)
class ComposedExtensionControls:
    global_lockdown: bool
    controls: tuple[ExtensionControl, ...]
    failures: tuple[ControlResolverFailure, ...] = ()

    def state_for(self, kind: ControlTargetKind, target_id: str) -> ControlState:
        target = ControlTarget(kind, target_id)
        return next(
            (control.state for control in self.controls if control.target == target),
            ControlState.ENABLED,
        )


@dataclass(frozen=True, slots=True)
class ControlResolution:
    composed: ComposedExtensionControls
    blocked: bool
    factors: tuple[DecisionFactor, ...]
    failures: tuple[ControlResolverFailure, ...]
    observations: tuple[str, ...]
