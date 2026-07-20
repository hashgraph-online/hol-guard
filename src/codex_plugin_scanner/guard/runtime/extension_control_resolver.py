"""Fail-closed composition and resolution of command-extension controls."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
from typing import cast

from .command_extensions import CommandSafetyExtensionRegistry
from .effect_contract import DecisionBasis
from .effect_decision import DecisionFactor, DecisionFactorSource
from .extension_control_contract import (
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolution,
    ControlResolverFailure,
    ControlState,
    ControlSurface,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)

_FAILURE_REASON = "control.resolver-failure"
_TRUSTED_LOCKDOWN_SURFACES = frozenset({ControlSurface.TRUSTED_LOCAL_RECOVERY, ControlSurface.TRUSTED_LOCAL_PROOF})
_MAX_LAYERS = len(ControlLayerKind)
_MAX_CONTROLS_PER_LAYER = 512
_MAX_RESOLUTION_IDS = 1024
_MAX_OBSERVATIONS = 2048
_MAX_INPUT_TEXT_LENGTH = 256


def compose_control_layers(layers: Iterable[ExtensionControlLayer]) -> ComposedExtensionControls:
    """Compose local and cloud layers with disable dominance and deterministic output."""
    states: dict[ControlTarget, ControlState] = {}
    seen_layer_kinds: set[ControlLayerKind] = set()
    failures: set[ControlResolverFailure] = set()
    lockdown = False
    for layer in layers:
        if layer.kind in seen_layer_kinds:
            failures.add(ControlResolverFailure(ResolverFailureCode.DUPLICATE_LAYER_KIND, layer.kind))
        seen_layer_kinds.add(layer.kind)
        lockdown = lockdown or layer.global_lockdown
        seen_targets: set[ControlTarget] = set()
        for control in layer.controls:
            if control.target in seen_targets:
                failures.add(ControlResolverFailure(ResolverFailureCode.DUPLICATE_TARGET_IN_LAYER, layer.kind))
                continue
            seen_targets.add(control.target)
            previous = states.get(control.target)
            if previous is ControlState.DISABLED or control.state is ControlState.DISABLED:
                states[control.target] = ControlState.DISABLED
            else:
                states[control.target] = ControlState.ENABLED
    controls = tuple(ExtensionControl(target, states[target]) for target in sorted(states))
    return ComposedExtensionControls(lockdown, controls, tuple(sorted(failures)))


def resolve_extension_controls(
    layers: Iterable[ExtensionControlLayer],
    registry: CommandSafetyExtensionRegistry,
    *,
    extension_ids: tuple[str, ...],
    permission_ids: tuple[str, ...],
    surface: ControlSurface,
    observations: tuple[str, ...] = (),
) -> ControlResolution:
    """Resolve controls for classified catalog identities without suppressing observations."""
    layer_values = tuple(islice(layers, _MAX_LAYERS + 1))
    composed = compose_control_layers(layer_values)
    failures = set(composed.failures)
    if (
        len(layer_values) > _MAX_LAYERS
        or any(len(layer.controls) > _MAX_CONTROLS_PER_LAYER for layer in layer_values)
        or len(extension_ids) > _MAX_RESOLUTION_IDS
        or len(permission_ids) > _MAX_RESOLUTION_IDS
        or len(observations) > _MAX_OBSERVATIONS
        or any(
            len(value) > _MAX_INPUT_TEXT_LENGTH
            for values in (extension_ids, permission_ids, observations)
            for value in values
        )
    ):
        failures.add(ControlResolverFailure(ResolverFailureCode.INPUT_LIMIT_EXCEEDED))
        return _resolution(composed, failures, observations[:_MAX_OBSERVATIONS], reason=None)
    if type(surface) is not ControlSurface:
        failures.add(ControlResolverFailure(ResolverFailureCode.INVALID_CONTROL_SURFACE))
    if not isinstance(cast(object, registry), CommandSafetyExtensionRegistry):
        failures.add(ControlResolverFailure(ResolverFailureCode.CATALOG_UNAVAILABLE))
        return _resolution(composed, failures, observations, reason=None)

    for layer in layer_values:
        if layer.catalog_digest != registry.catalog_digest:
            failures.add(ControlResolverFailure(ResolverFailureCode.CATALOG_DIGEST_MISMATCH, layer.kind))
        _validate_layer_targets(layer, registry, failures)

    expanded_extensions = _extension_closure(registry, extension_ids, failures)
    expanded_permissions = _permission_closure(registry, permission_ids, failures)
    for permission_id in tuple(expanded_permissions):
        permission = registry.permission(permission_id)
        if permission is not None:
            expanded_extensions.update(_extension_closure(registry, (permission.extension_id,), failures))

    if failures:
        return _resolution(composed, failures, observations, reason=None)
    if composed.global_lockdown and surface not in _TRUSTED_LOCKDOWN_SURFACES:
        return _resolution(composed, failures, observations, reason="control.global-lockdown")
    if any(
        composed.state_for(ControlTargetKind.EXTENSION, extension_id) is ControlState.DISABLED
        for extension_id in expanded_extensions
    ):
        return _resolution(composed, failures, observations, reason="control.disabled-extension")
    if any(
        composed.state_for(ControlTargetKind.PERMISSION, permission_id) is ControlState.DISABLED
        for permission_id in expanded_permissions
    ):
        return _resolution(composed, failures, observations, reason="control.disabled-permission")
    return ControlResolution(composed, False, (), (), observations)


def _validate_layer_targets(
    layer: ExtensionControlLayer,
    registry: CommandSafetyExtensionRegistry,
    failures: set[ControlResolverFailure],
) -> None:
    for control in layer.controls:
        if control.target.kind is ControlTargetKind.EXTENSION:
            extension = registry.get(control.target.target_id)
            if extension is None:
                failures.add(ControlResolverFailure(ResolverFailureCode.UNKNOWN_EXTENSION_TARGET, layer.kind))
            elif extension.extension_id != control.target.target_id:
                failures.add(ControlResolverFailure(ResolverFailureCode.NON_CANONICAL_TARGET, layer.kind))
        elif registry.permission(control.target.target_id) is None:
            failures.add(ControlResolverFailure(ResolverFailureCode.UNKNOWN_PERMISSION_TARGET, layer.kind))


def _extension_closure(
    registry: CommandSafetyExtensionRegistry,
    extension_ids: tuple[str, ...],
    failures: set[ControlResolverFailure],
) -> set[str]:
    resolved: set[str] = set()
    pending = list(extension_ids)
    while pending:
        extension_id = pending.pop()
        extension = registry.get(extension_id)
        if extension is None:
            failures.add(ControlResolverFailure(ResolverFailureCode.UNKNOWN_EXTENSION_TARGET))
            continue
        if extension.extension_id in resolved:
            continue
        resolved.add(extension.extension_id)
        pending.extend(extension.dependencies)
    return resolved


def _permission_closure(
    registry: CommandSafetyExtensionRegistry,
    permission_ids: tuple[str, ...],
    failures: set[ControlResolverFailure],
) -> set[str]:
    resolved: set[str] = set()
    pending = list(permission_ids)
    while pending:
        permission_id = pending.pop()
        permission = registry.permission(permission_id)
        if permission is None:
            failures.add(ControlResolverFailure(ResolverFailureCode.UNKNOWN_PERMISSION_TARGET))
            continue
        if permission.permission_id in resolved:
            continue
        resolved.add(permission.permission_id)
        pending.extend(permission.dependencies)
        pending.extend(permission.implied_permissions)
    return resolved


def _resolution(
    composed: ComposedExtensionControls,
    failures: set[ControlResolverFailure],
    observations: tuple[str, ...],
    *,
    reason: str | None,
) -> ControlResolution:
    ordered_failures = tuple(sorted(failures))
    reason_code = _FAILURE_REASON if ordered_failures else reason
    if reason_code is None:
        return ControlResolution(composed, False, (), ordered_failures, observations)
    factor = DecisionFactor(
        source=DecisionFactorSource.CONTROL,
        reason_code=reason_code,
        basis=DecisionBasis("block", None),
        producer_ref="control:resolver",
    )
    return ControlResolution(composed, True, (factor,), ordered_failures, observations)
