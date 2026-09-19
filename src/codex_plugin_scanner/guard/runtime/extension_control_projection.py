"""Compile provider controls separately from their immutable authority source."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace

from .extension_control_contract import (
    ComposedExtensionControls,
    ControlLayerKind,
    ControlResolverFailure,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
    ResolverFailureCode,
)

LEGACY_DNS_EXTENSION_ID = "command.dns"
LEGACY_DNS_PERMISSION_ID = "command.dns.permission.delete"
DNS_PROVIDER_EXTENSION_IDS = ("command.dns.aws", "command.dns.gcp", "command.dns.azure")
DNS_ZONE_PERMISSION_IDS = (
    "command.dns.aws.permission.zone-deletion",
    "command.dns.gcp.permission.zone-deletion",
    "command.dns.azure.permission.public-zone-deletion",
)


def expand_legacy_dns_target(target: ControlTarget) -> tuple[ControlTarget, ...]:
    """Expand the retired aggregate DNS identifiers onto provider-specific targets."""

    if target.kind is ControlTargetKind.EXTENSION and target.target_id == LEGACY_DNS_EXTENSION_ID:
        return tuple(
            ControlTarget(ControlTargetKind.EXTENSION, extension_id) for extension_id in DNS_PROVIDER_EXTENSION_IDS
        )
    if target.kind is ControlTargetKind.PERMISSION and target.target_id == LEGACY_DNS_PERMISSION_ID:
        return tuple(
            ControlTarget(ControlTargetKind.PERMISSION, permission_id) for permission_id in DNS_ZONE_PERMISSION_IDS
        )
    return (target,)


def expand_legacy_dns_layers(layers: tuple[ExtensionControlLayer, ...]) -> tuple[ExtensionControlLayer, ...]:
    """Rewrite persisted aggregate DNS controls onto the provider-specific replacements.

    Expansion-induced collisions (legacy aggregate plus an already-present provider
    target) merge with disable dominance. Duplicate original targets stay duplicated
    so composition can still fail closed.
    """

    rewritten: list[ExtensionControlLayer] = []
    for layer in layers:
        merged: dict[ControlTarget, ControlState] = {}
        order: list[ControlTarget] = []
        extras: list[ExtensionControl] = []
        seen_originals: set[ControlTarget] = set()
        for control in layer.controls:
            expanded_targets = expand_legacy_dns_target(control.target)
            if control.target in seen_originals:
                extras.extend(ExtensionControl(target, control.state) for target in expanded_targets)
                continue
            seen_originals.add(control.target)
            for target in expanded_targets:
                previous = merged.get(target)
                if previous is None:
                    order.append(target)
                    merged[target] = control.state
                elif previous is ControlState.DISABLED or control.state is ControlState.DISABLED:
                    merged[target] = ControlState.DISABLED
        expanded = [ExtensionControl(target, merged[target]) for target in order]
        expanded.extend(extras)
        rewritten.append(replace(layer, controls=tuple(expanded)))
    return tuple(rewritten)


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


@dataclass(frozen=True, slots=True)
class CompiledControlProjection:
    """Derived compiler data; never serialize this as authority or native binding."""

    layers: tuple[ExtensionControlLayer, ...]
    composed: ComposedExtensionControls


def compile_control_projection(raw_layers: tuple[ExtensionControlLayer, ...]) -> CompiledControlProjection:
    """Derive controls without mutating the exact source tuple or its metadata.

    The existing resolver must retain its iterator bound and subsequent limit,
    catalog, target, surface and authority-health checks. No new cache is added.
    """
    projected = expand_legacy_dns_layers(raw_layers)
    return CompiledControlProjection(projected, compose_control_layers(projected))
