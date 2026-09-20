"""Metadata-only migration of retired aggregate DNS controls.

The persisted ``command.dns`` controls predate the provider-specific DNS
extensions.  Their expansion is part of control resolution and catalog
migration, so it must remain importable without loading the legacy Python
command matcher catalog.
"""

from __future__ import annotations

from dataclasses import replace

from .extension_control_contract import (
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)

LEGACY_DNS_EXTENSION_ID = "command.dns"
LEGACY_DNS_PERMISSION_ID = "command.dns.permission.delete"
DNS_PROVIDER_EXTENSION_IDS = (
    "command.dns.aws",
    "command.dns.gcp",
    "command.dns.azure",
)
DNS_ZONE_PERMISSION_IDS = (
    "command.dns.aws.permission.zone-deletion",
    "command.dns.gcp.permission.zone-deletion",
    "command.dns.azure.permission.public-zone-deletion",
)


def expand_legacy_dns_target(target: ControlTarget) -> tuple[ControlTarget, ...]:
    """Expand retired aggregate DNS identifiers onto provider-specific targets."""

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
    """Rewrite persisted aggregate DNS controls onto provider-specific replacements.

    Expansion-induced collisions (legacy aggregate plus an already-present
    provider target) merge with disable dominance. Duplicate original targets
    stay duplicated so composition can still fail closed.
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


__all__ = [
    "DNS_PROVIDER_EXTENSION_IDS",
    "DNS_ZONE_PERMISSION_IDS",
    "LEGACY_DNS_EXTENSION_ID",
    "LEGACY_DNS_PERMISSION_ID",
    "expand_legacy_dns_layers",
    "expand_legacy_dns_target",
]
