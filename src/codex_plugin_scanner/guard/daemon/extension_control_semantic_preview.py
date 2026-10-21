"""Deterministic semantic preview for extension-control authority mutations.

The preview describes effective consequences without executing commands and without
changing detector metadata. It is derived from the same registry and resolver used
by runtime command enforcement so the dashboard does not duplicate policy truth.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

from ..native_extension_control import ControlItem, ControlScenario, resolve_scenarios
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
    ExtensionControlLayer,
)
from ..runtime.generated_command_catalog import GeneratedCommandPermission

SEMANTIC_PREVIEW_SCHEMA: Final = "guard.daemon.extension-control-semantic-preview.v1"
_MAX_CHANGED_TARGETS: Final = 4096
_MAX_WARNINGS_PER_TARGET: Final = 64
_MAX_RELATIONSHIP_IDS: Final = 4096


def _local_layer(layers: tuple[ExtensionControlLayer, ...]) -> ExtensionControlLayer | None:
    return next((layer for layer in layers if layer.kind is ControlLayerKind.LOCAL_ADMIN), None)


def _explicit_state(
    layers: tuple[ExtensionControlLayer, ...],
    kind: ControlTargetKind,
    target_id: str,
) -> str:
    layer = _local_layer(layers)
    if layer is None:
        return "inherited"
    for control in layer.controls:
        if control.target.kind is kind and control.target.target_id == target_id:
            return control.state.value
    return "inherited"


@dataclass(frozen=True, slots=True)
class _Effective:
    """What one set of layers blocks, as the native resolver answered it."""

    global_lockdown: bool
    permission_allowed: dict[str, bool]
    extension_blocked: dict[str, bool]


def _resolve_effective(
    registry: CommandSafetyExtensionRegistry,
    questions: Sequence[tuple[tuple[ExtensionControlLayer, ...], tuple[str, ...]]],
    guard_home: Path | None,
) -> list[_Effective]:
    """Resolve every registry permission, and the named extensions, once per set of layers."""

    permissions = registry.permissions
    permission_items = tuple(ControlItem((), (permission.permission_id,)) for permission in permissions)
    answers = resolve_scenarios(
        registry,
        [
            ControlScenario(
                layers,
                (*permission_items, *(ControlItem((extension_id,), ()) for extension_id in extension_ids)),
            )
            for layers, extension_ids in questions
        ],
        guard_home=guard_home,
    )
    effective: list[_Effective] = []
    for (_, extension_ids), answer in zip(questions, answers, strict=True):
        permission_answers = answer.items[: len(permissions)]
        extension_answers = answer.items[len(permissions) :]
        effective.append(
            _Effective(
                answer.global_lockdown,
                {
                    permission.permission_id: not permission_answer.blocked
                    for permission, permission_answer in zip(permissions, permission_answers, strict=True)
                },
                {
                    extension_id: extension_answer.blocked
                    for extension_id, extension_answer in zip(extension_ids, extension_answers, strict=True)
                },
            )
        )
    return effective


def _layers_with_target_reverted(
    current_layers: tuple[ExtensionControlLayer, ...],
    proposed_layers: tuple[ExtensionControlLayer, ...],
    key: tuple[ControlTargetKind, str],
) -> tuple[ExtensionControlLayer, ...]:
    current_local = _local_layer(current_layers)
    proposed_local = _local_layer(proposed_layers)
    current_control = None
    if current_local is not None:
        current_control = next(
            (control for control in current_local.controls if (control.target.kind, control.target.target_id) == key),
            None,
        )
    if proposed_local is None:
        return proposed_layers
    controls = [
        control for control in proposed_local.controls if (control.target.kind, control.target.target_id) != key
    ]
    if current_control is not None:
        controls.append(current_control)
    controls.sort(key=lambda control: (control.target.kind.value, control.target.target_id))
    reverted_local = replace(proposed_local, controls=tuple(controls))
    return tuple(reverted_local if layer is proposed_local else layer for layer in proposed_layers)


def _marginal_permission_ids(proposed: _Effective, reverted: _Effective) -> tuple[str, ...]:
    return tuple(
        sorted(
            permission_id
            for permission_id, state in proposed.permission_allowed.items()
            if state != reverted.permission_allowed.get(permission_id, state)
        )[:_MAX_RELATIONSHIP_IDS]
    )


def _rule_ids_for_permissions(
    registry: CommandSafetyExtensionRegistry, permission_ids: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                rule_id
                for permission_id in permission_ids
                for permission in (registry.permission(permission_id),)
                if permission is not None
                for rule_id in permission.rule_ids
            }
        )[:_MAX_RELATIONSHIP_IDS]
    )


def _extension_ids_for_permissions(
    registry: CommandSafetyExtensionRegistry, permission_ids: tuple[str, ...]
) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                permission.extension_id
                for permission_id in permission_ids
                for permission in (registry.permission(permission_id),)
                if permission is not None
            }
        )[:_MAX_RELATIONSHIP_IDS]
    )


def _extension_dependency_ids(registry: CommandSafetyExtensionRegistry, extension_id: str) -> tuple[str, ...]:
    resolved: set[str] = set()
    pending = [extension_id]
    while pending and len(resolved) < _MAX_RELATIONSHIP_IDS:
        current = pending.pop()
        extension = registry.get(current)
        if extension is None or extension.extension_id in resolved:
            continue
        resolved.add(extension.extension_id)
        pending.extend(extension.dependencies)
    return tuple(sorted(resolved))


def _provenance(
    layers: tuple[ExtensionControlLayer, ...],
    kind: ControlTargetKind,
    target_id: str,
    *,
    global_lockdown: bool,
) -> tuple[str, ...]:
    sources: list[str] = []
    if global_lockdown:
        sources.append("global-lockdown")
    for layer in layers:
        if any(control.target.kind is kind and control.target.target_id == target_id for control in layer.controls):
            sources.append(layer.kind.value)
    if not sources:
        sources.append("built-in-default")
    return tuple(sources)


def _warnings_for_permission(
    registry: CommandSafetyExtensionRegistry,
    proposed: _Effective,
    permission: GeneratedCommandPermission,
    *,
    requested_state: str,
    affected_permission_ids: tuple[str, ...],
) -> list[dict[str, object]]:
    warnings: list[dict[str, object]] = []
    if requested_state == ControlState.ENABLED.value and not proposed.permission_allowed[permission.permission_id]:
        warnings.append(
            {
                "code": "requested-allow-not-effective",
                "message": "A stronger parent, dependency, lockdown, or managed control still blocks this permission.",
            }
        )
    for conflict_id in permission.conflicts:
        conflict = registry.permission(conflict_id)
        if conflict is not None and proposed.permission_allowed[conflict.permission_id]:
            warnings.append(
                {
                    "code": "conflicting-permission-effective",
                    "target_id": conflict.permission_id,
                    "message": f"Conflicting permission {conflict.label} remains effective.",
                }
            )
    indirect = tuple(item for item in affected_permission_ids if item != permission.permission_id)
    if indirect:
        warnings.append(
            {
                "code": "dependent-permissions-affected",
                "count": len(indirect),
                "message": "This target also changes effective behavior for related permissions.",
            }
        )
    return warnings[:_MAX_WARNINGS_PER_TARGET]


def build_extension_control_semantic_preview(
    registry: CommandSafetyExtensionRegistry,
    current_layers: tuple[ExtensionControlLayer, ...],
    proposed_layers: tuple[ExtensionControlLayer, ...],
    *,
    guard_home: Path | None = None,
) -> dict[str, object]:
    current_local = _local_layer(current_layers)
    proposed_local = _local_layer(proposed_layers)
    current_controls = {
        (control.target.kind, control.target.target_id): control.state
        for control in (() if current_local is None else current_local.controls)
    }
    proposed_controls = {
        (control.target.kind, control.target.target_id): control.state
        for control in (() if proposed_local is None else proposed_local.controls)
    }
    target_keys = sorted(set(current_controls) | set(proposed_controls), key=lambda value: (value[0].value, value[1]))
    changed_keys = [key for key in target_keys if current_controls.get(key) != proposed_controls.get(key)][
        :_MAX_CHANGED_TARGETS
    ]

    # A changed target the catalog does not know yields no entry, so it needs no resolution.
    known_keys = [
        key
        for key in changed_keys
        if (registry.permission(key[1]) if key[0] is ControlTargetKind.PERMISSION else registry.get(key[1])) is not None
    ]
    changed_extension_ids = tuple(
        extension.extension_id
        for kind, target_id in known_keys
        if kind is ControlTargetKind.EXTENSION
        for extension in (registry.get(target_id),)
        if extension is not None
    )
    # The current and proposed layers, then the proposed layers with each changed target reverted.
    current, proposed, *reverted_effective = _resolve_effective(
        registry,
        [
            (current_layers, changed_extension_ids),
            (proposed_layers, changed_extension_ids),
            *((_layers_with_target_reverted(current_layers, proposed_layers, key), ()) for key in known_keys),
        ],
        guard_home,
    )
    reverted_by_key = dict(zip(known_keys, reverted_effective, strict=True))
    before_permission_states = current.permission_allowed
    after_permission_states = proposed.permission_allowed

    changed_targets: list[dict[str, object]] = []
    all_affected_permission_ids: set[str] = set()
    all_affected_rule_ids: set[str] = set()

    for kind, target_id in changed_keys:
        key = (kind, target_id)
        before_explicit = _explicit_state(current_layers, kind, target_id)
        after_explicit = _explicit_state(proposed_layers, kind, target_id)
        if key not in reverted_by_key:
            continue
        affected_permission_ids = _marginal_permission_ids(proposed, reverted_by_key[key])
        if kind is ControlTargetKind.PERMISSION and target_id not in affected_permission_ids:
            affected_permission_ids = tuple(sorted((*affected_permission_ids, target_id)))[:_MAX_RELATIONSHIP_IDS]
        affected_rule_ids = _rule_ids_for_permissions(registry, affected_permission_ids)
        affected_extension_ids = _extension_ids_for_permissions(registry, affected_permission_ids)

        if kind is ControlTargetKind.PERMISSION:
            permission = registry.permission(target_id)
            if permission is None:
                continue
            extension = registry.get(permission.extension_id)
            affected_extension_ids = tuple(sorted(set(affected_extension_ids) | {permission.extension_id}))[
                :_MAX_RELATIONSHIP_IDS
            ]
            warnings = _warnings_for_permission(
                registry,
                proposed,
                permission,
                requested_state=after_explicit,
                affected_permission_ids=affected_permission_ids,
            )
            changed_targets.append(
                {
                    "target": {"kind": kind.value, "target_id": target_id},
                    "extension_id": permission.extension_id,
                    "label": permission.label,
                    "before_explicit": before_explicit,
                    "after_explicit": after_explicit,
                    "before_effective": "allowed"
                    if before_permission_states.get(permission.permission_id, False)
                    else "blocked",
                    "after_effective": "allowed"
                    if after_permission_states.get(permission.permission_id, False)
                    else "blocked",
                    "baseline_risk": permission.risk_tier,
                    "baseline_floor": permission.baseline_floor,
                    "affected_permission_ids": list(affected_permission_ids),
                    "affected_rule_ids": list(affected_rule_ids),
                    "affected_extension_ids": list(affected_extension_ids),
                    "dependency_permission_ids": sorted(permission.dependencies)[:_MAX_RELATIONSHIP_IDS],
                    "implied_permission_ids": sorted(permission.implied_permissions)[:_MAX_RELATIONSHIP_IDS],
                    "conflict_permission_ids": sorted(permission.conflicts)[:_MAX_RELATIONSHIP_IDS],
                    "provenance": list(
                        _provenance(proposed_layers, kind, target_id, global_lockdown=proposed.global_lockdown)
                    ),
                    "warnings": warnings,
                    **({"extension_name": extension.name} if extension is not None else {}),
                }
            )
        else:
            extension = registry.get(target_id)
            if extension is None:
                continue
            affected_extension_ids = tuple(
                sorted(set(affected_extension_ids) | set(_extension_dependency_ids(registry, extension.extension_id)))
            )[:_MAX_RELATIONSHIP_IDS]
            extension_rule_ids = {rule.rule_id for rule in extension.rules}
            affected_rule_ids = tuple(sorted(set(affected_rule_ids) | extension_rule_ids))[:_MAX_RELATIONSHIP_IDS]
            warnings: list[dict[str, object]] = []
            after_effective = not proposed.extension_blocked[extension.extension_id]
            if after_explicit == ControlState.ENABLED.value and not after_effective:
                warnings.append(
                    {
                        "code": "requested-allow-not-effective",
                        "message": "A stronger dependency, lockdown, or managed control still blocks this extension.",
                    }
                )
            changed_targets.append(
                {
                    "target": {"kind": kind.value, "target_id": target_id},
                    "extension_id": extension.extension_id,
                    "label": extension.name,
                    "before_explicit": before_explicit,
                    "after_explicit": after_explicit,
                    "before_effective": "blocked" if current.extension_blocked[extension.extension_id] else "allowed",
                    "after_effective": "allowed" if after_effective else "blocked",
                    "affected_permission_ids": list(affected_permission_ids),
                    "affected_rule_ids": list(affected_rule_ids),
                    "affected_extension_ids": list(affected_extension_ids),
                    "dependency_permission_ids": [],
                    "implied_permission_ids": [],
                    "conflict_permission_ids": [],
                    "provenance": list(
                        _provenance(proposed_layers, kind, target_id, global_lockdown=proposed.global_lockdown)
                    ),
                    "warnings": warnings,
                }
            )
        all_affected_permission_ids.update(affected_permission_ids)
        all_affected_rule_ids.update(affected_rule_ids)

    newly_blocked = sum(
        1
        for permission_id, before in before_permission_states.items()
        if before and not after_permission_states.get(permission_id, False)
    )
    newly_allowed = sum(
        1
        for permission_id, before in before_permission_states.items()
        if not before and after_permission_states.get(permission_id, False)
    )
    lockdown_changed = current.global_lockdown != proposed.global_lockdown

    return {
        "schema_version": SEMANTIC_PREVIEW_SCHEMA,
        "global_lockdown": {
            "before": current.global_lockdown,
            "after": proposed.global_lockdown,
            "changed": lockdown_changed,
        },
        "changed_target_count": len(changed_targets),
        "affected_permission_count": len(all_affected_permission_ids),
        "affected_rule_count": len(all_affected_rule_ids),
        "changed_targets": changed_targets,
        "approval_required": bool(changed_targets or lockdown_changed),
        "summary": {
            "newly_blocked_permissions": newly_blocked,
            "newly_allowed_permissions": newly_allowed,
            "effective_change_count": newly_blocked + newly_allowed,
        },
    }
