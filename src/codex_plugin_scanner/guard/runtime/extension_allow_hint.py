"""Queue-time hint: which configurable extension permissions would allow a reviewed command.

The hint is advisory. It is computed by re-running the pure policy resolver
against the same native evidence with a hypothetical local-admin layer, so it
never triggers a native call, never mutates authority, and carries only catalog
identifiers (no command text). Enabling a permission still requires the normal
proof-bound extension-control mutation.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from .command_evaluation import evaluate_command
from .command_evaluation_types import CompositeCommandEvaluation
from .command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY, CommandSafetyExtensionRegistry
from .extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from .extension_control_runtime import ExtensionControlRuntimeSnapshot
from .native_command_extension_evidence import NativeCommandExtensionEvidenceError

EXTENSION_ALLOW_HINT_SCHEMA = "guard.extension-allow-hint.v1"
MAX_HINT_PERMISSIONS = 3
_MAX_HINT_IDS = MAX_HINT_PERMISSIONS * 4


def _valid_hint_ids(items: object, *, allow_empty: bool) -> list[str] | None:
    if not isinstance(items, list) or (not items and not allow_empty) or len(items) > _MAX_HINT_IDS:
        return None
    ids = [item for item in items if isinstance(item, str) and item.startswith("command.") and len(item) <= 256]
    return ids if len(ids) == len(items) else None


def _with_local_permissions_enabled(
    snapshot: ExtensionControlRuntimeSnapshot,
    permission_ids: tuple[str, ...],
) -> ExtensionControlRuntimeSnapshot:
    """Return an in-memory counterfactual snapshot; never installed or persisted.

    Revision and digest fields are kept so the native evidence binding still
    validates; only the layers used for control resolution change.
    """

    targets = {ControlTarget(ControlTargetKind.PERMISSION, permission_id) for permission_id in permission_ids}
    local = next((layer for layer in snapshot.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN), None)
    retained = tuple(control for control in (() if local is None else local.controls) if control.target not in targets)
    added = tuple(ExtensionControl(target, ControlState.ENABLED) for target in sorted(targets))
    hypothetical_local = ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=snapshot.catalog_digest if local is None else local.catalog_digest,
        global_lockdown=False if local is None else local.global_lockdown,
        controls=tuple(sorted((*retained, *added), key=lambda control: control.target)),
    )
    layers = tuple(layer for layer in snapshot.layers if layer.kind is not ControlLayerKind.LOCAL_ADMIN)
    return dataclasses.replace(snapshot, layers=(hypothetical_local, *layers))


def compute_extension_allow_hint(
    evaluation: CompositeCommandEvaluation,
    *,
    command_text: str,
    snapshot: ExtensionControlRuntimeSnapshot,
    native_evidence: object,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    registry: CommandSafetyExtensionRegistry = BUILT_IN_COMMAND_EXTENSION_REGISTRY,
) -> dict[str, object] | None:
    """Return permission ids whose Allow state would let this command run, or None."""

    if snapshot.authority_failure is not None or evaluation.decision_plane.action != "review":
        return None
    if isinstance(native_evidence, dict) and native_evidence.get("minimum_action") == "block":
        return None
    already_enabled = set(evaluation.control_resolution.explicitly_enabled_permission_ids)
    permission_ids: list[str] = []
    rule_ids: list[str] = []
    extension_ids: list[str] = []
    relied_permission_ids: list[str] = []
    for owned in evaluation.matches:
        rule_id = owned.match.rule.rule_id
        permission = registry.permission_for_rule_id(rule_id)
        if permission is None or not permission.configurable:
            continue
        if permission.permission_id in already_enabled:
            # The counterfactual only holds while this permission stays enabled.
            if permission.permission_id not in relied_permission_ids:
                relied_permission_ids.append(permission.permission_id)
            continue
        if permission.permission_id not in permission_ids:
            permission_ids.append(permission.permission_id)
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
        if permission.extension_id not in extension_ids:
            extension_ids.append(permission.extension_id)
    if not permission_ids or len(permission_ids) > MAX_HINT_PERMISSIONS or len(relied_permission_ids) > _MAX_HINT_IDS:
        return None
    try:
        counterfactual = evaluate_command(
            command_text,
            canonical_command=evaluation.command,
            cwd=cwd,
            home_dir=home_dir,
            registry=registry,
            native_extension_evidence=native_evidence,
            extension_control_snapshot=_with_local_permissions_enabled(snapshot, tuple(permission_ids)),
        )
    except (NativeCommandExtensionEvidenceError, RuntimeError, ValueError):
        return None
    if counterfactual.decision_plane.action != "allow" or counterfactual.minimum_action != "allow":
        return None
    return {
        "schema": EXTENSION_ALLOW_HINT_SCHEMA,
        "permission_ids": permission_ids,
        "rule_ids": rule_ids,
        "extension_ids": extension_ids,
        "relied_permission_ids": relied_permission_ids,
        "catalog_digest": registry.catalog_digest,
    }


def validated_extension_allow_hint(value: object) -> dict[str, object] | None:
    """Return a shape-checked copy of a stored hint, or None."""

    if not isinstance(value, dict) or value.get("schema") != EXTENSION_ALLOW_HINT_SCHEMA:
        return None
    result: dict[str, object] = {"schema": EXTENSION_ALLOW_HINT_SCHEMA}
    for key in ("permission_ids", "rule_ids", "extension_ids"):
        items = _valid_hint_ids(value.get(key), allow_empty=False)
        if items is None:
            return None
        result[key] = items
    # Optional: hints queued before this key existed carry no relied permissions.
    relied = _valid_hint_ids(value.get("relied_permission_ids", []), allow_empty=True)
    if relied is None:
        return None
    result["relied_permission_ids"] = relied
    digest = value.get("catalog_digest")
    if not isinstance(digest, str) or len(digest) != 64:
        return None
    result["catalog_digest"] = digest
    return result
