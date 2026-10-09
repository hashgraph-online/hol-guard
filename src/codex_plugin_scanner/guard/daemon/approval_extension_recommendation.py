"""Live "always allow via extension" recommendation for one pending approval request.

The queue-time hint records which configurable permissions would have let the
command run. This module re-checks that hint against the current catalog and
control authority on every read, so stale or no-longer-applicable advice is
never shown. Payloads carry catalog identifiers and labels only, never command
text.
"""

from __future__ import annotations

from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_allow_hint import validated_extension_allow_hint
from ..runtime.extension_control_authority import AuthorityHealth
from ..runtime.extension_control_contract import ControlLayerKind, ControlState, ControlTargetKind
from ..runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot

RECOMMENDATION_SCHEMA = "guard.approval-extension-recommendation.v1"
_MAX_TEXT_CHARS = 240
_CAUTION_RISK_CLASSES = frozenset(
    {
        "credential_exfiltration",
        "data_flow_exfiltration",
        "destructive",
        "dynamic_execution",
        "encoded_execution",
        "financial_transaction",
        "local_secret_read",
        "policy_bypass",
    }
)


def _bounded(value: str | None, *, limit: int = _MAX_TEXT_CHARS) -> str | None:
    if value is None:
        return None
    normalized = " ".join(value.split())
    return normalized[:limit] if normalized else None


def _layer_states(snapshot: ExtensionControlRuntimeSnapshot, kind: ControlLayerKind) -> dict[tuple[str, str], str]:
    return {
        (control.target.kind.value, control.target.target_id): control.state.value
        for layer in snapshot.layers
        if layer.kind is kind
        for control in layer.controls
    }


def _caution_reason(permission, rules) -> str | None:
    if permission.risk_tier == "critical" or any(rule.severity == "critical" for rule in rules):
        return "critical"
    if (permission.family or "").endswith("-destructive"):
        return "destructive"
    action_classes = {*permission.action_classes, *(cls for rule in rules for cls in rule.action_classes)}
    if any("destructive" in action_class for action_class in action_classes):
        return "destructive"
    risk_classes = {risk for rule in rules for risk in rule.risk_classes}
    if risk_classes & _CAUTION_RISK_CLASSES:
        return "sensitive"
    return None


def _hint_ids(hint: dict[str, object], key: str) -> list[str]:
    items = hint.get(key)
    return [item for item in items if isinstance(item, str)] if isinstance(items, list) else []


def build_approval_extension_recommendation(
    approval: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    snapshot: ExtensionControlRuntimeSnapshot,
) -> dict[str, object] | None:
    """Return the recommendation for a pending request, or None when not applicable."""

    if approval.get("status") != "pending":
        return None
    hint = validated_extension_allow_hint(approval.get("extension_allow_hint"))
    if hint is None or hint["catalog_digest"] != registry.catalog_digest:
        return None
    if any(layer.global_lockdown for layer in snapshot.layers):
        return None
    local_states = _layer_states(snapshot, ControlLayerKind.LOCAL_ADMIN)
    managed_states = _layer_states(snapshot, ControlLayerKind.SIGNED_CLOUD)
    hinted_rule_ids = set(_hint_ids(hint, "rule_ids"))
    enabled = ControlState.ENABLED.value
    for relied_id in _hint_ids(hint, "relied_permission_ids"):
        # The queue-time check assumed these were already allowed; if one has
        # since been turned off, allowing the hinted permissions is not enough.
        relied_key = (ControlTargetKind.PERMISSION.value, relied_id)
        if managed_states.get(relied_key) == ControlState.DISABLED.value or enabled not in (
            local_states.get(relied_key),
            managed_states.get(relied_key),
        ):
            return None
    permissions: list[dict[str, object]] = []
    for permission_id in _hint_ids(hint, "permission_ids"):
        permission = registry.permission(permission_id)
        extension = registry.get(permission.extension_id) if permission is not None else None
        if permission is None or extension is None or not permission.configurable or permission.deprecated:
            return None
        disabled = ControlState.DISABLED.value
        permission_key = (ControlTargetKind.PERMISSION.value, permission.permission_id)
        if (
            managed_states.get(permission_key) == disabled
            or managed_states.get((ControlTargetKind.EXTENSION.value, extension.extension_id)) == disabled
            or local_states.get((ControlTargetKind.EXTENSION.value, extension.extension_id)) == disabled
        ):
            return None
        if local_states.get(permission_key) == ControlState.ENABLED.value:
            continue
        rules = [rule for rule_id in permission.rule_ids if (rule := registry.get_rule(rule_id)) is not None]
        matched_rule_ids = [rule.rule_id for rule in rules if rule.rule_id in hinted_rule_ids]
        caution = _caution_reason(permission, rules)
        primary_rule = next((rule for rule in rules if rule.rule_id in hinted_rule_ids), rules[0] if rules else None)
        permissions.append(
            {
                "permission_id": permission.permission_id,
                "label": _bounded(permission.label, limit=120),
                "description": _bounded(permission.description),
                "example_command": _bounded(permission.example_command, limit=160),
                "extension_id": extension.extension_id,
                "extension_name": _bounded(extension.name, limit=120),
                "rule_id": matched_rule_ids[0] if matched_rule_ids else (rules[0].rule_id if rules else None),
                "risk_tier": permission.risk_tier,
                "caution": caution is not None,
                "caution_reason": caution,
                "caution_detail": _bounded(primary_rule.description) if caution and primary_rule else None,
                "cli_command": f"hol-guard command controls set {permission.permission_id} --state allow",
            }
        )
    if not permissions:
        return None
    return {
        "schema": RECOMMENDATION_SCHEMA,
        "status": "available" if snapshot.health is AuthorityHealth.PROTECTED else "authority_unavailable",
        "permissions": permissions,
        "caution": any(item["caution"] for item in permissions),
        "revision": snapshot.revision,
        "catalog_digest": snapshot.catalog_digest,
    }


def with_approval_extension_recommendation(
    approval: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry | None,
    snapshot: ExtensionControlRuntimeSnapshot | None,
    include: bool,
) -> dict[str, object]:
    """Replace the private queue hint with a live recommendation; never fails the read."""

    payload = {key: value for key, value in approval.items() if key != "extension_allow_hint"}
    if not include or registry is None or snapshot is None:
        return payload
    try:
        recommendation = build_approval_extension_recommendation(approval, registry=registry, snapshot=snapshot)
    except (AttributeError, KeyError, TypeError, ValueError):
        recommendation = None
    if recommendation is not None:
        payload["extension_recommendation"] = recommendation
    return payload
