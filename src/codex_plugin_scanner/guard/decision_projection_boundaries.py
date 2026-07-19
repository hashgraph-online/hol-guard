"""Canonical DecisionV2 projections for untyped approval boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .action_lattice import (
    is_action_bearing_key,
    most_restrictive_guard_action,
    normalize_guard_action_result,
)
from .models import GuardAction
from .runtime.decisions import (
    AUTHORITATIVE_DECISION_INCONSISTENT,
    GuardDecisionAction,
    GuardDecisionV2,
    decision_from_legacy_policy_action,
)
from .runtime.signals import RiskSignalV2

_PRODUCT_ACTIONS = frozenset({"allow", "warn", "ask", "block"})
_DEGRADED_TRUST_DETAIL_REASON = "remembered_rule_ignored_degraded_trust"
_DECISION_V2_ACTION_FIELDS = frozenset({"action", "guard_action"})


@dataclass(frozen=True, slots=True)
class CanonicalApprovalDecision:
    """One exact queue action and its compatible product-facing projection."""

    policy_action: GuardAction
    decision_v2_json: dict[str, object]
    contract_error: str | None = None


def canonical_approval_decision(
    policy_action: object,
    decision_v2_json: object,
    *,
    reject_contradiction: bool,
) -> CanonicalApprovalDecision:
    """Validate new approval fields or safely project a legacy database row.

    Product decisions intentionally collapse the three approval-gated Guard
    actions to ``ask``. That lossy mapping is compatible, but a permissive
    product action paired with a blocking policy action (or vice versa) is not.
    """

    normalization = normalize_guard_action_result(
        policy_action,
        unknown_action="require-reapproval",
    )
    normalized_action = normalization.action
    raw_decision = dict(decision_v2_json) if isinstance(decision_v2_json, Mapping) else None
    invalid_payload = decision_v2_json is not None and raw_decision is None
    unknown_action_fields = unknown_action_bearing_fields(raw_decision, _DECISION_V2_ACTION_FIELDS)
    hidden_action_candidates = action_candidates(raw_decision, unknown_action_fields)
    raw_guard_action = raw_decision.get("guard_action") if raw_decision is not None else None
    guard_action_normalization = (
        normalize_guard_action_result(raw_guard_action, unknown_action="require-reapproval")
        if raw_guard_action is not None
        else None
    )
    invalid_guard_action = guard_action_normalization is not None and not guard_action_normalization.recognized
    contradictory_guard_action = (
        guard_action_normalization is not None
        and guard_action_normalization.recognized
        and guard_action_normalization.action != normalized_action
    )
    raw_product_action = raw_decision.get("action") if raw_decision is not None else None
    invalid_product_action = raw_product_action is not None and (
        not isinstance(raw_product_action, str) or raw_product_action not in _PRODUCT_ACTIONS
    )
    contradictory = (
        isinstance(raw_product_action, str)
        and raw_product_action in _PRODUCT_ACTIONS
        and raw_product_action != _product_action_for_policy(normalized_action)
    )

    if reject_contradiction and (
        invalid_payload
        or invalid_guard_action
        or contradictory_guard_action
        or invalid_product_action
        or contradictory
        or unknown_action_fields
    ):
        raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)

    contract_error: str | None = None
    projected_action = normalized_action
    if not normalization.recognized:
        contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
    if invalid_payload or invalid_guard_action or invalid_product_action or unknown_action_fields:
        contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
        projected_action = most_restrictive_guard_action(
            projected_action,
            "require-reapproval",
            *hidden_action_candidates,
            unknown_action="require-reapproval",
        )
    elif contradictory_guard_action or contradictory:
        contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
        guard_action_floor = (
            guard_action_normalization.action
            if guard_action_normalization is not None and guard_action_normalization.recognized
            else "require-reapproval"
        )
        projected_action = most_restrictive_guard_action(
            projected_action,
            guard_action_floor,
            _policy_floor_for_product_action(raw_product_action),
            unknown_action="require-reapproval",
        )

    if contract_error is not None:
        reason = "Stored approval decision fields were inconsistent; HOL Guard failed closed."
    else:
        reason_value = raw_decision.get("reason") if raw_decision is not None else None
        reason = reason_value if isinstance(reason_value, str) and reason_value.strip() else projected_action
    signals = _validated_signals(raw_decision)
    canonical_v2 = decision_from_legacy_policy_action(
        projected_action,
        reason=reason,
        signals=signals,
    ).to_dict()
    if _validated_degraded_trust_detail(
        raw_decision,
        canonical_v2=canonical_v2,
        projected_action=projected_action,
    ):
        assert raw_decision is not None
        canonical_v2["harness_message"] = raw_decision["harness_message"]
        canonical_v2["dashboard_primary_detail"] = raw_decision["dashboard_primary_detail"]
        canonical_v2["detail_reason_code"] = _DEGRADED_TRUST_DETAIL_REASON
    if raw_decision is not None:
        policy_version = raw_decision.get("policyVersion")
        if isinstance(policy_version, str) and policy_version.strip():
            canonical_v2["policyVersion"] = policy_version

    return CanonicalApprovalDecision(
        policy_action=projected_action,
        decision_v2_json=canonical_v2,
        contract_error=contract_error,
    )


def unknown_action_bearing_fields(
    payload: Mapping[str, object] | None,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    """Return unrecognized fields that could conceal another action."""

    if payload is None:
        return ()
    return tuple(key for key in payload if isinstance(key, str) and is_action_bearing_key(key) and key not in allowed)


def action_candidates(
    payload: Mapping[str, object] | None,
    keys: tuple[str, ...],
) -> list[GuardAction]:
    """Normalize hidden action candidates for fail-closed composition."""

    if payload is None:
        return []
    return [normalize_guard_action_result(payload.get(key), unknown_action="require-reapproval").action for key in keys]


def _validated_degraded_trust_detail(
    raw_decision: Mapping[str, object] | None,
    *,
    canonical_v2: Mapping[str, object],
    projected_action: GuardAction,
) -> bool:
    """Preserve only the complete, internally tagged degraded-trust explanation."""

    if (
        raw_decision is None
        or raw_decision.get("detail_reason_code") != _DEGRADED_TRUST_DETAIL_REASON
        or projected_action not in {"review", "require-reapproval"}
    ):
        return False
    try:
        parsed = GuardDecisionV2.from_dict(raw_decision)
    except (TypeError, ValueError):
        return False
    if parsed.guard_action != projected_action:
        return False
    for key, expected in canonical_v2.items():
        # Package-review producers may specialize the title/body before the
        # degraded-trust explanation is attached. Those fields are reprojected
        # canonically below; only the tightly validated explanation survives.
        if key in {"user_title", "user_body", "harness_message", "dashboard_primary_detail"}:
            continue
        if raw_decision.get(key) != expected:
            return False
    message = raw_decision.get("harness_message")
    dashboard_detail = raw_decision.get("dashboard_primary_detail")
    required_fragments = ("remembered local rule was ignored", "One-time approvals still work")
    return bool(
        isinstance(message, str)
        and isinstance(dashboard_detail, str)
        and message == dashboard_detail
        and len(message) <= 2_000
        and all(fragment in message for fragment in required_fragments)
    )


def _validated_signals(decision: Mapping[str, object] | None) -> tuple[RiskSignalV2, ...]:
    raw_signals = decision.get("signals") if decision is not None else None
    if not isinstance(raw_signals, list):
        return ()
    signals: list[RiskSignalV2] = []
    for index, raw_signal in enumerate(raw_signals):
        if not isinstance(raw_signal, Mapping):
            continue
        payload = {
            "signal_id": f"approval-signal:{index}",
            "category": "policy",
            "severity": "info",
            "confidence": "likely",
            "detector": "guard.approval-boundary",
            "title": "Guard risk signal",
            "plain_reason": "HOL Guard recorded a risk signal for this approval.",
            "technical_detail": None,
            "evidence_ref": None,
            "redaction_level": "summary",
            "false_positive_hint": None,
            "advisory_id": None,
            **dict(raw_signal),
        }
        try:
            signals.append(RiskSignalV2.from_dict(payload))
        except (TypeError, ValueError):
            continue
    return tuple(signals)


def _product_action_for_policy(action: GuardAction) -> GuardDecisionAction:
    if action == "allow":
        return "allow"
    if action == "warn":
        return "warn"
    if action == "block":
        return "block"
    return "ask"


def _policy_floor_for_product_action(action: object) -> GuardAction:
    if action == "allow":
        return "allow"
    if action == "warn":
        return "warn"
    if action == "block":
        return "block"
    return "require-reapproval"
