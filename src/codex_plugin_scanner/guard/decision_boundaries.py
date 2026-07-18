"""Canonical action projections for untyped persistence and API boundaries."""

from __future__ import annotations

import json
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
_ACTION_ENVELOPE_ACTION_FIELDS = frozenset(
    {
        "action_id",
        "action_type",
        "policy_action",
        "pre_execution_result",
        "actionId",
        "actionType",
        "policyAction",
        "preExecutionResult",
    }
)


@dataclass(frozen=True, slots=True)
class CanonicalApprovalDecision:
    """One exact queue action and its compatible product-facing projection."""

    policy_action: GuardAction
    decision_v2_json: dict[str, object]
    contract_error: str | None = None


@dataclass(frozen=True, slots=True)
class CanonicalReceiptDecision:
    """One exact receipt action and synchronized action-envelope fields."""

    policy_decision: GuardAction
    action_envelope_json: dict[str, object] | None
    contract_error: str | None = None


@dataclass(frozen=True, slots=True)
class CanonicalApprovalSurfaces:
    """Approval persistence fields synchronized to one exact action."""

    policy_action: GuardAction
    decision_v2_json: dict[str, object]
    action_envelope_json: dict[str, object] | None
    contract_error: str | None = None


@dataclass(frozen=True, slots=True)
class CanonicalLinkedApprovalAuthority:
    """Final approval authority that is safe to compose into a receipt.

    Pending requests are governed by their pre-execution approval surfaces.
    Once a request is resolved, those surfaces are historical context and the
    resolution action is the only approval authority that may affect a new or
    subsequently read receipt.
    """

    policy_action: GuardAction | None
    action_envelope_json: dict[str, object] | None
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
    unknown_action_fields = _unknown_action_bearing_fields(raw_decision, _DECISION_V2_ACTION_FIELDS)
    hidden_action_candidates = _action_candidates(raw_decision, unknown_action_fields)
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


def canonical_receipt_decision(
    policy_decision: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
) -> CanonicalReceiptDecision:
    """Synchronize final-action fields in a receipt-owned envelope."""

    normalization = normalize_guard_action_result(
        policy_decision,
        unknown_action="require-reapproval",
    )
    projected_action = normalization.action
    contract_error = None if normalization.recognized else AUTHORITATIVE_DECISION_INCONSISTENT
    envelope = dict(action_envelope_json) if isinstance(action_envelope_json, Mapping) else None
    invalid_payload = action_envelope_json is not None and envelope is None
    unknown_action_fields = _unknown_action_bearing_fields(envelope, _ACTION_ENVELOPE_ACTION_FIELDS)
    contradiction = any(
        _aliases_conflict(envelope, snake_key, camel_key)
        for snake_key, camel_key in (
            ("action_id", "actionId"),
            ("action_type", "actionType"),
            ("policy_action", "policyAction"),
            ("pre_execution_result", "preExecutionResult"),
        )
    )
    candidates: list[GuardAction] = _action_candidates(envelope, unknown_action_fields)
    if unknown_action_fields:
        contradiction = True
        assert envelope is not None
        for key in unknown_action_fields:
            envelope.pop(key, None)
    if envelope is not None:
        for key, alias in (("policy_action", "policyAction"), ("pre_execution_result", "preExecutionResult")):
            for field in (key, alias):
                raw_action = envelope.get(field)
                if raw_action is None:
                    continue
                candidate = normalize_guard_action_result(
                    raw_action,
                    unknown_action="require-reapproval",
                )
                candidates.append(candidate.action)
                if not candidate.recognized or candidate.action != projected_action:
                    contradiction = True

    if reject_contradiction and (invalid_payload or contradiction):
        raise ValueError(AUTHORITATIVE_DECISION_INCONSISTENT)
    if invalid_payload:
        contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
        projected_action = most_restrictive_guard_action(
            projected_action,
            "require-reapproval",
            unknown_action="require-reapproval",
        )
    elif contradiction:
        contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
        projected_action = most_restrictive_guard_action(
            projected_action,
            "require-reapproval",
            *candidates,
            unknown_action="require-reapproval",
        )
    if envelope is not None:
        for key in ("policy_action", "pre_execution_result", "policyAction", "preExecutionResult"):
            if envelope.get(key) is not None:
                envelope[key] = projected_action

    return CanonicalReceiptDecision(
        policy_decision=projected_action,
        action_envelope_json=envelope,
        contract_error=contract_error,
    )


def _unknown_action_bearing_fields(
    payload: Mapping[str, object] | None,
    allowed: frozenset[str],
) -> tuple[str, ...]:
    if payload is None:
        return ()
    return tuple(key for key in payload if isinstance(key, str) and is_action_bearing_key(key) and key not in allowed)


def _aliases_conflict(payload: Mapping[str, object] | None, snake_key: str, camel_key: str) -> bool:
    return bool(
        payload is not None
        and snake_key in payload
        and camel_key in payload
        and payload[snake_key] != payload[camel_key]
    )


def _action_candidates(
    payload: Mapping[str, object] | None,
    keys: tuple[str, ...],
) -> list[GuardAction]:
    if payload is None:
        return []
    return [normalize_guard_action_result(payload.get(key), unknown_action="require-reapproval").action for key in keys]


def canonical_approval_surfaces(
    policy_action: object,
    decision_v2_json: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
) -> CanonicalApprovalSurfaces:
    """Cross-check approval action, product decision, and action envelope."""

    decision = canonical_approval_decision(
        policy_action,
        decision_v2_json,
        reject_contradiction=reject_contradiction,
    )
    envelope = canonical_receipt_decision(
        decision.policy_action,
        action_envelope_json,
        reject_contradiction=reject_contradiction,
    )
    final_decision = canonical_approval_decision(
        envelope.policy_decision,
        decision.decision_v2_json,
        reject_contradiction=False,
    )
    final_envelope = canonical_receipt_decision(
        final_decision.policy_action,
        envelope.action_envelope_json,
        reject_contradiction=False,
    )
    return CanonicalApprovalSurfaces(
        policy_action=final_decision.policy_action,
        decision_v2_json=final_decision.decision_v2_json,
        action_envelope_json=final_envelope.action_envelope_json,
        contract_error=(
            decision.contract_error
            or envelope.contract_error
            or final_decision.contract_error
            or final_envelope.contract_error
        ),
    )


def canonical_linked_approval_authority(
    *,
    approval_request_id: object,
    linked_request_id: object,
    status: object,
    resolution_action: object,
    resolved_at: object,
    policy_action: object,
    decision_v2_json: object,
    action_envelope_json: object,
) -> CanonicalLinkedApprovalAuthority:
    """Resolve a linked approval row without reviving stale request authority.

    The receipt row owns whether a link exists. A missing local row is accepted
    as lineage-only compatibility, while a present malformed approval lifecycle
    fails closed. For a pending request, all persisted approval projections are
    cross-checked. For a resolved request, only the exact final
    ``allow``/``block`` resolution participates in composition; the original
    review envelope remains diagnostic history.
    """

    if approval_request_id is None:
        return CanonicalLinkedApprovalAuthority(None, None)
    # Memory-decision receipts may preserve a cloud/local request ID even when
    # this device has no corresponding local approval row. In that compatible
    # lineage-only case, the receipt remains its own authority. If the row is
    # later inserted, the approval insert trigger invalidates the rollup.
    if linked_request_id is None:
        return CanonicalLinkedApprovalAuthority(None, None)
    if linked_request_id != approval_request_id:
        return _invalid_linked_approval_authority()

    pre_resolution_surfaces = canonical_approval_surfaces(
        policy_action,
        _json_mapping_or_original(decision_v2_json),
        _json_mapping_or_original(action_envelope_json),
        reject_contradiction=False,
    )
    resolution_candidate: GuardAction | None = None
    if resolution_action == "allow":
        resolution_candidate = "allow"
    elif resolution_action == "block":
        resolution_candidate = "block"
    invalid_candidates: list[object] = [
        "require-reapproval",
        pre_resolution_surfaces.policy_action,
    ]
    if resolution_action is not None:
        invalid_candidates.append(resolution_action)
    invalid_action = most_restrictive_guard_action(
        *invalid_candidates,
        unknown_action="require-reapproval",
    )

    if status == "pending":
        if resolution_action is not None or resolved_at is not None:
            return _invalid_linked_approval_authority(invalid_action)
        return CanonicalLinkedApprovalAuthority(
            pre_resolution_surfaces.policy_action,
            pre_resolution_surfaces.action_envelope_json,
            pre_resolution_surfaces.contract_error,
        )

    if status == "resolved":
        if pre_resolution_surfaces.contract_error is not None:
            return _invalid_linked_approval_authority(invalid_action)
        if pre_resolution_surfaces.policy_action in {"block", "sandbox-required"}:
            return _invalid_linked_approval_authority(invalid_action)
        if resolution_candidate is None or not isinstance(resolved_at, str) or not resolved_at.strip():
            return _invalid_linked_approval_authority(invalid_action)
        resolved_envelope, contract_error = _resolved_approval_envelope(
            resolution_candidate,
            pre_resolution_surfaces.action_envelope_json,
        )
        return CanonicalLinkedApprovalAuthority(
            resolution_candidate,
            resolved_envelope,
            contract_error,
        )

    return _invalid_linked_approval_authority(invalid_action)


def _invalid_linked_approval_authority(
    policy_action: GuardAction = "require-reapproval",
) -> CanonicalLinkedApprovalAuthority:
    return CanonicalLinkedApprovalAuthority(
        policy_action,
        None,
        AUTHORITATIVE_DECISION_INCONSISTENT,
    )


def _json_mapping_or_original(value: object) -> object:
    if isinstance(value, Mapping) or value is None:
        return value
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return value
    return dict(parsed) if isinstance(parsed, Mapping) else value


def _resolved_approval_envelope(
    resolution_action: GuardAction,
    action_envelope_json: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Retain historical metadata while removing stale action authority."""

    parsed = _json_mapping_or_original(action_envelope_json)
    if parsed is None:
        return None, None
    if not isinstance(parsed, Mapping):
        return None, AUTHORITATIVE_DECISION_INCONSISTENT
    envelope = dict(parsed)
    contract_error: str | None = None
    for key in tuple(envelope):
        if isinstance(key, str) and is_action_bearing_key(key) and key not in _ACTION_ENVELOPE_ACTION_FIELDS:
            envelope.pop(key, None)
            contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
    for snake_key, camel_key in (("action_id", "actionId"), ("action_type", "actionType")):
        if _aliases_conflict(envelope, snake_key, camel_key):
            envelope.pop(camel_key, None)
            contract_error = AUTHORITATIVE_DECISION_INCONSISTENT
    for key in ("policy_action", "policyAction", "pre_execution_result", "preExecutionResult"):
        if key in envelope:
            envelope[key] = resolution_action
    canonical = canonical_receipt_decision(
        resolution_action,
        envelope,
        reject_contradiction=False,
    )
    return canonical.action_envelope_json, contract_error or canonical.contract_error


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
    if action == "ask":
        return "require-reapproval"
    return "require-reapproval"
