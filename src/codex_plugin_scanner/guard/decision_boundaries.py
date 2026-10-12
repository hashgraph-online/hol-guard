"""Canonical action projections for untyped persistence and API boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .action_lattice import (
    most_restrictive_guard_action,
    normalize_guard_action_result,
)
from .decision_projection_boundaries import (
    CanonicalApprovalDecision as CanonicalApprovalDecision,
)
from .decision_projection_boundaries import (
    action_candidates as _action_candidates,
)
from .decision_projection_boundaries import (
    canonical_approval_decision,
)
from .decision_projection_boundaries import (
    unknown_action_bearing_fields as _unknown_action_bearing_fields,
)
from .models import GuardAction
from .runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT

_ACTION_ENVELOPE_ACTION_FIELDS = frozenset(
    {
        "action_id",
        "action_type",
        "policy_action",
        "pre_execution_result",
        "observed_policy_action",
        "actionId",
        "actionType",
        "policyAction",
        "preExecutionResult",
        "observedPolicyAction",
    }
)


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


def canonical_receipt_decision(
    policy_decision: object,
    action_envelope_json: object,
    *,
    reject_contradiction: bool,
) -> CanonicalReceiptDecision:
    """Synchronize final-action fields in a receipt-owned envelope.

    ``observed_policy_action`` is explicit Watch-only evidence, not execution
    authority. It must still be a recognized Guard action, but it may differ
    from the final receipt decision by design.
    """

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
            ("observed_policy_action", "observedPolicyAction"),
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
        for field in ("observed_policy_action", "observedPolicyAction"):
            raw_observed_action = envelope.get(field)
            if raw_observed_action is None:
                continue
            observed = normalize_guard_action_result(
                raw_observed_action,
                unknown_action="require-reapproval",
            )
            if not observed.recognized:
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


def _aliases_conflict(payload: Mapping[str, object] | None, snake_key: str, camel_key: str) -> bool:
    return bool(
        payload is not None
        and snake_key in payload
        and camel_key in payload
        and payload[snake_key] != payload[camel_key]
    )


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
