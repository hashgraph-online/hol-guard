"""Compatibility adapters from command evidence to the central evaluator."""

from __future__ import annotations

from .effect_decision import (
    DecisionReason,
    EffectDecision,
)


def effect_decision_to_dict(decision: EffectDecision) -> dict[str, object]:
    return {
        "schema_version": decision.schema_version,
        "action": decision.action,
        "disposition": decision.disposition.value,
        "proof_routes": sorted(item.value for item in decision.proof_routes),
        "controlling_reasons": [_reason_to_dict(item) for item in decision.controlling_reasons],
        "reasons": [_reason_to_dict(item) for item in decision.reasons],
    }


def _reason_to_dict(reason: object) -> dict[str, object]:
    if not isinstance(reason, DecisionReason):
        raise ValueError("reason must be a DecisionReason")
    return {
        "source": reason.source.value,
        "reason_code": reason.reason_code,
        "action_floor": reason.action_floor,
        "segment_ref": reason.segment_ref,
        "operation_ref": reason.operation_ref,
    }
