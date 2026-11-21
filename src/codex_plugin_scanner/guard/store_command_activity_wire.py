"""Wire shapes exchanged with the native resident for command activity.

Python serializes its frozen dataclasses into the exact column values the
resident binds. Nothing here recalculates a verdict or a persisted fact.
"""

# pyright: reportAny=false

from __future__ import annotations

from enum import Enum

from .runtime.command_activity_contract import (
    CommandActivity,
    CommandActivityEvidence,
    CorrelationHandle,
)
from .runtime.command_shadow_evaluation import CommandShadowObservation


def handle_wire(handle: CorrelationHandle | None) -> dict[str, str] | None:
    if handle is None:
        return None
    return {
        "kind": handle.kind.value,
        "harness": handle.harness,
        "key_id": handle.key_id,
        "digest": handle.digest,
    }


def _value(item: object) -> object:
    return item.value if isinstance(item, Enum) else item


def activity_wire(activity: CommandActivity) -> dict[str, object]:
    return {
        "activity_id": activity.activity_id,
        "occurred_at": activity.occurred_at.isoformat(),
        "harness": activity.harness,
        "hook_phase": activity.hook_phase.value,
        "execution_status": activity.execution_status.value,
        "proof_level": activity.proof_level.value,
        "policy_action": activity.policy_action,
        "decision_reason_code": _value(activity.decision_reason_code),
        "controlling_rule_id": activity.controlling_rule_id,
        "parse_confidence": _value(activity.parse_confidence),
        "uncertainty_class": _value(activity.uncertainty_class),
        "match_count": activity.match_count,
        "prompted": int(activity.prompted),
        "approval_reuse_status": activity.approval_reuse_status.value,
        "receipt_link_status": activity.receipt_link_status.value,
        "receipt_id": activity.receipt_id,
        "evaluation_latency_bucket": activity.evaluation_latency_bucket.value,
        "persistence_latency_bucket": activity.persistence_latency_bucket.value,
        "schema_version": activity.schema_version,
        "request_correlation": handle_wire(activity.request_correlation),
        "session_correlation": handle_wire(activity.session_correlation),
    }


def evidence_wire(evidence: CommandActivityEvidence) -> dict[str, object]:
    return {
        "activity": activity_wire(evidence.activity),
        "matches": [
            {
                "activity_id": match.activity_id,
                "ordinal": match.ordinal,
                "extension_id": match.identity.extension_id,
                "extension_version": match.identity.extension_version,
                "rule_id": match.identity.rule_id,
                "rule_version": match.identity.rule_version,
                "match_class": match.match_class.value,
                "severity": match.severity.value,
                "default_floor": match.default_floor,
                "safe_variant_id": match.safe_variant_id,
                "schema_version": match.schema_version,
                "effects": sorted(effect.value for effect in match.effect_claims),
            }
            for match in evidence.matches
        ],
    }


def shadow_wire(shadow: CommandShadowObservation | None) -> dict[str, object] | None:
    if shadow is None:
        return None
    return {
        "activity_id": shadow.activity_id,
        "occurred_at": shadow.occurred_at.isoformat(),
        "authoritative_action": shadow.authoritative_action,
        "current_action": shadow.current_action,
        "current_disposition": shadow.current_disposition.value,
        "proposed_action": shadow.proposed_action,
        "proposed_disposition": shadow.proposed_disposition.value,
        "comparison": shadow.comparison.value,
        "proposal_version": shadow.proposal_version,
        "evaluator_schema_version": shadow.evaluator_schema_version,
        "control_generation": shadow.control_generation,
        "sample_basis_points": shadow.sample_basis_points,
        "schema_version": shadow.schema_version,
        "cohorts": [cohort.value for cohort in shadow.cohorts],
    }
