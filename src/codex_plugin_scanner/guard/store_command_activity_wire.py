"""Wire shapes exchanged with the native resident for command activity.

Python serializes its frozen dataclasses into the exact column values the
resident binds, and rebuilds a ``CommandActivity`` from the resident's row.
Nothing here recalculates a verdict or a persisted fact.
"""

# pyright: reportAny=false

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import TypeVar, cast

from .models import GuardAction
from .runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
)
from .runtime.command_shadow_evaluation import CommandShadowObservation
from .runtime.effect_contract import UncertaintyKind


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


def _handle_from_wire(value: object) -> CorrelationHandle | None:
    if not isinstance(value, Mapping):
        return None
    item = cast(Mapping[str, object], value)
    return CorrelationHandle(
        CorrelationKind(str(item["kind"])),
        str(item["harness"]),
        str(item["key_id"]),
        str(item["digest"]),
    )


_EnumT = TypeVar("_EnumT", bound=Enum)


def _optional_enum(enum_type: type[_EnumT], value: object) -> _EnumT | None:
    return enum_type(str(value)) if value is not None else None


def activity_from_wire(row: Mapping[str, object]) -> CommandActivity:
    return CommandActivity(
        activity_id=str(row["activity_id"]),
        occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
        harness=str(row["harness"]),
        hook_phase=CommandHookPhase(str(row["hook_phase"])),
        execution_status=CommandExecutionStatus(str(row["execution_status"])),
        proof_level=CommandProofLevel(str(row["proof_level"])),
        policy_action=cast(GuardAction | None, row["policy_action"]),
        decision_reason_code=_optional_enum(ActivityDecisionReason, row["decision_reason_code"]),
        controlling_rule_id=str(row["controlling_rule_id"]) if row["controlling_rule_id"] is not None else None,
        parse_confidence=_optional_enum(ActivityParseConfidence, row["parse_confidence"]),
        uncertainty_class=_optional_enum(UncertaintyKind, row["uncertainty_class"]),
        match_count=int(cast(int, row["match_count"])),
        prompted=bool(row["prompted"]),
        approval_reuse_status=ActivityApprovalReuseStatus(str(row["approval_reuse_status"])),
        request_correlation=_handle_from_wire(row.get("request_correlation")),
        session_correlation=_handle_from_wire(row.get("session_correlation")),
        receipt_link_status=ReceiptLinkStatus(str(row["receipt_link_status"])),
        receipt_id=str(row["receipt_id"]) if row["receipt_id"] is not None else None,
        evaluation_latency_bucket=ActivityLatencyBucket(str(row["evaluation_latency_bucket"])),
        persistence_latency_bucket=ActivityLatencyBucket(str(row["persistence_latency_bucket"])),
        schema_version=str(row["schema_version"]),
    )
