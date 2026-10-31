"""Drive guard_store resident ops that only tests call.

The runtime reaches these ops natively, so the store keeps no Python wrapper for
them. Tests call the same resident op the wrapper did, with the input checks it
made before sending, so recorded vectors and store tests keep their coverage.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypeVar, cast

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
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
from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    CommandShadowComparison,
    CommandShadowObservation,
)
from codex_plugin_scanner.guard.runtime.effect_contract import UncertaintyKind
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_activity import _validate_command_activity_write
from codex_plugin_scanner.guard.store_command_activity_display_schema import INVOCATION_PREVIEW_MAX_CHARS
from codex_plugin_scanner.guard.store_command_activity_lifecycle import _require_utc_datetime
from codex_plugin_scanner.guard.store_command_activity_wire import (
    activity_wire,
    evidence_wire,
    handle_wire,
    shadow_wire,
)
from codex_plugin_scanner.guard.store_local_cli_retention import utc_now_iso


def record_command_activity(
    store: GuardStore,
    evidence: CommandActivityEvidence,
    *,
    shadow: CommandShadowObservation | None = None,
    shadow_evaluation_succeeded: bool = False,
    invocation_preview: str | None = None,
) -> bool:
    """Persist one logical command and its rule hits; return false for an exact replay."""

    _validate_command_activity_write(evidence, shadow)
    preview = _validated_invocation_preview(invocation_preview)
    return bool(
        store._native_store_call(
            "record_command_activity",
            {
                "evidence": evidence_wire(evidence),
                "shadow": shadow_wire(shadow),
                "shadow_evaluation_succeeded": shadow_evaluation_succeeded,
                "invocation_preview": preview,
            },
        )
    )


def is_exact_command_activity_pre_replay(store: GuardStore, evidence: CommandActivityEvidence) -> bool:
    correlation = evidence.activity.request_correlation
    if correlation is None:
        return False
    _require_request_correlation(correlation)
    return bool(store._native_store_call("is_exact_command_activity_pre_replay", {"evidence": evidence_wire(evidence)}))


def get_command_activity_by_request_correlation(
    store: GuardStore,
    correlation: CorrelationHandle,
) -> CommandActivity | None:
    _require_request_correlation(correlation)
    row = store._native_store_call(
        "command_activity_by_request_correlation",
        {"correlation": handle_wire(correlation)},
    )
    return activity_from_wire(cast(Mapping[str, object], row)) if row is not None else None


def transition_command_activity(store: GuardStore, current: CommandActivity) -> bool:
    if not isinstance(cast(object, current), CommandActivity):
        raise ValueError("current must be a CommandActivity")
    correlation = current.request_correlation
    if correlation is None:
        raise ValueError("lifecycle transitions require request correlation")
    _require_request_correlation(correlation)
    return bool(store._native_store_call("transition_command_activity", {"current": activity_wire(current)}))


def record_command_activity_observation_conflict(store: GuardStore, *, occurred_at: datetime) -> None:
    _require_utc_datetime(occurred_at)
    store._native_store_call(
        "record_command_activity_observation_conflict",
        {"occurred_at": occurred_at.isoformat()},
    )


def rebuild_command_activity_rollups(store: GuardStore, *, now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")
    store._native_store_call("rebuild_command_activity_rollups", {"now": now.isoformat()})


def command_activity_rollups_are_reconciled(store: GuardStore) -> bool:
    return bool(store._native_store_call("command_activity_rollups_are_reconciled", {}))


def local_cli_replay_allowed(store: GuardStore, identity_hash: str, seen_at: str, *, now: str | None = None) -> bool:
    return bool(
        store._native_store_call(
            "local_cli_replay_allowed",
            {"identity_hash": identity_hash, "seen_at": seen_at, "now": now, "clock": utc_now_iso()},
        )
    )


def count_command_shadow_observations(store: GuardStore) -> int:
    return int(store._native_store_call("count_command_shadow_observations", {}))


def list_command_shadow_observations(
    store: GuardStore,
    *,
    limit: int = 10_000,
) -> tuple[CommandShadowObservation, ...]:
    if type(limit) is not int or not 1 <= limit <= 10_000:
        raise ValueError("limit must be between 1 and 10000")
    rows = cast(
        Sequence[Mapping[str, Any]],
        store._native_store_call("list_command_shadow_observations", {"limit": limit}),
    )
    return tuple(_observation_from_wire(row) for row in rows)


def _observation_from_wire(row: Mapping[str, Any]) -> CommandShadowObservation:
    return CommandShadowObservation(
        activity_id=str(row["activity_id"]),
        occurred_at=datetime.fromisoformat(str(row["occurred_at"])),
        cohorts=tuple(CommandShadowCohort(str(cohort)) for cohort in row["cohorts"]),
        authoritative_action=cast(GuardAction, row["authoritative_action"]),
        current_action=cast(GuardAction, row["current_action"]),
        current_disposition=FinalDisposition(str(row["current_disposition"])),
        proposed_action=cast(GuardAction, row["proposed_action"]),
        proposed_disposition=FinalDisposition(str(row["proposed_disposition"])),
        comparison=CommandShadowComparison(str(row["comparison"])),
        proposal_version=str(row["proposal_version"]),
        evaluator_schema_version=str(row["evaluator_schema_version"]),
        control_generation=int(row["control_generation"]),
        sample_basis_points=int(row["sample_basis_points"]),
        schema_version=str(row["schema_version"]),
    )


def _require_request_correlation(correlation: CorrelationHandle) -> None:
    if not isinstance(cast(object, correlation), CorrelationHandle) or correlation.kind is not CorrelationKind.REQUEST:
        raise ValueError("correlation must be an exact request CorrelationHandle")


def _validated_invocation_preview(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid_invocation_preview")
    stripped = value.strip()
    if not stripped or len(stripped) > INVOCATION_PREVIEW_MAX_CHARS:
        raise ValueError("invalid_invocation_preview")
    return stripped


__all__ = (
    "command_activity_rollups_are_reconciled",
    "count_command_shadow_observations",
    "get_command_activity_by_request_correlation",
    "is_exact_command_activity_pre_replay",
    "list_command_shadow_observations",
    "local_cli_replay_allowed",
    "rebuild_command_activity_rollups",
    "record_command_activity",
    "record_command_activity_observation_conflict",
    "transition_command_activity",
)


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
