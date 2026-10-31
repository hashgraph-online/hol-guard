"""Drive guard_store resident ops that only tests call.

The runtime reaches these ops natively, so the store keeps no Python wrapper for
them. Tests call the same resident op the wrapper did, with the input checks it
made before sending, so recorded vectors and store tests keep their coverage.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, TypeVar, cast
from uuid import uuid4

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
from codex_plugin_scanner.guard.runtime.composio_contract import composio_tool_role
from codex_plugin_scanner.guard.runtime.composio_discovery import ComposioActionSchema
from codex_plugin_scanner.guard.runtime.composio_workflows import ComposioWorkflowProposal
from codex_plugin_scanner.guard.runtime.effect_contract import UncertaintyKind
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition
from codex_plugin_scanner.guard.runtime.observed_mcp_tools import ObservedMcpTool, observed_mcp_tool
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
from codex_plugin_scanner.guard.store_local_mcp import _notify_legacy_mcp_denial
from codex_plugin_scanner.guard.store_sessions import _guard_attachment_row, _guard_item_row


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


def list_guard_operation_items(store: GuardStore, operation_id: str) -> list[dict[str, object]]:
    rows = store._native_store_call("list_guard_operation_items", {"operation_id": operation_id})
    return [_guard_item_row(row) for row in rows]


def attach_guard_client(
    store: GuardStore,
    *,
    client_id: str,
    surface: str,
    session_id: str | None,
    metadata: dict[str, object],
    lease_seconds: int,
    now: str,
) -> dict[str, object]:
    row = store._native_store_call(
        "attach_guard_client",
        {
            "client_id": client_id,
            "surface": surface,
            "session_id": session_id,
            "metadata_json": json.dumps(metadata),
            "lease_id": uuid4().hex,
            "lease_seconds": lease_seconds,
            "now": _aware_instant(now),
        },
    )
    return _guard_attachment_row(row)


def renew_guard_client_attachment(
    store: GuardStore,
    *,
    client_id: str,
    lease_id: str,
    lease_seconds: int,
    now: str,
) -> dict[str, object] | None:
    row = store._native_store_call(
        "renew_guard_client_attachment",
        {"client_id": client_id, "lease_id": lease_id, "lease_seconds": lease_seconds, "now": _aware_instant(now)},
    )
    return None if row is None else _guard_attachment_row(row)


def get_guard_client_attachment(store: GuardStore, client_id: str) -> dict[str, object] | None:
    row = store._native_store_call("get_guard_client_attachment", {"client_id": client_id})
    return None if row is None else _guard_attachment_row(row)


def record_composio_discovery(
    store: GuardStore,
    source: ObservedMcpTool,
    actions: tuple[ComposioActionSchema, ...],
    *,
    seen_at: str,
    proposals: tuple[ComposioWorkflowProposal, ...] = (),
) -> str:
    if observed_mcp_tool(source.harness, source.qualified_name) != source or (
        composio_tool_role(source.qualified_name) != "discovery"
    ):
        raise ValueError("invalid provider discovery source")
    server = source.server_identity
    cli_id = store.ensure_local_mcp_observation(
        source.identity,
        seen_at=seen_at,
        server_identity_hash=server.identity_hash,
        server_command=server.command,
        server_args_hash=server.args_hash,
        source_label=f"{source.harness.title()} · observed provider metadata",
    )
    args: dict[str, object] = {
        "cli_id": cli_id,
        "identity_hash": server.identity_hash,
        "server_command": server.command,
        "source_tool": source.qualified_name,
        "seen_at": seen_at,
        "actions": [
            {
                "toolkit": action.toolkit,
                "tool_slug": action.tool_slug,
                "description": action.description,
                "input_schema": action.input_schema,
                "full_schema": bool(action.full_schema),
            }
            for action in actions
        ],
        "proposals": [
            {
                "primary": list(proposal.primary),
                "supporting": list(proposal.supporting),
                "guidance_present": proposal.guidance_present,
            }
            for proposal in proposals
        ],
    }
    result = store._native_store_call("record_composio_discovery", args)
    if isinstance(result, dict) and result.get("need_barrier") is True:
        # The batch moves the provider authority, so the resident asks for the
        # native policy barrier and wrote nothing; run it again inside one.
        with _notify_legacy_mcp_denial(store.guard_home):
            store._native_store_call("record_composio_discovery", {**args, "barrier_closed": True})
    return cli_id


def reconcile_receipt_events(store: GuardStore) -> None:
    store._native_store_call("reconcile_receipt_events", {})


def refresh_review_event_outbox_binding(store: GuardStore) -> int:
    return int(store._native_store_call("refresh_review_event_outbox_binding", {}))


def _aware_instant(now: str) -> str:
    """Validate an ISO instant; a naive one means host-local time, as `datetime.timestamp()` reads it."""

    parsed = datetime.fromisoformat(now)
    return now if parsed.tzinfo is not None else parsed.astimezone().isoformat()


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
    "attach_guard_client",
    "command_activity_rollups_are_reconciled",
    "count_command_shadow_observations",
    "get_command_activity_by_request_correlation",
    "get_guard_client_attachment",
    "is_exact_command_activity_pre_replay",
    "list_command_shadow_observations",
    "list_guard_operation_items",
    "local_cli_replay_allowed",
    "rebuild_command_activity_rollups",
    "reconcile_receipt_events",
    "record_command_activity",
    "record_command_activity_observation_conflict",
    "record_composio_discovery",
    "refresh_review_event_outbox_binding",
    "renew_guard_client_attachment",
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
