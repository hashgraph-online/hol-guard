"""Lifecycle updates and bounded persistence health for command activity."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Final, Protocol, TypeVar, cast

from codex_plugin_scanner.guard.models import GuardAction

from .runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
    validate_activity_transition,
)
from .runtime.effect_contract import UncertaintyKind
from .store_command_activity_rollups import transition_command_activity_rollups

_MAX_COUNTER: Final = 9_223_372_036_854_775_807
_ERROR_CODE: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
COMMAND_PERSISTENCE_ERROR_DOMAIN: Final = "command"
SHADOW_PERSISTENCE_ERROR_DOMAIN: Final = "shadow"
MAINTENANCE_ERROR_DOMAIN: Final = "maintenance"
_PERSISTENCE_ERROR_DOMAINS: Final = frozenset(
    {
        COMMAND_PERSISTENCE_ERROR_DOMAIN,
        SHADOW_PERSISTENCE_ERROR_DOMAIN,
        MAINTENANCE_ERROR_DOMAIN,
    }
)
_EnumT = TypeVar("_EnumT", bound=Enum)


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


@dataclass(frozen=True, slots=True)
class CommandActivityPersistenceHealth:
    dropped_event_count: int
    persistence_error_count: int
    active_error_count: int
    last_error_code: str | None
    last_error_at: datetime | None
    schema_version: str


class StoreCommandActivityLifecycleMixin:
    def is_exact_command_activity_pre_replay(
        self: _ConnectionOwner,
        evidence: CommandActivityEvidence,
    ) -> bool:
        """Return true for one existing logical pre delivery; reject fact conflicts."""

        correlation = evidence.activity.request_correlation
        if correlation is None:
            return False
        _require_request_correlation(correlation)
        with self._connect() as connection:
            row = _select_by_request_correlation(connection, correlation)
            if row is None:
                return False
            previous = _activity_from_row(connection, row)
            persisted_matches = tuple(
                tuple(item)
                for item in connection.execute(
                    """
                    select ordinal, extension_id, extension_version, rule_id, rule_version,
                           match_class, severity, default_floor, safe_variant_id, schema_version
                    from command_activity_matches where activity_id = ? order by ordinal
                    """,
                    (previous.activity_id,),
                ).fetchall()
            )
            persisted_effects = tuple(
                tuple(item)
                for item in connection.execute(
                    """
                    select ordinal, effect_class from command_activity_match_effects
                    where activity_id = ? order by ordinal, effect_class
                    """,
                    (previous.activity_id,),
                ).fetchall()
            )
        expected_matches = tuple(_pre_replay_match_values(item) for item in evidence.matches)
        expected_effects = tuple(
            (match.ordinal, effect.value)
            for match in evidence.matches
            for effect in sorted(match.effect_claims, key=lambda item: item.value)
        )
        if (
            _pre_replay_activity_values(previous) != _pre_replay_activity_values(evidence.activity)
            or persisted_matches != expected_matches
            or persisted_effects != expected_effects
        ):
            raise ValueError("conflicting command activity replay")
        return True

    def get_command_activity_by_request_correlation(
        self: _ConnectionOwner,
        correlation: CorrelationHandle,
    ) -> CommandActivity | None:
        """Resolve one logical command by an exact, strong request handle."""

        _require_request_correlation(correlation)
        with self._connect() as connection:
            row = _select_by_request_correlation(connection, correlation)
            return _activity_from_row(connection, row) if row is not None else None

    def transition_command_activity(self: _ConnectionOwner, current: CommandActivity) -> bool:
        """Atomically advance one correlated activity; return false for an exact replay."""

        if not isinstance(cast(object, current), CommandActivity):
            raise ValueError("current must be a CommandActivity")
        correlation = current.request_correlation
        if correlation is None:
            raise ValueError("lifecycle transitions require request correlation")
        _require_request_correlation(correlation)
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = _select_by_request_correlation(connection, correlation)
            if row is None:
                raise ValueError("command activity correlation does not identify a pre-hook record")
            previous = _activity_from_row(connection, row)
            if previous.activity_id != current.activity_id:
                raise ValueError("command activity correlation conflicts with activity identity")
            validate_activity_transition(previous, current)
            if previous == current:
                return False
            result = connection.execute(
                """
                update command_activity
                set hook_phase = ?, execution_status = ?, proof_level = ?,
                    persistence_latency_bucket = ?
                where activity_id = ? and hook_phase = ?
                  and execution_status = ? and proof_level = ?
                  and persistence_latency_bucket = ?
                """,
                (
                    current.hook_phase.value,
                    current.execution_status.value,
                    current.proof_level.value,
                    current.persistence_latency_bucket.value,
                    current.activity_id,
                    previous.hook_phase.value,
                    previous.execution_status.value,
                    previous.proof_level.value,
                    previous.persistence_latency_bucket.value,
                ),
            )
            if result.rowcount != 1:
                raise RuntimeError("command activity changed during lifecycle transition")
            transition_command_activity_rollups(connection, previous, current)
            recover_command_activity_persistence(
                connection,
                error_domain=COMMAND_PERSISTENCE_ERROR_DOMAIN,
            )
            return True

    def record_command_activity_persistence_failure(
        self: _ConnectionOwner,
        *,
        error_code: str,
        occurred_at: datetime,
    ) -> None:
        """Count one dropped event and persistence error without unbounded details."""

        _require_error_code(error_code)
        _require_utc_datetime(occurred_at)
        with self._connect() as connection:
            connection.execute("begin immediate")
            connection.execute(
                """
                update command_activity_health
                set dropped_event_count = min(dropped_event_count + 1, ?),
                    persistence_error_count = min(persistence_error_count + 1, ?),
                    last_error_code = ?, last_error_at = ?
                where singleton = 1
                """,
                (_MAX_COUNTER, _MAX_COUNTER, error_code, occurred_at.isoformat()),
            )
            error_domain = _persistence_error_domain(error_code)
            connection.execute(
                f"""
                update command_activity_health_active
                set {error_domain}_error_active = 1
                where singleton = 1
                """
            )

    def get_command_activity_persistence_health(
        self: _ConnectionOwner,
    ) -> CommandActivityPersistenceHealth:
        with self._connect() as connection:
            row = cast(
                sqlite3.Row | None,
                connection.execute("select * from command_activity_health where singleton = 1").fetchone(),
            )
            active = cast(
                sqlite3.Row | None,
                connection.execute("select * from command_activity_health_active where singleton = 1").fetchone(),
            )
        if row is None or active is None:
            raise RuntimeError("command activity persistence health is unavailable")
        last_error_at = str(row["last_error_at"]) if row["last_error_at"] is not None else None
        return CommandActivityPersistenceHealth(
            dropped_event_count=int(row["dropped_event_count"]),
            persistence_error_count=int(row["persistence_error_count"]),
            active_error_count=sum(
                int(active[column])
                for column in (
                    "command_error_active",
                    "shadow_error_active",
                    "maintenance_error_active",
                )
            ),
            last_error_code=str(row["last_error_code"]) if row["last_error_code"] is not None else None,
            last_error_at=datetime.fromisoformat(last_error_at) if last_error_at is not None else None,
            schema_version=str(row["schema_version"]),
        )


def recover_command_activity_persistence(
    connection: sqlite3.Connection,
    *,
    error_domain: str,
) -> None:
    """Clear only the active error class recovered by this successful operation."""

    if error_domain not in _PERSISTENCE_ERROR_DOMAINS:
        raise ValueError("invalid persistence error domain")
    connection.execute(
        f"""
        update command_activity_health_active
        set {error_domain}_error_active = 0
        where singleton = 1
        """
    )


def _persistence_error_domain(error_code: str) -> str:
    if error_code == "maintenance_failed":
        return MAINTENANCE_ERROR_DOMAIN
    if error_code == "shadow_evaluation_failed":
        return SHADOW_PERSISTENCE_ERROR_DOMAIN
    return COMMAND_PERSISTENCE_ERROR_DOMAIN


def _select_by_request_correlation(
    connection: sqlite3.Connection,
    correlation: CorrelationHandle,
) -> sqlite3.Row | None:
    return cast(
        sqlite3.Row | None,
        connection.execute(
            """
            select activity.* from command_activity as activity
            join command_activity_correlations as correlation
              on correlation.activity_id = activity.activity_id
            where correlation.kind = 'request' and correlation.harness = ?
              and correlation.key_id = ? and correlation.digest = ?
            """,
            (correlation.harness, correlation.key_id, correlation.digest),
        ).fetchone(),
    )


def _activity_from_row(connection: sqlite3.Connection, row: sqlite3.Row) -> CommandActivity:
    correlations = cast(
        list[sqlite3.Row],
        connection.execute(
            "select kind, harness, key_id, digest from command_activity_correlations where activity_id = ?",
            (str(row["activity_id"]),),
        ).fetchall(),
    )
    handles = {
        CorrelationKind(str(item["kind"])): CorrelationHandle(
            CorrelationKind(str(item["kind"])),
            str(item["harness"]),
            str(item["key_id"]),
            str(item["digest"]),
        )
        for item in correlations
    }
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
        match_count=int(row["match_count"]),
        prompted=bool(row["prompted"]),
        approval_reuse_status=ActivityApprovalReuseStatus(str(row["approval_reuse_status"])),
        request_correlation=handles.get(CorrelationKind.REQUEST),
        session_correlation=handles.get(CorrelationKind.SESSION),
        receipt_link_status=ReceiptLinkStatus(str(row["receipt_link_status"])),
        receipt_id=str(row["receipt_id"]) if row["receipt_id"] is not None else None,
        evaluation_latency_bucket=ActivityLatencyBucket(str(row["evaluation_latency_bucket"])),
        persistence_latency_bucket=ActivityLatencyBucket(str(row["persistence_latency_bucket"])),
        schema_version=str(row["schema_version"]),
    )


def _optional_enum(enum_type: type[_EnumT], value: object) -> _EnumT | None:
    return enum_type(str(value)) if value is not None else None


def _pre_replay_activity_values(activity: CommandActivity) -> tuple[object, ...]:
    return (
        activity.harness,
        activity.policy_action,
        activity.decision_reason_code,
        activity.controlling_rule_id,
        activity.parse_confidence,
        activity.uncertainty_class,
        activity.match_count,
        activity.prompted,
        activity.approval_reuse_status,
        activity.request_correlation,
        activity.session_correlation,
        activity.receipt_link_status,
        activity.evaluation_latency_bucket,
        activity.schema_version,
    )


def _pre_replay_match_values(match: CommandActivityMatch) -> tuple[object, ...]:
    return (
        match.ordinal,
        match.identity.extension_id,
        match.identity.extension_version,
        match.identity.rule_id,
        match.identity.rule_version,
        match.match_class.value,
        match.severity.value,
        match.default_floor,
        match.safe_variant_id,
        match.schema_version,
    )


def _require_request_correlation(correlation: CorrelationHandle) -> None:
    if not isinstance(cast(object, correlation), CorrelationHandle) or correlation.kind is not CorrelationKind.REQUEST:
        raise ValueError("correlation must be an exact request CorrelationHandle")


def _require_error_code(value: str) -> None:
    if not isinstance(cast(object, value), str) or len(value) > 64 or _ERROR_CODE.fullmatch(value) is None:
        raise ValueError("error_code must be a bounded stable identifier")


def _require_utc_datetime(value: datetime) -> None:
    if not isinstance(cast(object, value), datetime) or value.tzinfo is None:
        raise ValueError("occurred_at must be timezone-aware")
    offset = value.utcoffset()
    if offset is None:
        raise ValueError("occurred_at must be timezone-aware")
    if offset.total_seconds() != 0:
        raise ValueError("occurred_at must be UTC")
