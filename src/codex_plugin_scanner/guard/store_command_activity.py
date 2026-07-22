"""Transactional persistence for command activity evidence."""

# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from contextlib import AbstractContextManager
from typing import Protocol, cast

from .runtime.command_activity_contract import (
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CorrelationHandle,
)
from .runtime.command_shadow_evaluation import CommandShadowObservation
from .store_command_activity_lifecycle import (
    COMMAND_PERSISTENCE_ERROR_DOMAIN,
    SHADOW_PERSISTENCE_ERROR_DOMAIN,
    recover_command_activity_persistence,
)
from .store_command_activity_rollups import record_command_activity_rollups
from .store_command_shadow import record_command_shadow_observation


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


class StoreCommandActivityMixin:
    def record_command_activity(
        self: _ConnectionOwner,
        evidence: CommandActivityEvidence,
        *,
        shadow: CommandShadowObservation | None = None,
        shadow_evaluation_succeeded: bool = False,
    ) -> bool:
        """Persist one logical command and its rule hits; return false for an exact replay."""

        if not isinstance(cast(object, evidence), CommandActivityEvidence):
            raise ValueError("evidence must be a CommandActivityEvidence")
        if shadow is not None:
            if not isinstance(cast(object, shadow), CommandShadowObservation):
                raise ValueError("shadow must be a CommandShadowObservation")
            if shadow.activity_id != evidence.activity.activity_id:
                raise ValueError("shadow activity_id must match command evidence")
            if shadow.occurred_at != evidence.activity.occurred_at:
                raise ValueError("shadow occurred_at must match command evidence")
        with self._connect() as connection:
            connection.execute("begin immediate")
            existing = cast(
                sqlite3.Row | None,
                connection.execute(
                    "select * from command_activity where activity_id = ?",
                    (evidence.activity.activity_id,),
                ).fetchone(),
            )
            if existing is not None:
                _require_exact_replay(connection, evidence, existing)
                if shadow is not None:
                    if (
                        connection.execute(
                            "select 1 from command_activity_shadow_evaluations where activity_id = ?",
                            (shadow.activity_id,),
                        ).fetchone()
                        is None
                    ):
                        raise ValueError("command shadow replay is missing persisted evidence")
                    record_command_shadow_observation(connection, shadow)
                return False
            if (
                connection.execute(
                    "select 1 from command_activity_rollup_membership where activity_id = ?",
                    (evidence.activity.activity_id,),
                ).fetchone()
                is not None
            ):
                return False
            connection.execute(
                """
                insert into command_activity (
                  activity_id, occurred_at, harness, hook_phase, execution_status,
                  proof_level, policy_action, decision_reason_code, controlling_rule_id,
                  parse_confidence, uncertainty_class, match_count, prompted,
                  approval_reuse_status, receipt_link_status, receipt_id,
                  evaluation_latency_bucket, persistence_latency_bucket, schema_version
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _activity_values(evidence.activity),
            )
            connection.executemany(
                """
                insert into command_activity_matches (
                  activity_id, ordinal, extension_id, extension_version, rule_id,
                  rule_version, match_class, severity, default_floor,
                  safe_variant_id, schema_version
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(_match_values(item) for item in evidence.matches),
            )
            connection.executemany(
                """
                insert into command_activity_match_effects (
                  activity_id, ordinal, effect_class
                ) values (?, ?, ?)
                """,
                _effect_values(evidence),
            )
            connection.executemany(
                """
                insert into command_activity_correlations (
                  activity_id, kind, harness, key_id, digest
                ) values (?, ?, ?, ?, ?)
                """,
                _correlation_values(evidence.activity),
            )
            if shadow is not None:
                record_command_shadow_observation(connection, shadow)
            record_command_activity_rollups(connection, evidence)
            recover_command_activity_persistence(
                connection,
                error_domain=COMMAND_PERSISTENCE_ERROR_DOMAIN,
            )
            if shadow is not None or shadow_evaluation_succeeded:
                recover_command_activity_persistence(
                    connection,
                    error_domain=SHADOW_PERSISTENCE_ERROR_DOMAIN,
                )
            return True

    def count_command_activities(self: _ConnectionOwner) -> int:
        with self._connect() as connection:
            row = cast(
                tuple[int] | None,
                connection.execute("select count(*) from command_activity").fetchone(),
            )
        return int(row[0]) if row is not None else 0

    def count_command_activity_rule_hits(self: _ConnectionOwner, rule_id: str | None = None) -> int:
        with self._connect() as connection:
            if rule_id is None:
                row = cast(
                    tuple[int] | None,
                    connection.execute("select count(*) from command_activity_matches").fetchone(),
                )
            else:
                row = cast(
                    tuple[int] | None,
                    connection.execute(
                        "select count(*) from command_activity_matches where rule_id = ?",
                        (rule_id,),
                    ).fetchone(),
                )
        return int(row[0]) if row is not None else 0


def _require_exact_replay(
    connection: sqlite3.Connection,
    evidence: CommandActivityEvidence,
    existing: sqlite3.Row,
) -> None:
    persisted_activity = _row_values(existing)
    persisted_matches = _query_values(
        connection,
        "select * from command_activity_matches where activity_id = ? order by ordinal",
        evidence.activity.activity_id,
    )
    persisted_correlations = _query_values(
        connection,
        "select * from command_activity_correlations where activity_id = ? order by kind",
        evidence.activity.activity_id,
    )
    persisted_effects = _query_values(
        connection,
        """
        select * from command_activity_match_effects
        where activity_id = ? order by ordinal, effect_class
        """,
        evidence.activity.activity_id,
    )
    expected_matches = tuple(_match_values(item) for item in evidence.matches)
    expected_effects = _effect_values(evidence)
    expected_correlations = tuple(sorted(_correlation_values(evidence.activity), key=lambda item: str(item[1])))
    if (
        persisted_activity != _activity_values(evidence.activity)
        or persisted_matches != expected_matches
        or persisted_effects != expected_effects
        or persisted_correlations != expected_correlations
    ):
        raise ValueError("conflicting command activity replay")


def _query_values(
    connection: sqlite3.Connection,
    query: str,
    activity_id: str,
) -> tuple[tuple[object, ...], ...]:
    rows = cast(
        list[sqlite3.Row],
        connection.execute(query, (activity_id,)).fetchall(),
    )
    return tuple(_row_values(row) for row in rows)


def _row_values(row: sqlite3.Row) -> tuple[object, ...]:
    return tuple(cast(Sequence[object], row))


def _activity_values(activity: CommandActivity) -> tuple[object, ...]:
    return (
        activity.activity_id,
        activity.occurred_at.isoformat(),
        activity.harness,
        activity.hook_phase.value,
        activity.execution_status.value,
        activity.proof_level.value,
        activity.policy_action,
        activity.decision_reason_code.value if activity.decision_reason_code is not None else None,
        activity.controlling_rule_id,
        activity.parse_confidence.value if activity.parse_confidence is not None else None,
        activity.uncertainty_class.value if activity.uncertainty_class is not None else None,
        activity.match_count,
        int(activity.prompted),
        activity.approval_reuse_status.value,
        activity.receipt_link_status.value,
        activity.receipt_id,
        activity.evaluation_latency_bucket.value,
        activity.persistence_latency_bucket.value,
        activity.schema_version,
    )


def _match_values(match: CommandActivityMatch) -> tuple[object, ...]:
    return (
        match.activity_id,
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


def _effect_values(evidence: CommandActivityEvidence) -> tuple[tuple[object, ...], ...]:
    return tuple(
        (match.activity_id, match.ordinal, effect.value)
        for match in evidence.matches
        for effect in sorted(match.effect_claims, key=lambda item: item.value)
    )


def _correlation_values(activity: CommandActivity) -> tuple[tuple[object, ...], ...]:
    handles = tuple(
        handle for handle in (activity.request_correlation, activity.session_correlation) if handle is not None
    )
    return tuple(_correlation_value(activity.activity_id, handle) for handle in handles)


def _correlation_value(activity_id: str, handle: CorrelationHandle) -> tuple[object, ...]:
    return (activity_id, handle.kind.value, handle.harness, handle.key_id, handle.digest)
