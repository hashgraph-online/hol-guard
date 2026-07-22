"""Bounded rollup reconciliation and retention for command activity."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Final, Protocol, cast

from .store_command_activity_lifecycle import MAINTENANCE_ERROR_DOMAIN, recover_command_activity_persistence
from .store_command_activity_rollups import (
    CommandActivityRollupBackfillResult,
    backfill_command_activity_rollups_batch,
    command_activity_rollups_are_reconciled,
    rebuild_command_activity_rollups,
)

COMMAND_ACTIVITY_AGGREGATE_MONTHS: Final = 13
DEFAULT_COMMAND_ACTIVITY_MAINTENANCE_BATCH_SIZE: Final = 1_000
_MAX_BATCH_SIZE: Final = 10_000
_MAX_RETENTION_DAYS: Final = 3_650


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


@dataclass(frozen=True, slots=True)
class CommandActivityMaintenanceResult:
    ran: bool
    completed: bool
    backfilled_rows: int
    detail_rows_deleted: int
    correlation_rows_deleted: int
    aggregate_rows_deleted: int


class StoreCommandActivityMaintenanceMixin:
    def maintain_command_activity(
        self: _ConnectionOwner,
        *,
        now: datetime,
        detail_retain_days: int,
        batch_size: int = DEFAULT_COMMAND_ACTIVITY_MAINTENANCE_BATCH_SIZE,
    ) -> CommandActivityMaintenanceResult:
        """Run at most one crash-safe batch until today's work is complete."""

        _validate_maintenance_inputs(now, detail_retain_days, batch_size)
        today = now.date().isoformat()
        with self._connect() as connection:
            connection.execute("begin immediate")
            state = cast(
                sqlite3.Row,
                connection.execute("select * from command_activity_maintenance where singleton = 1").fetchone(),
            )
            last_completed_day = str(state["last_completed_day"]) if state["last_completed_day"] is not None else None
            pending = connection.execute("select 1 from command_activity_rollup_pending limit 1").fetchone()
            if last_completed_day == today and pending is None:
                recover_command_activity_persistence(connection, error_domain=MAINTENANCE_ERROR_DOMAIN)
                return CommandActivityMaintenanceResult(False, True, 0, 0, 0, 0)

            backfill = _backfill_batch(connection, state=state, batch_size=batch_size, now=now)
            detail_deleted, correlations_deleted = _delete_retained_detail_batch(
                connection,
                cutoff=now - timedelta(days=detail_retain_days),
                batch_size=batch_size,
            )
            aggregates_deleted = _delete_expired_aggregates(
                connection,
                now=now,
                batch_size=batch_size,
            )
            completed = backfill.complete and detail_deleted < batch_size and aggregates_deleted < batch_size
            connection.execute(
                """
                update command_activity_maintenance
                set last_completed_day = case when ? then ? else last_completed_day end,
                    last_run_at = ?, last_backfilled_rows = ?,
                    last_detail_rows_deleted = ?, last_correlation_rows_deleted = ?,
                    last_aggregate_rows_deleted = ?,
                    detail_compaction_started_at = case
                      when ? > 0 then coalesce(detail_compaction_started_at, ?)
                      else detail_compaction_started_at end,
                    rollup_backfill_cursor_occurred_at = ?,
                    rollup_backfill_cursor_activity_id = ?,
                    rollup_backfill_complete = ?
                where singleton = 1
                """,
                (
                    completed,
                    today,
                    now.isoformat(),
                    backfill.rolled_rows,
                    detail_deleted,
                    correlations_deleted,
                    aggregates_deleted,
                    detail_deleted,
                    now.isoformat(),
                    backfill.cursor_occurred_at,
                    backfill.cursor_activity_id,
                    backfill.cursor_complete,
                ),
            )
            recover_command_activity_persistence(connection, error_domain=MAINTENANCE_ERROR_DOMAIN)
            return CommandActivityMaintenanceResult(
                True,
                completed,
                backfill.rolled_rows,
                detail_deleted,
                correlations_deleted,
                aggregates_deleted,
            )

    def rebuild_command_activity_rollups(
        self: _ConnectionOwner,
        *,
        now: datetime,
    ) -> None:
        """Rebuild all retained-detail aggregates atomically for reconciliation."""

        _require_utc(now)
        with self._connect() as connection:
            connection.execute("begin immediate")
            rebuild_command_activity_rollups(connection, rebuilt_at=now)

    def command_activity_rollups_are_reconciled(self: _ConnectionOwner) -> bool:
        with self._connect() as connection:
            return command_activity_rollups_are_reconciled(connection)


def _delete_retained_detail_batch(
    connection: sqlite3.Connection,
    *,
    cutoff: datetime,
    batch_size: int,
) -> tuple[int, int]:
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            """
            select membership.activity_id from command_activity_rollup_membership as membership
            join command_activity as activity on activity.activity_id = membership.activity_id
            where membership.detail_present = 1 and membership.occurred_at < ?
            order by membership.occurred_at, membership.activity_id limit ?
            """,
            (cutoff.isoformat(), batch_size),
        ).fetchall(),
    )
    activity_ids = tuple(str(row["activity_id"]) for row in rows)
    if not activity_ids:
        return 0, 0
    placeholders = ", ".join("?" for _ in activity_ids)
    correlation_row = connection.execute(
        f"select count(*) from command_activity_correlations where activity_id in ({placeholders})",
        activity_ids,
    ).fetchone()
    correlations = int(correlation_row[0]) if correlation_row is not None else 0
    connection.execute(
        f"delete from command_activity_shadow_cohorts where activity_id in ({placeholders})",
        activity_ids,
    )
    connection.execute(
        f"delete from command_activity_shadow_evaluations where activity_id in ({placeholders})",
        activity_ids,
    )
    result = connection.execute(
        f"delete from command_activity where activity_id in ({placeholders})",
        activity_ids,
    )
    return max(result.rowcount, 0), correlations


def _backfill_batch(
    connection: sqlite3.Connection,
    *,
    state: sqlite3.Row,
    batch_size: int,
    now: datetime,
) -> CommandActivityRollupBackfillResult:
    return backfill_command_activity_rollups_batch(
        connection,
        batch_size=batch_size,
        rolled_at=now,
        cursor_occurred_at=(
            str(state["rollup_backfill_cursor_occurred_at"])
            if state["rollup_backfill_cursor_occurred_at"] is not None
            else None
        ),
        cursor_activity_id=(
            str(state["rollup_backfill_cursor_activity_id"])
            if state["rollup_backfill_cursor_activity_id"] is not None
            else None
        ),
        cursor_complete=bool(state["rollup_backfill_complete"]),
    )


def _delete_expired_aggregates(
    connection: sqlite3.Connection,
    *,
    now: datetime,
    batch_size: int,
) -> int:
    cutoff = _aggregate_cutoff(now).isoformat()
    rollups = connection.execute(
        """
        delete from command_activity_daily_rollups where rowid in (
          select rowid from command_activity_daily_rollups
          where day < ? order by day, dimension, dimension_value limit ?
        )
        """,
        (cutoff, batch_size),
    )
    rollups_deleted = max(rollups.rowcount, 0)
    remaining = batch_size - rollups_deleted
    if remaining == 0:
        return rollups_deleted
    totals = connection.execute(
        """
        delete from command_activity_daily_totals where rowid in (
          select rowid from command_activity_daily_totals where day < ? order by day limit ?
        )
        """,
        (cutoff, remaining),
    )
    totals_deleted = max(totals.rowcount, 0)
    remaining -= totals_deleted
    if remaining == 0:
        return rollups_deleted + totals_deleted
    memberships = connection.execute(
        """
        delete from command_activity_rollup_membership where rowid in (
          select rowid from command_activity_rollup_membership
          where detail_present = 0 and day < ?
          order by day, activity_id limit ?
        )
        """,
        (cutoff, remaining),
    )
    return rollups_deleted + totals_deleted + max(memberships.rowcount, 0)


def _aggregate_cutoff(now: datetime) -> date:
    month_index = now.year * 12 + now.month - 1 - (COMMAND_ACTIVITY_AGGREGATE_MONTHS - 1)
    return date(month_index // 12, month_index % 12 + 1, 1)


def _validate_maintenance_inputs(now: datetime, detail_retain_days: int, batch_size: int) -> None:
    _require_utc(now)
    if isinstance(detail_retain_days, bool) or not 1 <= detail_retain_days <= _MAX_RETENTION_DAYS:
        raise ValueError(f"detail_retain_days must be between 1 and {_MAX_RETENTION_DAYS}")
    if isinstance(batch_size, bool) or not 1 <= batch_size <= _MAX_BATCH_SIZE:
        raise ValueError(f"batch_size must be between 1 and {_MAX_BATCH_SIZE}")


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("now must be timezone-aware UTC")


__all__ = [
    "COMMAND_ACTIVITY_AGGREGATE_MONTHS",
    "DEFAULT_COMMAND_ACTIVITY_MAINTENANCE_BATCH_SIZE",
    "CommandActivityMaintenanceResult",
    "StoreCommandActivityMaintenanceMixin",
]
