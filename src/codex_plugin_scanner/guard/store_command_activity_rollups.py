"""Transactional daily rollups for privacy-safe command activity facts."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Final, cast

from .runtime.command_activity_contract import CommandActivity, CommandActivityEvidence, CommandActivityMatch

COMMAND_ACTIVITY_ROLLUP_DIMENSIONS: Final = frozenset(
    {
        "harness",
        "extension",
        "rule",
        "disposition",
        "execution_status",
        "prompt_status",
        "proof_level",
        "latency",
    }
)


@dataclass(frozen=True, slots=True)
class CommandActivityRollupBackfillResult:
    examined_rows: int
    rolled_rows: int
    cursor_occurred_at: str | None
    cursor_activity_id: str | None
    cursor_complete: bool
    complete: bool


def record_command_activity_rollups(
    connection: sqlite3.Connection,
    evidence: CommandActivityEvidence,
) -> bool:
    """Add one activity to its daily cells exactly once in the caller transaction."""

    activity = evidence.activity
    day = activity.occurred_at.date().isoformat()
    if not _claim_rollup_membership(
        connection,
        activity.activity_id,
        day,
        activity.occurred_at.isoformat(),
        activity.occurred_at.isoformat(),
    ):
        return False
    _increment_total(connection, day, 1)
    _apply_dimension_deltas(connection, day, _activity_dimensions(activity, evidence.matches))
    return True


def transition_command_activity_rollups(
    connection: sqlite3.Connection,
    previous: CommandActivity,
    current: CommandActivity,
) -> None:
    """Move mutable lifecycle cells without changing one-command totals."""

    _ensure_persisted_activity_rolled(connection, previous)
    day = previous.occurred_at.date().isoformat()
    previous_dimensions = _base_activity_dimensions(previous)
    current_dimensions = _base_activity_dimensions(current)
    deltas: Counter[tuple[str, str]] = Counter()
    for cell in previous_dimensions.keys() | current_dimensions.keys():
        delta = current_dimensions[cell] - previous_dimensions[cell]
        if delta:
            deltas[cell] = delta
    _apply_dimension_deltas(connection, day, deltas)


def backfill_command_activity_rollups_batch(
    connection: sqlite3.Connection,
    *,
    batch_size: int,
    rolled_at: datetime,
    cursor_occurred_at: str | None,
    cursor_activity_id: str | None,
    cursor_complete: bool,
) -> CommandActivityRollupBackfillResult:
    """Roll up at most one bounded batch of legacy detail rows."""

    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    if (cursor_occurred_at is None) != (cursor_activity_id is None):
        raise ValueError("backfill cursor fields must both be present or absent")
    legacy_budget = 0 if cursor_complete else max(1, batch_size // 2)
    rows: list[sqlite3.Row] = []
    if legacy_budget and cursor_occurred_at is None:
        rows = cast(
            list[sqlite3.Row],
            connection.execute(
                "select * from command_activity order by occurred_at, activity_id limit ?",
                (legacy_budget,),
            ).fetchall(),
        )
    elif legacy_budget:
        rows = cast(
            list[sqlite3.Row],
            connection.execute(
                """
                select * from command_activity
                where (occurred_at, activity_id) > (?, ?)
                order by occurred_at, activity_id limit ?
                """,
                (cursor_occurred_at, cursor_activity_id, legacy_budget),
            ).fetchall(),
        )
    legacy_complete = cursor_complete or len(rows) < legacy_budget
    remaining = batch_size - len(rows)
    pending_rows = cast(
        list[sqlite3.Row],
        connection.execute(
            """
            select activity.* from command_activity_rollup_pending as pending
            join command_activity as activity on activity.activity_id = pending.activity_id
            order by pending.activity_id limit ?
            """,
            (remaining,),
        ).fetchall(),
    )
    processed = 0
    for row in rows:
        processed += int(_roll_raw_activity(connection, row, rolled_at=rolled_at))
    for row in pending_rows:
        processed += int(_roll_raw_activity(connection, row, rolled_at=rolled_at))
        connection.execute(
            "delete from command_activity_rollup_pending where activity_id = ?",
            (str(row["activity_id"]),),
        )
    return CommandActivityRollupBackfillResult(
        examined_rows=len(pending_rows) + len(rows),
        rolled_rows=processed,
        cursor_occurred_at=str(rows[-1]["occurred_at"]) if rows else cursor_occurred_at,
        cursor_activity_id=str(rows[-1]["activity_id"]) if rows else cursor_activity_id,
        cursor_complete=legacy_complete,
        complete=len(pending_rows) < remaining and legacy_complete,
    )


def _roll_raw_activity(connection: sqlite3.Connection, row: sqlite3.Row, *, rolled_at: datetime) -> bool:
    activity_id = str(row["activity_id"])
    day = str(row["occurred_at"])[:10]
    if not _claim_rollup_membership(
        connection,
        activity_id,
        day,
        str(row["occurred_at"]),
        rolled_at.isoformat(),
    ):
        return False
    _increment_total(connection, day, 1)
    _apply_dimension_deltas(connection, day, _raw_activity_dimensions(connection, row))
    return True


def rebuild_command_activity_rollups(connection: sqlite3.Connection, *, rebuilt_at: datetime) -> None:
    """Reconcile every aggregate from detail inside the caller transaction."""

    if _detail_compaction_has_started(connection):
        raise RuntimeError("rollups cannot be rebuilt after detail compaction")

    connection.execute("delete from command_activity_daily_totals")
    connection.execute("delete from command_activity_daily_rollups")
    connection.execute("delete from command_activity_rollup_membership")
    connection.execute(
        """
        insert into command_activity_daily_totals (day, total)
        select substr(occurred_at, 1, 10), count(*)
        from command_activity
        group by substr(occurred_at, 1, 10)
        """
    )
    connection.execute(
        """
        insert into command_activity_daily_rollups (day, dimension, dimension_value, count)
        select day, dimension, dimension_value, count(*)
        from (
          select substr(occurred_at, 1, 10) as day, 'harness' as dimension,
                 harness as dimension_value from command_activity
          union all
          select substr(occurred_at, 1, 10), 'disposition', policy_action
                 from command_activity where policy_action is not null
          union all
          select substr(occurred_at, 1, 10), 'execution_status', execution_status
                 from command_activity
          union all
          select substr(occurred_at, 1, 10), 'prompt_status',
                 case when prompted = 1 then 'prompted' else 'not_prompted' end from command_activity
          union all
          select substr(occurred_at, 1, 10), 'proof_level', proof_level
                 from command_activity
          union all
          select substr(occurred_at, 1, 10), 'latency',
                 'evaluation.' || evaluation_latency_bucket
                 from command_activity
          union all
          select substr(occurred_at, 1, 10), 'latency',
                 'persistence.' || persistence_latency_bucket
                 from command_activity
          union all
          select extension.day, 'extension', extension.extension_id from (
            select distinct activity.activity_id, substr(activity.occurred_at, 1, 10) as day,
                   matches.extension_id
            from command_activity as activity
            join command_activity_matches as matches on matches.activity_id = activity.activity_id
          ) as extension
          union all
          select substr(activity.occurred_at, 1, 10), 'rule', matches.rule_id
                 from command_activity as activity
                 join command_activity_matches as matches on matches.activity_id = activity.activity_id
        ) as cells
        group by day, dimension, dimension_value
        """
    )
    connection.execute(
        """
        insert into command_activity_rollup_membership (activity_id, day, occurred_at, rolled_at)
        select activity_id, substr(occurred_at, 1, 10), occurred_at, ? from command_activity
        """,
        (rebuilt_at.isoformat(),),
    )
    connection.execute(
        """
        update command_activity_maintenance
        set last_completed_day = null,
            rollup_backfill_cursor_occurred_at = null,
            rollup_backfill_cursor_activity_id = null,
            rollup_backfill_complete = 1
        where singleton = 1
        """
    )


def command_activity_rollups_are_reconciled(connection: sqlite3.Connection) -> bool:
    """Check exact total and per-dimension equality against retained detail."""

    if _detail_compaction_has_started(connection):
        return False

    expected_totals = _query_count_map(
        connection,
        """
        select substr(occurred_at, 1, 10) as day, count(*) as count
        from command_activity group by substr(occurred_at, 1, 10)
        """,
        key_columns=("day",),
    )
    actual_totals = _query_count_map(
        connection,
        "select day, total as count from command_activity_daily_totals",
        key_columns=("day",),
    )
    if actual_totals != expected_totals:
        return False
    expected_cells = _expected_dimension_cells(connection)
    actual_cells = _query_count_map(
        connection,
        "select day, dimension, dimension_value, count from command_activity_daily_rollups",
        key_columns=("day", "dimension", "dimension_value"),
    )
    return actual_cells == expected_cells


def _detail_compaction_has_started(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "select detail_compaction_started_at from command_activity_maintenance where singleton = 1"
    ).fetchone()
    return row is not None and row[0] is not None


def _ensure_persisted_activity_rolled(connection: sqlite3.Connection, activity: CommandActivity) -> None:
    day = activity.occurred_at.date().isoformat()
    if not _claim_rollup_membership(
        connection,
        activity.activity_id,
        day,
        activity.occurred_at.isoformat(),
        activity.occurred_at.isoformat(),
    ):
        return
    _increment_total(connection, day, 1)
    matches = cast(
        list[sqlite3.Row],
        connection.execute(
            "select extension_id, rule_id from command_activity_matches where activity_id = ?",
            (activity.activity_id,),
        ).fetchall(),
    )
    dimensions = _base_activity_dimensions(activity)
    for extension_id in {str(row["extension_id"]) for row in matches}:
        dimensions[("extension", extension_id)] += 1
    for row in matches:
        dimensions[("rule", str(row["rule_id"]))] += 1
    _apply_dimension_deltas(connection, day, dimensions)


def _claim_rollup_membership(
    connection: sqlite3.Connection,
    activity_id: str,
    day: str,
    occurred_at: str,
    rolled_at: str,
) -> bool:
    result = connection.execute(
        """
        insert or ignore into command_activity_rollup_membership (activity_id, day, occurred_at, rolled_at)
        values (?, ?, ?, ?)
        """,
        (activity_id, day, occurred_at, rolled_at),
    )
    return result.rowcount == 1


def _activity_dimensions(
    activity: CommandActivity,
    matches: Iterable[CommandActivityMatch],
) -> Counter[tuple[str, str]]:
    dimensions = _base_activity_dimensions(activity)
    materialized = tuple(matches)
    for extension_id in {match.identity.extension_id for match in materialized}:
        dimensions[("extension", extension_id)] += 1
    for match in materialized:
        dimensions[("rule", match.identity.rule_id)] += 1
    return dimensions


def _base_activity_dimensions(activity: CommandActivity) -> Counter[tuple[str, str]]:
    dimensions = Counter(
        {
            ("harness", activity.harness): 1,
            ("execution_status", activity.execution_status.value): 1,
            ("prompt_status", "prompted" if activity.prompted else "not_prompted"): 1,
            ("proof_level", activity.proof_level.value): 1,
            ("latency", f"evaluation.{activity.evaluation_latency_bucket.value}"): 1,
            ("latency", f"persistence.{activity.persistence_latency_bucket.value}"): 1,
        }
    )
    if activity.policy_action is not None:
        dimensions[("disposition", activity.policy_action)] += 1
    return dimensions


def _raw_activity_dimensions(connection: sqlite3.Connection, row: sqlite3.Row) -> Counter[tuple[str, str]]:
    dimensions: Counter[tuple[str, str]] = Counter(
        {
            ("harness", str(row["harness"])): 1,
            ("execution_status", str(row["execution_status"])): 1,
            ("prompt_status", "prompted" if bool(row["prompted"]) else "not_prompted"): 1,
            ("proof_level", str(row["proof_level"])): 1,
            ("latency", f"evaluation.{row['evaluation_latency_bucket']}"): 1,
            ("latency", f"persistence.{row['persistence_latency_bucket']}"): 1,
        }
    )
    if row["policy_action"] is not None:
        dimensions[("disposition", str(row["policy_action"]))] += 1
    matches = cast(
        list[sqlite3.Row],
        connection.execute(
            "select extension_id, rule_id from command_activity_matches where activity_id = ?",
            (str(row["activity_id"]),),
        ).fetchall(),
    )
    for extension_id in {str(match["extension_id"]) for match in matches}:
        dimensions[("extension", extension_id)] += 1
    for match in matches:
        dimensions[("rule", str(match["rule_id"]))] += 1
    return dimensions


def _increment_total(connection: sqlite3.Connection, day: str, delta: int) -> None:
    connection.execute(
        """
        insert into command_activity_daily_totals (day, total) values (?, ?)
        on conflict(day) do update set total = total + excluded.total
        """,
        (day, delta),
    )


def _apply_dimension_deltas(
    connection: sqlite3.Connection,
    day: str,
    deltas: Counter[tuple[str, str]],
) -> None:
    positive_rows = tuple((day, dimension, value, count) for (dimension, value), count in deltas.items() if count > 0)
    connection.executemany(
        """
        insert into command_activity_daily_rollups (day, dimension, dimension_value, count)
        values (?, ?, ?, ?)
        on conflict(day, dimension, dimension_value)
        do update set count = count + excluded.count
        """,
        positive_rows,
    )
    for (dimension, value), count in deltas.items():
        if count >= 0:
            continue
        result = connection.execute(
            """
            update command_activity_daily_rollups set count = count + ?
            where day = ? and dimension = ? and dimension_value = ?
            """,
            (count, day, dimension, value),
        )
        if result.rowcount != 1:
            raise RuntimeError("command activity rollup delta referenced a missing cell")
    connection.execute("delete from command_activity_daily_rollups where day = ? and count = 0", (day,))
    if connection.execute(
        "select 1 from command_activity_daily_rollups where day = ? and count < 0 limit 1",
        (day,),
    ).fetchone():
        raise RuntimeError("command activity rollup delta produced a negative count")


def _expected_dimension_cells(connection: sqlite3.Connection) -> dict[tuple[str, ...], int]:
    query = """
        select day, dimension, dimension_value, count(*) as count from (
          select substr(occurred_at, 1, 10) as day, 'harness' as dimension, harness as dimension_value
            from command_activity
          union all select substr(occurred_at, 1, 10), 'disposition', policy_action
            from command_activity where policy_action is not null
          union all select substr(occurred_at, 1, 10), 'execution_status', execution_status from command_activity
          union all select substr(occurred_at, 1, 10), 'prompt_status',
            case when prompted = 1 then 'prompted' else 'not_prompted' end from command_activity
          union all select substr(occurred_at, 1, 10), 'proof_level', proof_level from command_activity
          union all select substr(occurred_at, 1, 10), 'latency',
            'evaluation.' || evaluation_latency_bucket from command_activity
          union all select substr(occurred_at, 1, 10), 'latency',
            'persistence.' || persistence_latency_bucket
            from command_activity
          union all select extension.day, 'extension', extension.extension_id from (
            select distinct activity.activity_id, substr(activity.occurred_at, 1, 10) as day,
              matches.extension_id
            from command_activity activity join command_activity_matches matches using (activity_id)
          ) as extension
          union all select substr(activity.occurred_at, 1, 10), 'rule', matches.rule_id
            from command_activity activity join command_activity_matches matches using (activity_id)
        ) group by day, dimension, dimension_value
    """
    return _query_count_map(connection, query, key_columns=("day", "dimension", "dimension_value"))


def _query_count_map(
    connection: sqlite3.Connection,
    query: str,
    *,
    key_columns: tuple[str, ...],
) -> dict[tuple[str, ...], int]:
    rows = cast(list[sqlite3.Row], connection.execute(query).fetchall())
    return {tuple(str(row[column]) for column in key_columns): int(row["count"]) for row in rows}


__all__ = [
    "COMMAND_ACTIVITY_ROLLUP_DIMENSIONS",
    "CommandActivityRollupBackfillResult",
    "backfill_command_activity_rollups_batch",
    "command_activity_rollups_are_reconciled",
    "rebuild_command_activity_rollups",
    "record_command_activity_rollups",
    "transition_command_activity_rollups",
]
