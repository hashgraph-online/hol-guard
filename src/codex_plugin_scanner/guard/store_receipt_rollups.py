"""Incremental receipt rollups for fast analytics and counts."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from .models import GuardReceipt

_RECEIPT_TOTALS_KEY = "global"


def receipt_rollup_schema_statements() -> list[str]:
    return [
        """
        create table if not exists receipt_aggregate_totals (
          totals_key text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0,
          first_activity_at text,
          last_activity_at text
        )
        """,
        """
        create table if not exists receipt_daily_rollups (
          day_key text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0
        )
        """,
        """
        create table if not exists receipt_harness_rollups (
          harness text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0
        )
        """,
        """
        create table if not exists receipt_artifact_rollups (
          artifact_key text primary key,
          total integer not null default 0,
          allowed integer not null default 0,
          blocked integer not null default 0,
          reviewed integer not null default 0
        )
        """,
    ]


def receipt_rollup_index_statements() -> list[str]:
    return [
        "create index if not exists idx_receipt_daily_rollups_day on receipt_daily_rollups(day_key)",
        "create index if not exists idx_receipt_harness_rollups_total on receipt_harness_rollups(total desc)",
        "create index if not exists idx_receipt_artifact_rollups_total on receipt_artifact_rollups(total desc)",
    ]


def _decision_bucket(policy_decision: str) -> str:
    if policy_decision == "allow":
        return "allowed"
    if policy_decision == "block":
        return "blocked"
    return "reviewed"


def _bucket_counts(policy_decision: str) -> tuple[int, int, int]:
    bucket = _decision_bucket(policy_decision)
    if bucket == "allowed":
        return 1, 0, 0
    if bucket == "blocked":
        return 0, 1, 0
    return 0, 0, 1


def _day_key_from_timestamp(timestamp: str) -> str:
    return timestamp[:10] if len(timestamp) >= 10 else timestamp


def _artifact_key(artifact_name: str | None, artifact_id: str) -> str:
    name = (artifact_name or "").strip()
    if name:
        return name.lower()
    return artifact_id.lower()


def _apply_receipt_delta(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_name: str | None,
    artifact_id: str,
    policy_decision: str,
    timestamp: str,
    multiplier: int,
) -> None:
    allowed_delta, blocked_delta, reviewed_delta = _bucket_counts(policy_decision)
    allowed_delta *= multiplier
    blocked_delta *= multiplier
    reviewed_delta *= multiplier
    total_delta = multiplier
    day_key = _day_key_from_timestamp(timestamp)
    artifact_key = _artifact_key(artifact_name, artifact_id)

    connection.execute(
        """
        insert into receipt_aggregate_totals (
          totals_key, total, allowed, blocked, reviewed, first_activity_at, last_activity_at
        )
        values (?, ?, ?, ?, ?, ?, ?)
        on conflict(totals_key) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed,
          first_activity_at = case
            when first_activity_at is null then excluded.first_activity_at
            when excluded.first_activity_at is null then first_activity_at
            when excluded.first_activity_at < first_activity_at then excluded.first_activity_at
            else first_activity_at
          end,
          last_activity_at = case
            when last_activity_at is null then excluded.last_activity_at
            when excluded.last_activity_at is null then last_activity_at
            when excluded.last_activity_at > last_activity_at then excluded.last_activity_at
            else last_activity_at
          end
        """,
        (
            _RECEIPT_TOTALS_KEY,
            total_delta,
            allowed_delta,
            blocked_delta,
            reviewed_delta,
            timestamp,
            timestamp,
        ),
    )

    connection.execute(
        """
        insert into receipt_daily_rollups (day_key, total, allowed, blocked, reviewed)
        values (?, ?, ?, ?, ?)
        on conflict(day_key) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed
        """,
        (day_key, total_delta, allowed_delta, blocked_delta, reviewed_delta),
    )

    connection.execute(
        """
        insert into receipt_harness_rollups (harness, total, allowed, blocked, reviewed)
        values (?, ?, ?, ?, ?)
        on conflict(harness) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed
        """,
        (harness, total_delta, allowed_delta, blocked_delta, reviewed_delta),
    )

    connection.execute(
        """
        insert into receipt_artifact_rollups (artifact_key, total, allowed, blocked, reviewed)
        values (?, ?, ?, ?, ?)
        on conflict(artifact_key) do update set
          total = total + excluded.total,
          allowed = allowed + excluded.allowed,
          blocked = blocked + excluded.blocked,
          reviewed = reviewed + excluded.reviewed
        """,
        (artifact_key, total_delta, allowed_delta, blocked_delta, reviewed_delta),
    )


def record_receipt_insert(connection: sqlite3.Connection, receipt: GuardReceipt) -> None:
    _apply_receipt_delta(
        connection,
        harness=receipt.harness,
        artifact_name=receipt.artifact_name,
        artifact_id=receipt.artifact_id,
        policy_decision=receipt.policy_decision,
        timestamp=receipt.timestamp,
        multiplier=1,
    )


def record_receipt_policy_decision_change(
    connection: sqlite3.Connection,
    *,
    harness: str,
    artifact_name: str | None,
    artifact_id: str,
    timestamp: str,
    old_policy_decision: str,
    new_policy_decision: str,
) -> None:
    if old_policy_decision == new_policy_decision:
        return
    _apply_receipt_delta(
        connection,
        harness=harness,
        artifact_name=artifact_name,
        artifact_id=artifact_id,
        policy_decision=old_policy_decision,
        timestamp=timestamp,
        multiplier=-1,
    )
    _apply_receipt_delta(
        connection,
        harness=harness,
        artifact_name=artifact_name,
        artifact_id=artifact_id,
        policy_decision=new_policy_decision,
        timestamp=timestamp,
        multiplier=1,
    )


def backfill_receipt_rollups(connection: sqlite3.Connection) -> None:
    connection.execute("delete from receipt_aggregate_totals")
    connection.execute("delete from receipt_daily_rollups")
    connection.execute("delete from receipt_harness_rollups")
    connection.execute("delete from receipt_artifact_rollups")
    rows = connection.execute(
        """
        select harness, artifact_id, artifact_name, policy_decision, timestamp
        from runtime_receipts
        order by rowid asc
        """
    ).fetchall()
    for row in rows:
        _apply_receipt_delta(
            connection,
            harness=str(row["harness"]),
            artifact_name=row["artifact_name"],
            artifact_id=str(row["artifact_id"]),
            policy_decision=str(row["policy_decision"]),
            timestamp=str(row["timestamp"]),
            multiplier=1,
        )


def receipt_rollups_need_backfill(connection: sqlite3.Connection) -> bool:
    rollup_row = connection.execute(
        "select total from receipt_aggregate_totals where totals_key = ?",
        (_RECEIPT_TOTALS_KEY,),
    ).fetchone()
    if rollup_row is None:
        return True
    receipt_row = connection.execute("select count(*) as total from runtime_receipts").fetchone()
    receipt_total = int(receipt_row["total"]) if receipt_row is not None else 0
    rollup_total = int(rollup_row["total"])
    return rollup_total != receipt_total


def count_receipts_from_rollups(connection: sqlite3.Connection, *, harness: str | None = None) -> int | None:
    if harness is None:
        row = connection.execute(
            "select total from receipt_aggregate_totals where totals_key = ?",
            (_RECEIPT_TOTALS_KEY,),
        ).fetchone()
        return int(row["total"]) if row is not None else None
    row = connection.execute(
        "select total from receipt_harness_rollups where harness = ?",
        (harness,),
    ).fetchone()
    return int(row["total"]) if row is not None else 0


def load_receipt_analytics(
    connection: sqlite3.Connection,
    *,
    activity_days: int,
    trend_days: int,
    top_limit: int,
) -> dict[str, object]:
    now = datetime.now(tz=timezone.utc)
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    activity_start = start_of_today - timedelta(days=activity_days - 1)
    trend_start = start_of_today - timedelta(days=trend_days - 1)
    activity_start_key = activity_start.strftime("%Y-%m-%d")
    trend_start_key = trend_start.strftime("%Y-%m-%d")

    totals_row = connection.execute(
        "select total, allowed, blocked, reviewed, first_activity_at, last_activity_at "
        "from receipt_aggregate_totals where totals_key = ?",
        (_RECEIPT_TOTALS_KEY,),
    ).fetchone()

    daily_rows = connection.execute(
        """
        select day_key, total, allowed, blocked, reviewed
        from receipt_daily_rollups
        where day_key >= ?
        order by day_key asc
        """,
        (activity_start_key,),
    ).fetchall()

    harness_rows = connection.execute(
        """
        select harness, total, allowed, blocked, reviewed
        from receipt_harness_rollups
        order by total desc
        limit ?
        """,
        (top_limit,),
    ).fetchall()

    artifact_rows = connection.execute(
        """
        select artifact_key, total, allowed, blocked, reviewed
        from receipt_artifact_rollups
        order by total desc
        limit ?
        """,
        (top_limit,),
    ).fetchall()

    total = int(totals_row["total"]) if totals_row is not None else 0
    allowed = int(totals_row["allowed"] or 0) if totals_row is not None else 0
    blocked = int(totals_row["blocked"] or 0) if totals_row is not None else 0
    reviewed = int(totals_row["reviewed"] or 0) if totals_row is not None else 0
    first_activity_at = str(totals_row["first_activity_at"]) if totals_row and totals_row["first_activity_at"] else None
    last_activity_at = str(totals_row["last_activity_at"]) if totals_row and totals_row["last_activity_at"] else None

    daily_map = {str(row["day_key"]): int(row["total"]) for row in daily_rows}
    trend_map = {
        str(row["day_key"]): {
            "allowed": int(row["allowed"] or 0),
            "blocked": int(row["blocked"] or 0),
            "reviewed": int(row["reviewed"] or 0),
        }
        for row in daily_rows
        if str(row["day_key"]) >= trend_start_key
    }

    daily_activity: list[dict[str, object]] = []
    for offset in range(activity_days):
        day = activity_start + timedelta(days=offset)
        day_key = day.strftime("%Y-%m-%d")
        daily_activity.append({"date_key": day_key, "total": daily_map.get(day_key, 0)})

    trend_buckets: list[dict[str, object]] = []
    for offset in range(trend_days):
        day = trend_start + timedelta(days=offset)
        day_key = day.strftime("%Y-%m-%d")
        counts = trend_map.get(day_key, {"allowed": 0, "blocked": 0, "reviewed": 0})
        trend_buckets.append(
            {
                "date_key": day_key,
                "label": f"{day.strftime('%b')} {day.day}",
                "allowed": counts["allowed"],
                "blocked": counts["blocked"],
                "reviewed": counts["reviewed"],
            }
        )

    active_day_streak = 0
    streak_entries = list(reversed(daily_activity))
    if streak_entries and int(streak_entries[0]["total"]) == 0:
        streak_entries = streak_entries[1:]
    for entry in streak_entries:
        if int(entry["total"]) > 0:
            active_day_streak += 1
        else:
            break

    peak_day_total = max((int(entry["total"]) for entry in daily_activity), default=0)

    return {
        "total": total,
        "allowed": allowed,
        "blocked": blocked,
        "reviewed": reviewed,
        "first_activity_at": first_activity_at,
        "last_activity_at": last_activity_at,
        "active_day_streak": active_day_streak,
        "peak_day_total": peak_day_total,
        "daily_activity": daily_activity,
        "trend_buckets": trend_buckets,
        "by_harness": [
            {
                "harness": str(row["harness"]),
                "total": int(row["total"]),
                "allowed": int(row["allowed"] or 0),
                "blocked": int(row["blocked"] or 0),
            }
            for row in harness_rows
        ],
        "top_artifacts": [
            {
                "name": str(row["artifact_key"]),
                "total": int(row["total"]),
                "allowed": int(row["allowed"] or 0),
                "blocked": int(row["blocked"] or 0),
            }
            for row in artifact_rows
        ],
        "loaded_sample_limit": 200,
    }
