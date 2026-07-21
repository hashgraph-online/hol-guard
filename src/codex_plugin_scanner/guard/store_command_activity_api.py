"""Bounded queries and feedback for the local command-activity API."""

# pyright: reportAny=false, reportImplicitStringConcatenation=false, reportPrivateUsage=false
# pyright: reportUnnecessaryIsInstance=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from contextlib import AbstractContextManager
from datetime import date, datetime, time, timedelta, timezone
from typing import Protocol, cast

from .runtime.command_activity_api_contract import (
    COMMAND_ACTIVITY_API_SCHEMA_VERSION,
    CommandActivityAnalyticsQuery,
    CommandActivityFeedbackLabel,
    CommandActivityListQuery,
)


class CommandActivityNotFoundError(ValueError):
    pass


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


class StoreCommandActivityApiMixin:
    def list_command_activity_page(
        self: _ConnectionOwner,
        query: CommandActivityListQuery,
        *,
        cursor: tuple[str, str] | None = None,
    ) -> dict[str, object]:
        if not isinstance(cast(object, query), CommandActivityListQuery):
            raise ValueError("invalid_query")
        sql, params = _activity_page_query(query, cursor=cursor)
        with self._connect() as connection:
            connection.execute("begin")
            rows = cast(list[sqlite3.Row], connection.execute(sql, params).fetchall())
            page_rows = rows[: query.limit]
            items = _activity_items(connection, page_rows)
        next_marker = None
        if len(rows) > query.limit and page_rows:
            last = page_rows[-1]
            next_marker = (str(last["occurred_at"]), str(last["activity_id"]))
        return {
            "schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
            "items": items,
            "next_marker": next_marker,
        }

    def command_activity_analytics(
        self: _ConnectionOwner,
        query: CommandActivityAnalyticsQuery,
        *,
        as_of: date,
    ) -> dict[str, object]:
        if not isinstance(cast(object, query), CommandActivityAnalyticsQuery):
            raise ValueError("invalid_query")
        if type(cast(object, as_of)) is not date:
            raise ValueError("invalid_as_of")
        start = as_of - timedelta(days=query.days - 1)
        with self._connect() as connection:
            connection.execute("begin")
            trend = _analytics_trend(connection, query, start=start, end=as_of)
            dimensions = {
                dimension: _top_dimension(
                    connection,
                    dimension,
                    start=start,
                    end=as_of,
                    limit=query.top_limit,
                )
                for dimension in (
                    "harness",
                    "extension",
                    "rule",
                    "disposition",
                    "execution_status",
                    "prompt_status",
                    "proof_level",
                    "latency",
                )
            }
            feedback = _feedback_counts(connection, query=query, start=start, end=as_of)
            health = _health_payload(connection)
        total = sum(cast(int, item["count"]) for item in trend)
        return {
            "schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
            "window": {"from": start.isoformat(), "through": as_of.isoformat(), "days": query.days},
            "scope": {
                "dimension": query.dimension,
                "dimension_value": query.dimension_value,
            },
            "commands_checked": total,
            "trend": trend,
            "dimensions": dimensions,
            "dimension_breakdowns_scope": "global",
            "feedback": feedback,
            "health": health,
        }

    def record_command_activity_feedback(
        self: _ConnectionOwner,
        *,
        activity_id: str,
        label: CommandActivityFeedbackLabel,
        recorded_at: datetime,
    ) -> dict[str, object]:
        if not isinstance(activity_id, str) or not activity_id:
            raise ValueError("invalid_activity_id")
        if not isinstance(cast(object, label), CommandActivityFeedbackLabel):
            raise ValueError("invalid_feedback_label")
        if recorded_at.tzinfo is None or recorded_at.utcoffset() != timedelta(0):
            raise ValueError("recorded_at_must_be_utc")
        timestamp = recorded_at.isoformat()
        with self._connect() as connection:
            connection.execute("begin immediate")
            if (
                connection.execute(
                    "select 1 from command_activity where activity_id = ?",
                    (activity_id,),
                ).fetchone()
                is None
            ):
                raise CommandActivityNotFoundError(activity_id)
            existing = cast(
                sqlite3.Row | None,
                connection.execute(
                    "select label, created_at, updated_at from command_activity_feedback where activity_id = ?",
                    (activity_id,),
                ).fetchone(),
            )
            if existing is not None and str(existing["label"]) == label.value:
                changed = False
                created_at = str(existing["created_at"])
                updated_at = str(existing["updated_at"])
            else:
                created_at = str(existing["created_at"]) if existing is not None else timestamp
                updated_at = timestamp
                connection.execute(
                    """
                    insert into command_activity_feedback (
                      activity_id, label, created_at, updated_at, schema_version
                    ) values (?, ?, ?, ?, ?)
                    on conflict(activity_id) do update set
                      label = excluded.label,
                      updated_at = excluded.updated_at,
                      schema_version = excluded.schema_version
                    """,
                    (activity_id, label.value, created_at, timestamp, COMMAND_ACTIVITY_API_SCHEMA_VERSION),
                )
                changed = True
        return {
            "schema_version": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
            "activity_id": activity_id,
            "label": label.value,
            "created_at": created_at,
            "updated_at": updated_at,
            "changed": changed,
        }

    def list_command_activity_invalidations(
        self: _ConnectionOwner,
        cursor: int,
        *,
        limit: int = 100,
    ) -> dict[str, object]:
        if type(cursor) is not int or cursor < 0:
            raise ValueError("invalid_invalidation_cursor")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid_invalidation_limit")
        with self._connect() as connection:
            connection.execute("begin")
            bounds = cast(
                sqlite3.Row,
                connection.execute(
                    "select min(sequence) as minimum, max(sequence) as maximum from command_activity_invalidations"
                ).fetchone(),
            )
            minimum = int(bounds["minimum"]) if bounds["minimum"] is not None else None
            maximum = int(bounds["maximum"]) if bounds["maximum"] is not None else None
            reset_required = (minimum is None and cursor > 0) or (
                minimum is not None and maximum is not None and (cursor < minimum - 1 or cursor > maximum)
            )
            if reset_required:
                if minimum is None or maximum is None:
                    effective_cursor = 0
                elif cursor > maximum:
                    effective_cursor = maximum
                else:
                    effective_cursor = minimum - 1
            else:
                effective_cursor = cursor
            rows = cast(
                list[sqlite3.Row],
                connection.execute(
                    """
                    select sequence, activity_id from command_activity_invalidations
                    where sequence > ? order by sequence limit ?
                    """,
                    (effective_cursor, limit),
                ).fetchall(),
            )
        return {
            "reset_required": reset_required,
            "reset_cursor": effective_cursor if reset_required else None,
            "items": [{"sequence": int(row["sequence"]), "activity_id": str(row["activity_id"])} for row in rows],
        }


def _activity_page_query(
    query: CommandActivityListQuery,
    *,
    cursor: tuple[str, str] | None,
) -> tuple[str, tuple[object, ...]]:
    clauses: list[str] = []
    params: list[object] = []
    for column, value in (
        ("activity.harness", query.harness),
        ("activity.execution_status", query.execution_status),
        ("activity.proof_level", query.proof_level),
        ("activity.approval_reuse_status", query.approval_reuse_status),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    if query.prompted is not None:
        clauses.append("activity.prompted = ?")
        params.append(int(query.prompted))
    if query.occurred_from is not None:
        clauses.append("activity.occurred_at >= ?")
        params.append(datetime.combine(query.occurred_from, time.min, tzinfo=timezone.utc).isoformat())
    if query.occurred_through is not None:
        if query.occurred_through == date.max:
            clauses.append("activity.occurred_at <= ?")
            params.append("9999-12-31T23:59:59.999999+00:00")
        else:
            clauses.append("activity.occurred_at < ?")
            through_exclusive = query.occurred_through + timedelta(days=1)
            params.append(datetime.combine(through_exclusive, time.min, tzinfo=timezone.utc).isoformat())
    for column, value in (("extension_id", query.extension_id), ("rule_id", query.rule_id)):
        if value is not None:
            clauses.append(
                f"activity.activity_id in (select match.activity_id from command_activity_matches as match "
                f"where match.{column} = ?)"
            )
            params.append(value)
    if cursor is not None:
        clauses.append("(activity.occurred_at < ? or (activity.occurred_at = ? and activity.activity_id < ?))")
        params.extend((cursor[0], cursor[0], cursor[1]))
    where = " where " + " and ".join(clauses) if clauses else ""
    sql = (
        "select activity.*, feedback.label as feedback_label "
        "from command_activity as activity "
        "left join command_activity_feedback as feedback using (activity_id)"
        f"{where} order by activity.occurred_at desc, activity.activity_id desc limit ?"
    )
    params.append(query.limit + 1)
    return sql, tuple(params)


def _activity_items(connection: sqlite3.Connection, rows: Sequence[sqlite3.Row]) -> list[dict[str, object]]:
    if not rows:
        return []
    activity_ids = [str(row["activity_id"]) for row in rows]
    placeholders = ",".join("?" for _ in activity_ids)
    match_rows = cast(
        list[sqlite3.Row],
        connection.execute(
            f"""
            select matches.*, effects.effect_class from command_activity_matches as matches
            left join command_activity_match_effects as effects
              on effects.activity_id = matches.activity_id and effects.ordinal = matches.ordinal
            where matches.activity_id in ({placeholders})
            order by matches.activity_id, matches.ordinal, effects.effect_class
            """,
            tuple(activity_ids),
        ).fetchall(),
    )
    matches_by_activity = _group_matches(match_rows)
    return [_activity_row_payload(row, matches_by_activity.get(str(row["activity_id"]), [])) for row in rows]


def _group_matches(rows: Sequence[sqlite3.Row]) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    keys: dict[tuple[str, int], dict[str, object]] = {}
    for row in rows:
        activity_id = str(row["activity_id"])
        ordinal = int(row["ordinal"])
        key = (activity_id, ordinal)
        item: dict[str, object] | None = keys.get(key)
        if item is None:
            item = {
                "ordinal": ordinal,
                "extension_id": str(row["extension_id"]),
                "extension_version": str(row["extension_version"]),
                "rule_id": str(row["rule_id"]),
                "rule_version": str(row["rule_version"]),
                "match_class": str(row["match_class"]),
                "severity": str(row["severity"]),
                "default_floor": str(row["default_floor"]),
                "safe_variant_id": str(row["safe_variant_id"]) if row["safe_variant_id"] is not None else None,
                "effect_classes": [],
                "schema_version": str(row["schema_version"]),
            }
            keys[key] = item
            grouped.setdefault(activity_id, []).append(item)
        effect = row["effect_class"]
        if effect is not None:
            cast(list[str], item["effect_classes"]).append(str(effect))
    return grouped


def _activity_row_payload(row: sqlite3.Row, matches: list[dict[str, object]]) -> dict[str, object]:
    return {
        "activity_id": str(row["activity_id"]),
        "occurred_at": str(row["occurred_at"]),
        "harness": str(row["harness"]),
        "hook_phase": str(row["hook_phase"]),
        "execution_status": str(row["execution_status"]),
        "proof_level": str(row["proof_level"]),
        "policy_action": str(row["policy_action"]) if row["policy_action"] is not None else None,
        "decision_reason_code": str(row["decision_reason_code"]) if row["decision_reason_code"] is not None else None,
        "controlling_rule_id": str(row["controlling_rule_id"]) if row["controlling_rule_id"] is not None else None,
        "parse_confidence": str(row["parse_confidence"]) if row["parse_confidence"] is not None else None,
        "uncertainty_class": str(row["uncertainty_class"]) if row["uncertainty_class"] is not None else None,
        "match_count": int(row["match_count"]),
        "prompted": bool(row["prompted"]),
        "approval_reuse_status": str(row["approval_reuse_status"]),
        "receipt_link_status": str(row["receipt_link_status"]),
        "receipt_id": str(row["receipt_id"]) if row["receipt_id"] is not None else None,
        "evaluation_latency_bucket": str(row["evaluation_latency_bucket"]),
        "persistence_latency_bucket": str(row["persistence_latency_bucket"]),
        "feedback_label": str(row["feedback_label"]) if row["feedback_label"] is not None else None,
        "schema_version": str(row["schema_version"]),
        "matches": matches,
    }


def _analytics_trend(
    connection: sqlite3.Connection,
    query: CommandActivityAnalyticsQuery,
    *,
    start: date,
    end: date,
) -> list[dict[str, object]]:
    if query.dimension is None:
        rows = connection.execute(
            """select day, total as count from command_activity_daily_totals
            where day between ? and ? order by day""",
            (start.isoformat(), end.isoformat()),
        ).fetchall()
    else:
        rows = connection.execute(
            """select day, count from command_activity_daily_rollups
            where day between ? and ? and dimension = ? and dimension_value = ? order by day""",
            (start.isoformat(), end.isoformat(), query.dimension, query.dimension_value),
        ).fetchall()
    return [{"day": str(row["day"]), "count": int(row["count"])} for row in rows]


def _top_dimension(
    connection: sqlite3.Connection,
    dimension: str,
    *,
    start: date,
    end: date,
    limit: int,
) -> list[dict[str, object]]:
    rows = connection.execute(
        """
        select dimension_value, sum(count) as total from command_activity_daily_rollups
        where day between ? and ? and dimension = ?
        group by dimension_value order by total desc, dimension_value limit ?
        """,
        (start.isoformat(), end.isoformat(), dimension, limit),
    ).fetchall()
    return [{"value": str(row["dimension_value"]), "count": int(row["total"])} for row in rows]


def _feedback_counts(
    connection: sqlite3.Connection,
    *,
    query: CommandActivityAnalyticsQuery,
    start: date,
    end: date,
) -> list[dict[str, object]]:
    end_exclusive = end + timedelta(days=1)
    clauses = ["activity.occurred_at >= ?", "activity.occurred_at < ?"]
    params: list[object] = [
        datetime.combine(start, time.min, tzinfo=timezone.utc).isoformat(),
        datetime.combine(end_exclusive, time.min, tzinfo=timezone.utc).isoformat(),
    ]
    if query.dimension == "harness":
        clauses.append("activity.harness = ?")
        params.append(query.dimension_value)
    elif query.dimension in {"extension", "rule"}:
        column = "extension_id" if query.dimension == "extension" else "rule_id"
        clauses.append(
            f"activity.activity_id in (select match.activity_id from command_activity_matches as match "
            f"where match.{column} = ?)"
        )
        params.append(query.dimension_value)
    rows = connection.execute(
        f"""
        select feedback.label, count(*) as total from command_activity_feedback as feedback
        join command_activity as activity using (activity_id)
        where {" and ".join(clauses)}
        group by feedback.label order by feedback.label
        """,
        tuple(params),
    ).fetchall()
    return [{"label": str(row["label"]), "count": int(row["total"])} for row in rows]


def _health_payload(connection: sqlite3.Connection) -> dict[str, object]:
    row = cast(
        sqlite3.Row | None,
        connection.execute("select * from command_activity_health where singleton = 1").fetchone(),
    )
    if row is None:
        return {"status": "degraded", "dropped_events": 0, "persistence_errors": 0}
    return {
        "status": ("degraded" if int(row["dropped_event_count"]) or int(row["persistence_error_count"]) else "healthy"),
        "dropped_events": int(row["dropped_event_count"]),
        "persistence_errors": int(row["persistence_error_count"]),
        "last_error_class": str(row["last_error_code"]) if row["last_error_code"] is not None else None,
        "last_error_at": str(row["last_error_at"]) if row["last_error_at"] is not None else None,
    }


__all__ = (
    "CommandActivityNotFoundError",
    "StoreCommandActivityApiMixin",
)
