"""Schema for bounded command-activity rollup and retention maintenance."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import Final, cast

COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_MIGRATION_VERSION: Final = 12
COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION: Final = "guard.command-activity-maintenance.v1"


def command_activity_maintenance_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists command_activity_rollup_membership (
          activity_id text primary key,
          day text not null,
          occurred_at text not null,
          rolled_at text not null,
          detail_present integer not null default 1 check (detail_present in (0, 1))
        )
        """,
        """
        create index if not exists idx_command_activity_rollup_membership_day
        on command_activity_rollup_membership (detail_present, day, activity_id)
        """,
        """
        create index if not exists idx_command_activity_rollup_membership_occurred_at
        on command_activity_rollup_membership (detail_present, occurred_at, activity_id)
        """,
        """
        create table if not exists command_activity_rollup_pending (
          activity_id text primary key,
          occurred_at text not null
        )
        """,
        """
        create table if not exists command_activity_maintenance (
          singleton integer primary key check (singleton = 1),
          last_completed_day text,
          last_run_at text,
          detail_compaction_started_at text,
          rollup_backfill_cursor_occurred_at text,
          rollup_backfill_cursor_activity_id text,
          rollup_backfill_complete integer not null default 0 check (rollup_backfill_complete in (0, 1)),
          last_backfilled_rows integer not null default 0 check (last_backfilled_rows >= 0),
          last_detail_rows_deleted integer not null default 0 check (last_detail_rows_deleted >= 0),
          last_correlation_rows_deleted integer not null default 0 check (last_correlation_rows_deleted >= 0),
          last_aggregate_rows_deleted integer not null default 0 check (last_aggregate_rows_deleted >= 0),
          schema_version text not null
        )
        """,
        """
        create trigger if not exists trg_command_activity_rollup_membership_parent
        before insert on command_activity_rollup_membership
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity rollup membership parent is missing');
        end
        """,
        """
        create trigger if not exists trg_command_activity_rollup_membership_detail_deleted
        after delete on command_activity
        begin
          update command_activity_rollup_membership
          set detail_present = 0 where activity_id = old.activity_id;
        end
        """,
        """
        create trigger if not exists trg_command_activity_rollup_pending_parent_inserted
        after insert on command_activity
        begin
          insert or ignore into command_activity_rollup_pending (activity_id, occurred_at)
          values (new.activity_id, new.occurred_at);
        end
        """,
        """
        create trigger if not exists trg_command_activity_rollup_pending_membership_inserted
        after insert on command_activity_rollup_membership
        begin
          delete from command_activity_rollup_pending where activity_id = new.activity_id;
        end
        """,
        """
        create trigger if not exists trg_command_activity_rollup_pending_parent_deleted
        after delete on command_activity
        begin
          delete from command_activity_rollup_pending where activity_id = old.activity_id;
        end
        """,
    )


def ensure_command_activity_maintenance_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Apply and validate maintenance state in one savepoint."""

    statements = command_activity_maintenance_schema_statements()
    connection.execute("savepoint command_activity_maintenance_schema_v1")
    try:
        for statement in statements:
            connection.execute(statement)
        connection.execute(
            """
            insert or ignore into command_activity_maintenance (
              singleton, last_completed_day, last_run_at, detail_compaction_started_at,
              rollup_backfill_cursor_occurred_at, rollup_backfill_cursor_activity_id,
              rollup_backfill_complete,
              last_backfilled_rows,
              last_detail_rows_deleted, last_correlation_rows_deleted,
              last_aggregate_rows_deleted, schema_version
            ) values (1, null, null, null, null, null, 0, 0, 0, 0, 0, ?)
            """,
            (COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION,),
        )
        _validate_command_activity_maintenance_schema(connection, statements)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to command_activity_maintenance_schema_v1")
        connection.execute("release command_activity_maintenance_schema_v1")
        raise
    connection.execute("release command_activity_maintenance_schema_v1")


def _validate_command_activity_maintenance_schema(
    connection: sqlite3.Connection,
    statements: tuple[str, ...],
) -> None:
    expected_columns = {
        "command_activity_rollup_membership": {
            "activity_id",
            "day",
            "occurred_at",
            "rolled_at",
            "detail_present",
        },
        "command_activity_maintenance": {
            "singleton",
            "last_completed_day",
            "last_run_at",
            "detail_compaction_started_at",
            "rollup_backfill_cursor_occurred_at",
            "rollup_backfill_cursor_activity_id",
            "rollup_backfill_complete",
            "last_backfilled_rows",
            "last_detail_rows_deleted",
            "last_correlation_rows_deleted",
            "last_aggregate_rows_deleted",
            "schema_version",
        },
        "command_activity_rollup_pending": {"activity_id", "occurred_at"},
    }
    for table, expected in expected_columns.items():
        rows = cast(
            list[tuple[int, str, str, int, object | None, int]],
            connection.execute(f"pragma table_info({table})").fetchall(),
        )
        if {str(row[1]) for row in rows} != expected:
            raise RuntimeError(f"incompatible {table} schema")
        primary_key = tuple(str(row[1]) for row in sorted(rows, key=lambda item: int(item[5])) if int(row[5]) > 0)
        expected_primary_key = ("singleton",) if table == "command_activity_maintenance" else ("activity_id",)
        if primary_key != expected_primary_key:
            raise RuntimeError(f"incompatible {table} primary key")
    _validate_schema_object_sql(connection, statements)
    row = cast(
        sqlite3.Row | None,
        connection.execute("select * from command_activity_maintenance where singleton = 1").fetchone(),
    )
    if row is None or str(row["schema_version"]) != COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION:
        raise RuntimeError("incompatible command_activity_maintenance singleton")


def _validate_schema_object_sql(connection: sqlite3.Connection, statements: tuple[str, ...]) -> None:
    expected: dict[str, str] = {}
    for statement in statements:
        canonical = _canonical_sql(statement)
        match = re.match(r"create (?:table|trigger|index) if not exists ([a-z0-9_]+)", canonical)
        if match is None:
            raise RuntimeError("unrecognized command activity maintenance schema statement")
        expected[match.group(1)] = canonical.replace(" if not exists", "", 1)
    placeholders = ", ".join("?" for _ in expected)
    rows = cast(
        list[tuple[str, str]],
        connection.execute(
            f"select name, sql from sqlite_schema where name in ({placeholders})",
            tuple(expected),
        ).fetchall(),
    )
    actual = {name: _canonical_sql(sql) for name, sql in rows}
    for name, expected_sql in expected.items():
        if actual.get(name) != expected_sql:
            raise RuntimeError(f"incompatible command activity maintenance schema object: {name}")


def _canonical_sql(value: str) -> str:
    return " ".join(value.strip().lower().split())


__all__ = [
    "COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_MIGRATION_VERSION",
    "COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION",
    "command_activity_maintenance_schema_statements",
    "ensure_command_activity_maintenance_schema",
]
