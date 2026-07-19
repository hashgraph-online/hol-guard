"""Schema for command-activity API feedback and invalidation state."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import Final, cast

COMMAND_ACTIVITY_API_SCHEMA_MIGRATION_VERSION: Final = 13
COMMAND_ACTIVITY_INVALIDATION_LIMIT: Final = 10_000


def command_activity_api_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists command_activity_feedback (
          activity_id text primary key references command_activity(activity_id) on delete cascade,
          label text not null check (
            label in ('should_not_have_interrupted', 'expected_guard_to_stop_this')
          ),
          created_at text not null,
          updated_at text not null,
          schema_version text not null
        )
        """,
        """
        create table if not exists command_activity_invalidations (
          sequence integer primary key autoincrement,
          activity_id text not null
        )
        """,
        """
        create index if not exists idx_command_activity_feedback_label
        on command_activity_feedback (label, updated_at desc, activity_id desc)
        """,
        """
        create index if not exists idx_command_activity_execution_status_occurred_at
        on command_activity (execution_status, occurred_at desc, activity_id desc)
        """,
        """
        create index if not exists idx_command_activity_proof_level_occurred_at
        on command_activity (proof_level, occurred_at desc, activity_id desc)
        """,
        """
        create index if not exists idx_command_activity_approval_reuse_occurred_at
        on command_activity (approval_reuse_status, occurred_at desc, activity_id desc)
        """,
        """
        create index if not exists idx_command_activity_prompted_occurred_at
        on command_activity (prompted, occurred_at desc, activity_id desc)
        """,
        """
        create trigger if not exists trg_command_activity_invalidation_insert
        after insert on command_activity
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        """,
        """
        create trigger if not exists trg_command_activity_invalidation_update
        after update on command_activity
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        """,
        """
        create trigger if not exists trg_command_activity_invalidation_delete
        after delete on command_activity
        begin
          insert into command_activity_invalidations (activity_id) values (old.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        """,
        """
        create trigger if not exists trg_command_activity_feedback_invalidation_insert
        after insert on command_activity_feedback
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        """,
        """
        create trigger if not exists trg_command_activity_feedback_invalidation_update
        after update on command_activity_feedback
        begin
          insert into command_activity_invalidations (activity_id) values (new.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        """,
        """
        create trigger if not exists trg_command_activity_feedback_invalidation_delete
        after delete on command_activity_feedback
        begin
          insert into command_activity_invalidations (activity_id) values (old.activity_id);
          delete from command_activity_invalidations
          where sequence <= last_insert_rowid() - 10000;
        end
        """,
    )


def ensure_command_activity_api_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    statements = command_activity_api_schema_statements()
    connection.execute("savepoint command_activity_api_schema_v1")
    try:
        for statement in statements:
            connection.execute(statement)
        _validate_command_activity_api_schema(connection, statements)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (COMMAND_ACTIVITY_API_SCHEMA_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to command_activity_api_schema_v1")
        connection.execute("release command_activity_api_schema_v1")
        raise
    connection.execute("release command_activity_api_schema_v1")


def _validate_command_activity_api_schema(
    connection: sqlite3.Connection,
    statements: tuple[str, ...],
) -> None:
    expected_columns = {
        "command_activity_feedback": {
            "activity_id",
            "label",
            "created_at",
            "updated_at",
            "schema_version",
        },
        "command_activity_invalidations": {"sequence", "activity_id"},
    }
    for table, columns in expected_columns.items():
        rows = cast(list[sqlite3.Row], connection.execute(f"pragma table_info({table})").fetchall())
        if {str(row["name"]) for row in rows} != columns:
            raise RuntimeError(f"incompatible {table} schema")
        primary_key = tuple(str(row["name"]) for row in sorted(rows, key=lambda row: int(row["pk"])) if row["pk"])
        expected_primary_key = ("activity_id",) if table == "command_activity_feedback" else ("sequence",)
        if primary_key != expected_primary_key:
            raise RuntimeError(f"incompatible {table} primary key")

    _validate_schema_object_sql(connection, statements)
    if len(statements) != 13:
        raise RuntimeError("incomplete command activity API schema")


def _validate_schema_object_sql(connection: sqlite3.Connection, statements: tuple[str, ...]) -> None:
    expected: dict[str, str] = {}
    for statement in statements:
        canonical = _canonical_sql(statement)
        match = re.match(r"create (?:table|trigger|index) if not exists ([a-z0-9_]+)", canonical)
        if match is None:
            raise RuntimeError("unrecognized command activity API schema statement")
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
            raise RuntimeError(f"incompatible command activity API schema object: {name}")


def _canonical_sql(value: str) -> str:
    return " ".join(value.strip().lower().split())


__all__ = (
    "COMMAND_ACTIVITY_API_SCHEMA_MIGRATION_VERSION",
    "COMMAND_ACTIVITY_INVALIDATION_LIMIT",
    "command_activity_api_schema_statements",
    "ensure_command_activity_api_schema",
)
