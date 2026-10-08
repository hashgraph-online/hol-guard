"""Local-only invocation preview for command-activity evidence."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from typing import Final, cast

from .store_command_activity_schema import _validate_schema_object_sql

COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION: Final = 27
INVOCATION_PREVIEW_MAX_CHARS: Final = 4_096


def command_activity_display_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists command_activity_invocation (
          activity_id text primary key references command_activity(activity_id) on delete cascade,
          invocation_preview text not null check (
            length(invocation_preview) between 1 and 4096
          )
        )
        """,
        """
        create trigger if not exists trg_command_activity_invocation_immutable
        before update on command_activity_invocation
        begin
          select raise(abort, 'command_activity_invocation_immutable');
        end
        """,
        """
        create trigger if not exists trg_command_activity_invocation_parent
        before insert on command_activity_invocation
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity invocation parent is missing');
        end
        """,
    )


def ensure_command_activity_display_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    statements = command_activity_display_schema_statements()
    connection.execute("savepoint command_activity_display_schema_v1")
    try:
        for statement in statements:
            connection.execute(statement)
        _validate_command_activity_display_schema(connection, statements)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to command_activity_display_schema_v1")
        connection.execute("release command_activity_display_schema_v1")
        raise
    connection.execute("release command_activity_display_schema_v1")


def _validate_command_activity_display_schema(
    connection: sqlite3.Connection,
    statements: tuple[str, ...],
) -> None:
    rows = cast(list[sqlite3.Row], connection.execute("pragma table_info(command_activity_invocation)").fetchall())
    columns = {str(row["name"]) for row in rows}
    if columns != {"activity_id", "invocation_preview"}:
        raise RuntimeError("incompatible command_activity_invocation schema")
    primary_key = tuple(str(row["name"]) for row in sorted(rows, key=lambda row: int(row["pk"])) if row["pk"])
    if primary_key != ("activity_id",):
        raise RuntimeError("incompatible command_activity_invocation primary key")
    _validate_schema_object_sql(connection, statements, family_label="display ")
    if len(statements) != 3:
        raise RuntimeError("incomplete command activity display schema")


__all__ = (
    "COMMAND_ACTIVITY_DISPLAY_SCHEMA_MIGRATION_VERSION",
    "INVOCATION_PREVIEW_MAX_CHARS",
    "command_activity_display_schema_statements",
    "ensure_command_activity_display_schema",
)
