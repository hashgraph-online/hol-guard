"""Schema migration for bounded command activity persistence health."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import Final, cast

COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION: Final = 14
_LEGACY_COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION: Final = 11
COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION: Final = "1.0.0"
_HEALTH_TABLE_SQL: Final = """
create table if not exists command_activity_health (
  singleton integer primary key check (singleton = 1),
  dropped_event_count integer not null check (dropped_event_count between 0 and 9223372036854775807),
  persistence_error_count integer not null check (persistence_error_count between 0 and 9223372036854775807),
  last_error_code text check (last_error_code is null or length(last_error_code) between 1 and 64),
  last_error_at text,
  schema_version text not null
)
"""


def ensure_command_activity_health_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Create and validate health state, repairing legacy false post failures once."""

    connection.execute("savepoint command_activity_health_schema_v1")
    try:
        connection.execute(_HEALTH_TABLE_SQL)
        _validate_health_schema(connection)
        connection.execute(
            """
            insert or ignore into command_activity_health (
              singleton, dropped_event_count, persistence_error_count,
              last_error_code, last_error_at, schema_version
            ) values (1, 0, 0, null, null, ?)
            """,
            (COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION,),
        )
        _validate_health_row(connection)
        migration_applied = cast(
            tuple[int] | None,
            connection.execute(
                "select 1 from schema_migrations where version = ?",
                (COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
            ).fetchone(),
        )
        if migration_applied is None:
            legacy_applied = cast(
                tuple[int] | None,
                connection.execute(
                    "select 1 from schema_migrations where version = ?",
                    (_LEGACY_COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION,),
                ).fetchone(),
            )
            if legacy_applied is not None:
                connection.execute(
                    """
                    update command_activity_health
                    set dropped_event_count = 0, persistence_error_count = 0,
                        last_error_code = null, last_error_at = null
                    where singleton = 1 and last_error_code = 'post_record_failed'
                    """
                )
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (COMMAND_ACTIVITY_HEALTH_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to command_activity_health_schema_v1")
        connection.execute("release command_activity_health_schema_v1")
        raise
    connection.execute("release command_activity_health_schema_v1")


def _validate_health_schema(connection: sqlite3.Connection) -> None:
    rows = cast(
        list[tuple[int, str, str, int, object | None, int]],
        connection.execute("pragma table_info(command_activity_health)").fetchall(),
    )
    expected_columns = {
        "singleton",
        "dropped_event_count",
        "persistence_error_count",
        "last_error_code",
        "last_error_at",
        "schema_version",
    }
    if {str(row[1]) for row in rows} != expected_columns:
        raise RuntimeError("incompatible command_activity_health schema")
    primary_key = tuple(str(row[1]) for row in rows if int(row[5]) > 0)
    if primary_key != ("singleton",):
        raise RuntimeError("incompatible command_activity_health primary key")
    row = cast(
        tuple[str] | None,
        connection.execute(
            "select sql from sqlite_schema where type = 'table' and name = 'command_activity_health'"
        ).fetchone(),
    )
    expected_sql = _canonical_sql(_HEALTH_TABLE_SQL).replace(" if not exists", "", 1)
    if row is None or _canonical_sql(row[0]) != expected_sql:
        raise RuntimeError("incompatible command_activity_health schema object")


def _validate_health_row(connection: sqlite3.Connection) -> None:
    row = cast(
        tuple[int, int, int, str | None, str | None, str] | None,
        connection.execute("select * from command_activity_health where singleton = 1").fetchone(),
    )
    if row is None or row[5] != COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION:
        raise RuntimeError("incompatible command_activity_health singleton")


def _canonical_sql(value: str) -> str:
    return " ".join(re.sub(r"\s+", " ", value.strip().lower()).split())
