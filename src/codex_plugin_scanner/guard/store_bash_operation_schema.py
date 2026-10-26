"""Storage migration only; native code authenticates all execution records."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final

from .store_command_activity_schema import _validate_schema_object_sql

BASH_OPERATION_MIGRATION_VERSION: Final = 30
BASH_REVIEW_MIGRATION_VERSION: Final = 31
BASH_INVOCATION_MIGRATION_VERSION: Final = 32


def bash_operation_schema_statement() -> str:
    return (Path(__file__).parent / "schemas" / "native_bash_operations_v1.sql").read_text(encoding="utf-8")


def ensure_bash_operation_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    statements = (
        bash_operation_schema_statement(),
        (Path(__file__).parent / "schemas" / "native_bash_reviews_v1.sql").read_text(encoding="utf-8"),
        (Path(__file__).parent / "schemas" / "native_bash_invocations_v1.sql").read_text(encoding="utf-8"),
    )
    connection.execute("savepoint bash_operation_schema_v1")
    try:
        for statement in statements:
            connection.execute(statement)
        _validate_schema_object_sql(connection, statements, family_label="Bash operation ")
        connection.executemany(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (
                (version, applied_at)
                for version in (
                    BASH_OPERATION_MIGRATION_VERSION,
                    BASH_REVIEW_MIGRATION_VERSION,
                    BASH_INVOCATION_MIGRATION_VERSION,
                )
            ),
        )
    except BaseException:
        connection.execute("rollback to bash_operation_schema_v1")
        connection.execute("release bash_operation_schema_v1")
        raise
    connection.execute("release bash_operation_schema_v1")
