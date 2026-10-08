"""Schema migration for actionable versus Watch-only approval records."""

from __future__ import annotations

import sqlite3
from typing import Protocol

WATCH_ONLY_APPROVAL_MIGRATION_VERSION = 23


class ApprovalSchemaMigrator(Protocol):
    def _ensure_approval_column(
        self,
        connection: sqlite3.Connection,
        column_name: str,
        column_type: str,
    ) -> None: ...

    def _schema_version_applied(self, connection: sqlite3.Connection, *, version: int) -> bool: ...

    def _record_schema_version(self, connection: sqlite3.Connection, *, version: int) -> None: ...


def ensure_watch_only_approval_schema(
    connection: sqlite3.Connection,
    *,
    schema: ApprovalSchemaMigrator,
) -> None:
    for column in ("guard_version", "first_seen_guard_version", "last_seen_guard_version", "oauth_source"):
        schema._ensure_approval_column(connection, column, "text")
    schema._ensure_approval_column(connection, "watch_only_observation", "integer not null default 0")
    if schema._schema_version_applied(connection, version=WATCH_ONLY_APPROVAL_MIGRATION_VERSION):
        return
    connection.execute(
        """
        update approval_requests
        set watch_only_observation = 1
        where exists (
              select 1
              from json_each(coalesce(scanner_evidence_json, '[]'))
              where json_extract(value, '$.source') = 'observe_mode_inbox'
          )
        """
    )
    schema._record_schema_version(connection, version=WATCH_ONLY_APPROVAL_MIGRATION_VERSION)
