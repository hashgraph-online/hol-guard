"""Request read-state persistence for the local Guard store."""

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager

# pyright: reportAttributeAccessIssue=false
from datetime import datetime, timezone
from typing import TYPE_CHECKING


class StoreReadStateMixin:
    """SQLite-backed read-state for approval requests viewed by the user."""

    READ_STATE_LIMIT = 50000

    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def mark_requests_read(self, request_ids: list[str]) -> None:
        if not request_ids:
            return
        now = datetime.now(timezone.utc).isoformat()
        unique_ids = list(dict.fromkeys(request_ids))
        with self._connect() as connection:
            for rid in unique_ids:
                connection.execute(
                    "insert into guard_request_read_state (request_id, read_at) values (?, ?) "
                    "on conflict(request_id) do update set read_at = excluded.read_at",
                    (rid, now),
                )
            connection.execute(
                "delete from guard_request_read_state where request_id not in "
                "(select request_id from guard_request_read_state order by read_at desc limit ?)",
                (self.READ_STATE_LIMIT,),
            )

    def mark_request_unread(self, request_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "delete from guard_request_read_state where request_id = ?",
                (request_id,),
            )

    def get_read_state(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "select request_id from guard_request_read_state order by read_at desc limit ?",
                (self.READ_STATE_LIMIT,),
            ).fetchall()
        return [str(row["request_id"]) for row in rows]

    def clear_read_state(self) -> None:
        with self._connect() as connection:
            connection.execute("delete from guard_request_read_state")
