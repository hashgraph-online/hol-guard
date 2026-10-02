"""Read and maintenance queries for the local approval queue."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false
# ruff: noqa: F403,F405
from .store_base import *


class StoreApprovalQueriesMixin:
    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        with self._connect() as connection:
            return load_approval_requests(
                connection,
                status=status,
                harness=harness,
                limit=limit,
                cursor=cursor,
                search=search,
            )

    def list_pending_approval_summaries(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        harness: str | None = None,
        search: str | None = None,
        include_totals: bool = True,
        exclude_watch_only: bool = False,
    ) -> dict[str, object]:
        with self._connect() as connection:
            return load_pending_approval_summaries(
                connection,
                limit=limit,
                cursor=cursor,
                harness=harness,
                search=search,
                include_totals=include_totals,
                exclude_watch_only=exclude_watch_only,
            )

    def list_approval_request_page(
        self,
        *,
        status: str | None = "pending",
        limit: int = 50,
        cursor: str | None = None,
        harness: str | None = None,
        search: str | None = None,
        include_totals: bool = True,
        exclude_watch_only: bool = False,
    ) -> dict[str, object]:
        with self._connect() as connection:
            return load_approval_request_page(
                connection,
                status=status,
                limit=limit,
                cursor=cursor,
                harness=harness,
                search=search,
                include_totals=include_totals,
                exclude_watch_only=exclude_watch_only,
            )

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_approval_request(connection, request_id)

    def get_raw_approval_request_snapshot(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select * from approval_requests where request_id = ?",
                (request_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                select desktop_notified_at
                from approval_requests
                where request_id = ?
                """,
                (request_id,),
            ).fetchone()
        if row is None:
            return None
        value = row["desktop_notified_at"]
        return str(value) if isinstance(value, str) and value else None

    def mark_approval_desktop_notified(self, request_id: str, notified_at: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                update approval_requests
                set desktop_notified_at = ?
                where request_id = ?
                  and desktop_notified_at is null
                """,
                (notified_at, request_id),
            )

    def get_next_pending_request(self, *, exclude_ids: set[str] | None = None) -> dict[str, object] | None:
        with self._connect() as connection:
            return load_next_pending_request(connection, exclude_ids=exclude_ids)

    def count_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        search: str | None = None,
        resolved_at_from: str | None = None,
        resolved_at_before: str | None = None,
        exclude_watch_only: bool = False,
    ) -> int:
        with self._connect() as connection:
            return count_pending_approval_requests(
                connection,
                status=status,
                harness=harness,
                search=search,
                resolved_at_from=resolved_at_from,
                resolved_at_before=resolved_at_before,
                exclude_watch_only=exclude_watch_only,
            )

    def oldest_approval_request_created_at(self, *, status: str = "pending") -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "select min(created_at) as oldest_created_at from approval_requests where status = ?",
                (status,),
            ).fetchone()
        if row is None:
            return None
        value = row["oldest_created_at"]
        return str(value) if isinstance(value, str) and value else None

    def count_pending_requests(self, *, harness: str | None = None, search: str | None = None) -> int:
        return self.count_approval_requests(status="pending", harness=harness, search=search)

    def clear_approval_requests(self, *, harness: str | None = None, status: str | None = None) -> int:
        conditions: list[str] = []
        params: list[object] = []
        if harness is not None:
            conditions.append("harness = ?")
            params.append(harness)
        if status is not None:
            conditions.append("status = ?")
            params.append(status)
        query = "delete from approval_requests"
        if conditions:
            query += " where " + " and ".join(conditions)
        with self._connect() as connection:
            request_rows = connection.execute(
                f"select request_id from approval_requests{' where ' + ' and '.join(conditions) if conditions else ''}",
                tuple(params),
            ).fetchall()
            request_ids = [str(row["request_id"]) for row in request_rows]
            purge_request_resumes(connection, request_ids)
            cursor = connection.execute(query, tuple(params))
            return int(cursor.rowcount if cursor.rowcount is not None else 0)
