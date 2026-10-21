"""Read and maintenance queries for the local approval queue."""

from __future__ import annotations

from .native_approval_scope import UNAVAILABLE as SCOPE_UNAVAILABLE
from .native_approval_scope import ApprovalScopeUnavailableError
from .native_guard_store import NativeGuardStoreUnavailable
from .store_approvals import InvalidApprovalCursorError, _decode_page_cursor

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false
# ruff: noqa: F403,F405
from .store_base import *
from .temporary_mcp_approvals import temporary_mcp_approval_payload
from .trusted_local_tools import local_tool_approval_payload

_NO_ANSWER = "native_guard_store_unavailable"
_RETRYABLE_READS = frozenset(
    {
        "approval_desktop_notified_at",
        "count_approval_requests",
        "get_approval_extension_allow_hint",
        "get_approval_request",
        "get_next_pending_request",
        "list_approval_request_page",
        "list_approval_requests",
        "oldest_approval_request_created_at",
    }
)


def _with_approval_hints(payload: dict[str, object]) -> dict[str, object]:
    """Attach the queue hints the resident leaves to Python, as the scope payload did."""

    temporary_mcp_approval = temporary_mcp_approval_payload(payload)
    if temporary_mcp_approval is not None:
        payload["temporary_mcp_approval"] = temporary_mcp_approval
    local_tool_approval = local_tool_approval_payload(payload)
    if local_tool_approval is not None:
        payload["local_tool_approval"] = local_tool_approval
    return payload


def _cursor_marker(cursor: str | None) -> list[str] | None:
    """The `[last_seen_at, request_id]` a page cursor names; Python rejects a bad cursor first."""

    if cursor is None:
        return None
    marker = _decode_page_cursor(cursor)
    if marker is None:
        raise InvalidApprovalCursorError("invalid approval queue cursor")
    return [marker["last_seen_at"], marker["request_id"]]


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
        items = self._native_approval_pages(
            "list_approval_requests",
            {
                "status": status,
                "harness": harness,
                "limit": limit,
                "cursor": _cursor_marker(cursor),
                "search": search,
            },
        )["items"]
        return [_with_approval_hints(item) for item in items]

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
        return self.list_approval_request_page(
            status="pending",
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
        return self._native_approval_pages(
            "list_approval_request_page",
            {
                "status": status,
                "limit": limit,
                "cursor": _cursor_marker(cursor),
                "harness": harness,
                "search": search,
                "include_totals": include_totals,
                "exclude_watch_only": exclude_watch_only,
            },
        )

    def get_approval_request(self, request_id: str, *, derive_scope: bool = True) -> dict[str, object] | None:
        payload = self._native_approval_read(
            "get_approval_request", {"request_id": request_id, "derive_scope": derive_scope}
        )
        return _with_approval_hints(payload) if payload is not None and derive_scope else payload

    def _native_approval_pages(self, method: str, args: dict[str, object]) -> dict[str, Any]:
        """Every chunk of one native queue page.

        Each chunk continues after the sort key of the previous chunk's last row.
        """

        items: list[dict[str, object]] = []
        continuation: dict[str, object] = {}
        while True:
            page = self._native_approval_read(method, {**args, **continuation})
            items.extend(page.pop("items"))
            if page.pop("complete"):
                return {"items": items, **page}
            continuation = {"after": page.pop("after"), "taken": len(items)}

    def _native_approval_read(self, method: str, args: dict[str, object]) -> Any:
        """One native queue call; a resident without an answer reads as scope unavailable."""

        try:
            # `Path.resolve` of a relative config path starts from this process's directory.
            cwd: str | None = os.getcwd()
        except OSError:
            cwd = None
        try:
            return self._native_approval_call(method, {**args, "cwd": cwd})
        except NativeGuardStoreUnavailable as error:
            if method not in _RETRYABLE_READS or error.reason != _NO_ANSWER:
                raise ApprovalScopeUnavailableError from error
        # A read changes nothing, so a resident that dropped one round trip
        # (a restart, a busy socket) gets one more before the queue reads as
        # unavailable. Writes are never retried: the first may have landed.
        try:
            return self._native_approval_call(method, {**args, "cwd": cwd})
        except NativeGuardStoreUnavailable as error:
            raise ApprovalScopeUnavailableError from error

    def _native_approval_call(self, method: str, args: dict[str, object]) -> Any:
        try:
            return self._native_store_call(method, args)
        except ValueError as error:
            if str(error) == SCOPE_UNAVAILABLE:
                raise ApprovalScopeUnavailableError from error
            raise

    def get_approval_extension_allow_hint(self, request_id: str) -> dict[str, object] | None:
        return self._native_approval_read("get_approval_extension_allow_hint", {"request_id": request_id})

    def get_raw_approval_request_snapshot(self, request_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "select * from approval_requests where request_id = ?",
                (request_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def approval_desktop_notified_at(self, request_id: str) -> str | None:
        return self._native_approval_read("approval_desktop_notified_at", {"request_id": request_id})

    def mark_approval_desktop_notified(self, request_id: str, notified_at: str) -> None:
        self._native_approval_read(
            "mark_approval_desktop_notified", {"request_id": request_id, "notified_at": notified_at}
        )

    def get_next_pending_request(self, *, exclude_ids: set[str] | None = None) -> dict[str, object] | None:
        return self._native_approval_read("get_next_pending_request", {"exclude_ids": sorted(exclude_ids or ())})

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
        return int(
            self._native_approval_read(
                "count_approval_requests",
                {
                    "status": status,
                    "harness": harness,
                    "search": search,
                    "resolved_at_from": resolved_at_from,
                    "resolved_at_before": resolved_at_before,
                    "exclude_watch_only": exclude_watch_only,
                },
            )
        )

    def oldest_approval_request_created_at(self, *, status: str = "pending") -> str | None:
        return self._native_approval_read("oldest_approval_request_created_at", {"status": status})

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
