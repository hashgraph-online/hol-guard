"""Request read-state persistence for the local Guard store.

The native resident (``guard_store`` op) owns the SQL and keeps only the
newest read marks.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any


class StoreReadStateMixin:
    """Read-state for approval requests viewed by the user."""

    if TYPE_CHECKING:

        def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...

    def mark_requests_read(self, request_ids: list[str]) -> None:
        if not request_ids:
            return
        now = datetime.now(timezone.utc).isoformat()
        self._native_store_call("mark_requests_read", {"request_ids": list(request_ids), "now": now})

    def mark_request_unread(self, request_id: str) -> None:
        self._native_store_call("mark_request_unread", {"request_id": request_id})

    def get_read_state(self) -> list[str]:
        return [str(request_id) for request_id in self._native_store_call("get_read_state", {})]

    def clear_read_state(self) -> None:
        self._native_store_call("clear_read_state", {})
