"""Request read-state persistence for the local Guard store.

The native resident (``guard_store`` op) owns the SQL and keeps only the
newest read marks. Marks travel in batches and pages that each fit one
native store message.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

_BATCH_BYTES = 1024 * 1024


def _batches(request_ids: list[str]) -> Iterator[list[str]]:
    batch: list[str] = []
    size = 0
    for request_id in request_ids:
        cost = len(json.dumps(request_id)) + 1
        if batch and size + cost > _BATCH_BYTES:
            yield batch
            batch, size = [], 0
        batch.append(request_id)
        size += cost
    if batch:
        yield batch


class StoreReadStateMixin:
    """Read-state for approval requests viewed by the user."""

    if TYPE_CHECKING:

        def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...

    def mark_requests_read(self, request_ids: list[str]) -> None:
        if not request_ids:
            return
        now = datetime.now(timezone.utc).isoformat()
        for batch in _batches(request_ids):
            self._native_store_call("mark_requests_read", {"request_ids": batch, "now": now})

    def mark_request_unread(self, request_id: str) -> None:
        self._native_store_call("mark_request_unread", {"request_id": request_id})

    def get_read_state(self) -> list[str]:
        request_ids: list[str] = []
        page: Mapping[str, Any] = {"after": None}
        while True:
            page = self._native_store_call("get_read_state", {"after": page["after"]})
            request_ids.extend(str(request_id) for request_id in page["ids"])
            if page["after"] is None:
                return request_ids

    def clear_read_state(self) -> None:
        self._native_store_call("clear_read_state", {})
