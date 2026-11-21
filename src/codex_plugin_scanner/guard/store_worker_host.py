"""Native store methods for the rows the request handlers and the worker host hand each other."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class StoreWorkerHostMixin:
    """Approval attention, the worker refresh handshake and the repair self-check status."""

    def queue_approval_attention(
        self: _NativeStore, *, operation_id: str, requests: Sequence[Mapping[str, object]], now: str
    ) -> None:
        """Leave an operation waiting on approval for the worker host's attention loop."""

        self._native_store_call(
            "queue_approval_attention",
            {"operation_id": operation_id, "requests": [dict(item) for item in requests], "now": now},
        )

    def take_approval_attention(self: _NativeStore) -> list[dict[str, object]]:
        """Every queued attention row, removed in the same write as it is read."""

        taken = self._native_store_call("take_approval_attention", {})
        if not isinstance(taken, list):
            raise RuntimeError("native approval attention take returned no answer")
        return [dict(item) for item in taken if isinstance(item, dict)]

    def request_worker_refresh(self: _NativeStore, *, nonce: str, now: str) -> None:
        """Ask the worker host to refresh its queue workers."""

        self._native_store_call("request_worker_refresh", {"nonce": nonce, "now": now})

    def worker_refresh_status(self: _NativeStore, *, nonce: str) -> dict[str, bool] | None:
        """The worker host's answer to the request with ``nonce``, or ``None`` before it answers."""

        status = self._native_store_call("worker_refresh_status", {"nonce": nonce})
        if not isinstance(status, dict):
            return None
        return {"running": status.get("running") is True, "sync_running": status.get("sync_running") is True}

    def take_worker_refresh_request(self: _NativeStore) -> str | None:
        """The waiting refresh request's nonce, removing the request; ``None`` when none is waiting."""

        nonce = self._native_store_call("take_worker_refresh_request", {})
        return nonce if isinstance(nonce, str) else None

    def record_worker_refresh_status(
        self: _NativeStore, *, nonce: str, running: bool, sync_running: bool, now: str
    ) -> None:
        """Answer the refresh request with ``nonce``."""

        self._native_store_call(
            "record_worker_refresh_status",
            {"nonce": nonce, "running": running, "sync_running": sync_running, "now": now},
        )

    def record_repair_self_check(self: _NativeStore, *, status: Mapping[str, object], now: str) -> None:
        """Publish the latest repair self-check status."""

        self._native_store_call("record_repair_self_check", {"status": dict(status), "now": now})

    def repair_self_check_status(self: _NativeStore) -> dict[str, object] | None:
        """The latest repair self-check status, or ``None`` when none is stored."""

        status = self._native_store_call("repair_self_check_status", {})
        return dict(status) if isinstance(status, dict) else None
