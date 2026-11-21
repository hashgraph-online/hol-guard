"""Native store methods for the AI-BOM inventory sync rows and the timing rules that read them."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


def _object(value: object, method: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError(f"native {method} returned no answer")
    return value


class StoreAibomStateMixin:
    """The AI-BOM sync summary, endpoint backoff, user inventory, inventory context and daemon record."""

    def aibom_sync_schedule(
        self: _NativeStore, *, generated_at: str, min_interval_seconds: int
    ) -> tuple[bool, str | None]:
        """Whether an AI-BOM sync is due at ``generated_at``, and when the last one ran."""

        answer = _object(
            self._native_store_call(
                "aibom_sync_schedule",
                {"generated_at": generated_at, "min_interval_seconds": int(min_interval_seconds)},
            ),
            "aibom_sync_schedule",
        )
        last_sync_at = answer.get("last_sync_at")
        return answer.get("due") is True, last_sync_at if isinstance(last_sync_at, str) else None

    def aibom_sync_summary(self: _NativeStore) -> dict[str, object] | None:
        """The last stored AI-BOM sync summary."""

        summary = self._native_store_call("aibom_sync_summary", {})
        return summary if isinstance(summary, dict) else None

    def record_aibom_sync_summary(self: _NativeStore, summary: Mapping[str, object], *, now: str) -> None:
        """Store the outcome of an AI-BOM sync attempt."""

        self._native_store_call("record_aibom_sync_summary", {"payload": dict(summary), "now": now})

    def aibom_guard_events_backoff_active(self: _NativeStore, *, now: str) -> bool:
        """Whether the guard-events endpoint was recorded missing within the backoff window."""

        return self._native_store_call("aibom_guard_events_backoff_active", {"now": now}) is True

    def record_aibom_guard_events_unavailable(self: _NativeStore, *, events: int, accepted: int, now: str) -> None:
        """Record that the guard-events endpoint was missing, with the events still unsent."""

        self._native_store_call(
            "record_aibom_guard_events_unavailable",
            {"events": int(events), "accepted": int(accepted), "now": now},
        )

    def aibom_user_inventory_recency(
        self: _NativeStore, *, generated_at: str, min_interval_seconds: int
    ) -> tuple[bool, str | None]:
        """Whether the user-wide inventory was collected within the interval, and when."""

        answer = _object(
            self._native_store_call(
                "aibom_user_inventory_recency",
                {"generated_at": generated_at, "min_interval_seconds": int(min_interval_seconds)},
            ),
            "aibom_user_inventory_recency",
        )
        collected_at = answer.get("collected_at")
        return answer.get("recent") is True, collected_at if isinstance(collected_at, str) else None

    def record_aibom_user_inventory(self: _NativeStore, summary: Mapping[str, object], *, now: str) -> None:
        """Store the last user-wide inventory collection."""

        self._native_store_call("record_aibom_user_inventory", {"payload": dict(summary), "now": now})

    def aibom_inventory_context(self: _NativeStore, *, workspace_id: str | None) -> dict[str, object]:
        """The stored inventory context when it was recorded for ``workspace_id``, else empty."""

        return _object(
            self._native_store_call("aibom_inventory_context", {"workspace_id": workspace_id}),
            "aibom_inventory_context",
        )

    def record_aibom_inventory_context(self: _NativeStore, context: Mapping[str, object], *, now: str) -> None:
        """Store the home and workspace the daemon refreshes AI-BOM inventory for."""

        self._native_store_call("record_aibom_inventory_context", {"payload": dict(context), "now": now})

    def record_aibom_inventory_daemon(self: _NativeStore, record: Mapping[str, object], *, now: str) -> None:
        """Store the daemon's last AI-BOM inventory refresh."""

        self._native_store_call("record_aibom_inventory_daemon", {"payload": dict(record), "now": now})
