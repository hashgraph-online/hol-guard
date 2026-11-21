"""Native store methods for the rows that steer the fleet posture report."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class _NativeStore(Protocol):
    def _native_store_call(
        self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
    ) -> Any: ...


class StoreFleetPostureStateMixin:
    """Settings, full-inventory request and last-sent rows, kept by the native store."""

    def fleet_posture_state(self: _NativeStore) -> dict[str, Any]:
        """The opt-out, a pending full-inventory request and the last accepted snapshot.

        ``last_sent`` is the stored object, possibly empty, or ``None``.
        """

        answer = self._native_store_call("fleet_posture_state", {})
        if not isinstance(answer, dict):
            raise RuntimeError("native fleet posture state returned no answer")
        last_sent = answer.get("last_sent")
        return {
            "opted_out": answer.get("opted_out") is True,
            "full_inventory_requested": answer.get("full_inventory_requested") is True,
            "last_sent": dict(last_sent) if isinstance(last_sent, dict) else None,
        }

    def set_fleet_posture_reporting(self: _NativeStore, *, enabled: bool, now: str) -> dict[str, object]:
        """Store the opt-out choice and return the new settings record."""

        answer = self._native_store_call("set_fleet_posture_reporting", {"enabled": enabled, "now": now})
        record = answer.get("record") if isinstance(answer, dict) else None
        if not isinstance(record, dict):
            raise RuntimeError("native fleet posture settings returned no record")
        return dict(record)

    def request_full_fleet_inventory(self: _NativeStore, *, source: str, now: str) -> None:
        """Make the next fleet posture report carry the full inventory."""

        self._native_store_call("request_full_fleet_inventory", {"source": source, "now": now})

    def commit_fleet_posture_sent(
        self: _NativeStore,
        *,
        next_state: Mapping[str, object],
        advanced_inventory: bool,
        now: str,
    ) -> bool:
        """Record the accepted snapshot; clear a full-inventory request it satisfied.

        Returns whether a pending request was cleared.
        """

        answer = self._native_store_call(
            "commit_fleet_posture_sent",
            {"next_state": dict(next_state), "advanced_inventory": bool(advanced_inventory), "now": now},
        )
        return isinstance(answer, dict) and answer.get("cleared_full_inventory_request") is True
