"""Native store methods for the rows that steer the fleet posture report."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

# The native request parser caps how many keys one JSON object may hold.
_NATIVE_JSON_WIDTH = 4096


def _chunked_items(state: Mapping[str, object]) -> dict[str, object]:
    """The snapshot with a large ``items`` map split into objects the parser accepts."""

    items = state.get("items")
    if not isinstance(items, Mapping):
        return dict(state)
    pairs = list(items.items())
    chunks = [dict(pairs[start : start + _NATIVE_JSON_WIDTH]) for start in range(0, len(pairs), _NATIVE_JSON_WIDTH)]
    return {**state, "items": chunks}


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
            {"next_state": _chunked_items(next_state), "advanced_inventory": bool(advanced_inventory), "now": now},
        )
        return isinstance(answer, dict) and answer.get("cleared_full_inventory_request") is True

    def fleet_posture_cached_diagnostics(
        self: _NativeStore, *, now: str, ttl_seconds: int
    ) -> dict[str, dict[str, Any]]:
        """Every cached per-tool diagnostics summary still fresh at ``now``, keyed by harness."""

        answer = self._native_store_call(
            "fleet_posture_cached_diagnostics", {"now": now, "ttl_seconds": int(ttl_seconds)}
        )
        diagnostics = answer.get("diagnostics") if isinstance(answer, dict) else None
        if not isinstance(diagnostics, dict):
            raise RuntimeError("native fleet posture diagnostics cache returned no answer")
        return {str(harness): dict(summary) for harness, summary in diagnostics.items() if isinstance(summary, dict)}

    def record_fleet_posture_diagnostics(self: _NativeStore, *, entries: Mapping[str, object], now: str) -> None:
        """Stamp new per-tool diagnostics summaries with ``now`` and merge them into the cache."""

        self._native_store_call("record_fleet_posture_diagnostics", {"entries": dict(entries), "now": now})

    def fleet_posture_cached_runtimes(
        self: _NativeStore, *, scope: str, now: str, ttl_seconds: int
    ) -> dict[str, object] | None:
        """The cached ``runtimes`` section while it still answers for ``scope`` at ``now``."""

        answer = self._native_store_call(
            "fleet_posture_cached_runtimes", {"scope": scope, "now": now, "ttl_seconds": int(ttl_seconds)}
        )
        if not isinstance(answer, dict):
            raise RuntimeError("native fleet posture runtimes cache returned no answer")
        section = answer.get("section")
        return dict(section) if isinstance(section, dict) else None

    def record_fleet_posture_runtimes(
        self: _NativeStore,
        *,
        scope: str,
        section: Mapping[str, object],
        valid_until: float | None,
        now: str,
    ) -> None:
        """Store a freshly built ``runtimes`` section for ``scope`` with its bundle's expiry."""

        self._native_store_call(
            "record_fleet_posture_runtimes",
            {"scope": scope, "section": dict(section), "valid_until": valid_until, "now": now},
        )

    def fleet_posture_hash_key(self: _NativeStore, *, now: str) -> str:
        """The per-install fleet posture hash key, created and stored on first use.

        A stored key is read without taking the write lock, so a busy writer
        cannot cost a sync cycle its posture report. Only when no usable key is
        stored does the native store read the row again and write a new random
        key in one write transaction, so concurrent reports agree on one key.
        The native store owns the rule for which stored key is usable.
        """

        stored = self._native_store_call("stored_fleet_posture_hash_key", {})
        stored_key = stored.get("key") if isinstance(stored, dict) else None
        if isinstance(stored_key, str) and stored_key:
            return stored_key
        answer = self._native_store_call("fleet_posture_hash_key", {"now": now})
        key = answer.get("key") if isinstance(answer, dict) else None
        if not isinstance(key, str) or len(key) < 32:
            raise RuntimeError("native fleet posture hash key returned no answer")
        return key
