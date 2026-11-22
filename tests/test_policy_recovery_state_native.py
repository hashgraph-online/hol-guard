"""The recovery marker check reads the marker through the native store."""

from __future__ import annotations

from codex_plugin_scanner.guard.mcp.policy_recovery_state import request_recovery_recorded
from codex_plugin_scanner.guard.store_sync_payload_snapshot import SyncPayloadRowUnreadableError

_KEY = "business_policy_request_recovered_v1/req-1"


class _Store:
    def __init__(self, row: object = None, *, unreadable: bool = False) -> None:
        self.row = row
        self.unreadable = unreadable
        self.calls: list[tuple[str, ...]] = []

    def sync_payload_snapshot(self, *keys: str) -> dict[str, object]:
        self.calls.append(keys)
        if self.unreadable:
            raise SyncPayloadRowUnreadableError(f"sync_payload_unreadable:{keys[0]}")
        return {keys[0]: self.row}

    def _connect(self) -> object:
        raise AssertionError("the marker check must not open a Python connection")


def test_a_stored_marker_is_recorded() -> None:
    store = _Store({"source_digest": "d", "request_recovered": True})
    assert request_recovery_recorded(store, "req-1") is True
    assert store.calls == [(_KEY,)]


def test_a_missing_marker_is_not_recorded() -> None:
    assert request_recovery_recorded(_Store(None), "req-1") is False


def test_an_unreadable_marker_still_counts_as_recorded() -> None:
    assert request_recovery_recorded(_Store(unreadable=True), "req-1") is True
