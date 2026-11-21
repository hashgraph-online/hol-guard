"""A successful sync's summary is stored through the native store write."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-08-03T00:01:00+00:00"


def test_the_summary_round_trips_without_a_connect_state(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    summary: dict[str, object] = {"synced_at": _NOW, "receipts_stored": 4, "nested": {"z": 1, "a": [1, 2]}}

    assert store.record_sync_summary(summary, now=_NOW) is None
    assert store.get_sync_payload("sync_summary") == summary


def test_skipping_the_summary_leaves_the_stored_one(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.record_sync_summary({"synced_at": "older"}, now=_NOW)

    store.record_sync_summary({"synced_at": _NOW}, now=_NOW, persist_summary=False)

    assert store.get_sync_payload("sync_summary") == {"synced_at": "older"}
