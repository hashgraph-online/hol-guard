"""The native store owns the AI-BOM inventory sync rows and the timing rules that read them."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-11-21T12:00:00Z"


def test_sync_schedule_reads_the_last_summary(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.aibom_sync_summary() is None
    assert store.aibom_sync_schedule(generated_at=_NOW, min_interval_seconds=600) == (True, None)
    store.record_aibom_sync_summary({"synced": True, "synced_at": "2026-11-21T11:55:00Z", "snapshots": 2}, now=_NOW)
    assert store.aibom_sync_schedule(generated_at=_NOW, min_interval_seconds=600) == (False, "2026-11-21T11:55:00Z")
    assert store.aibom_sync_schedule(generated_at=_NOW, min_interval_seconds=120) == (True, "2026-11-21T11:55:00Z")
    assert store.get_sync_payload("aibom_sync_summary") == store.aibom_sync_summary()


def test_an_empty_sync_is_retried_sooner(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.record_aibom_sync_summary({"synced": True, "synced_at": "2026-11-21T11:57:00Z", "snapshots": 0}, now=_NOW)
    due, _ = store.aibom_sync_schedule(generated_at=_NOW, min_interval_seconds=3600)
    assert due is True


def test_guard_events_backoff_window(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.aibom_guard_events_backoff_active(now=_NOW) is False
    store.record_aibom_guard_events_unavailable(events=4, accepted=1, now=_NOW)
    assert store.get_sync_payload("aibom_guard_events_backoff") == {
        "synced_at": _NOW,
        "events": 4,
        "accepted": 1,
        "skipped": 4,
        "sync_skipped": True,
        "sync_reason": "guard_events_endpoint_unavailable",
    }
    assert store.aibom_guard_events_backoff_active(now="2026-11-21T12:04:00Z") is True
    assert store.aibom_guard_events_backoff_active(now="2026-11-21T12:06:00Z") is False


def test_user_inventory_recency(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.aibom_user_inventory_recency(generated_at=_NOW, min_interval_seconds=600) == (False, None)
    store.record_aibom_user_inventory({"collected": True, "collected_at": "2026-11-21T11:58:00Z"}, now=_NOW)
    assert store.aibom_user_inventory_recency(generated_at=_NOW, min_interval_seconds=600) == (
        True,
        "2026-11-21T11:58:00Z",
    )
    assert store.aibom_user_inventory_recency(generated_at=_NOW, min_interval_seconds=60)[0] is False


def test_inventory_context_is_bound_to_the_current_workspace(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    context = {"home_dir": "/home/a", "workspace_dir": "/w", "workspace_id": "ws-1"}
    store.record_aibom_inventory_context(context, now=_NOW)
    assert store.aibom_inventory_context(workspace_id="ws-1") == context
    assert store.aibom_inventory_context(workspace_id="ws-2") == {}
    assert store.aibom_inventory_context(workspace_id=None) == {}


def test_daemon_record_and_refusals(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.record_aibom_inventory_daemon({"status": "synced", "refreshed_at": _NOW}, now=_NOW)
    assert store.get_sync_payload("aibom_inventory_daemon") == {"status": "synced", "refreshed_at": _NOW}
    with pytest.raises(ValueError, match="invalid_now"):
        store.record_aibom_inventory_daemon({"status": "error"}, now="")
    assert store.get_sync_payload("aibom_inventory_daemon") == {"status": "synced", "refreshed_at": _NOW}
