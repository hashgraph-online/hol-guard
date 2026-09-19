"""HGP-162: automatic headless sync after connect and restart."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.first_cloud_sync import maybe_queue_first_cloud_sync
from codex_plugin_scanner.guard.runtime.cloud_review_sync_worker import (
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_first_sync_runs_without_dashboard(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.get_cloud_sync_profile = lambda: {  # type: ignore[method-assign]
        "workspace_id": "workspace-1",
        "sync_url": "https://hol.example/api/guard/receipts/sync",
    }
    store.get_oauth_local_credential_health = lambda: {"configured": True, "state": "healthy"}  # type: ignore[method-assign]
    store.get_effective_guard_connect_state = lambda now="": {  # type: ignore[method-assign]
        "status": "connected",
        "milestone": "first_sync_pending",
    }
    calls: list[str] = []

    def queue_sync(*, store: GuardStore, managed_controls_publish: object = None) -> dict[str, object]:
        del store, managed_controls_publish
        calls.append("sync")
        return {"status": "queued"}

    result = maybe_queue_first_cloud_sync(
        store=store,
        queue_sync=queue_sync,
        repair_connect=lambda _store: None,
        now=lambda: "2026-07-18T00:00:00Z",
    )
    assert result == {"status": "queued"}
    assert calls == ["sync"]


def test_review_worker_starts_disconnected_and_survives_restart(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    worker = start_cloud_sync_sync_worker(store, poll_interval=0.2)
    assert worker is not None
    assert worker.thread.is_alive()
    stop_cloud_sync_sync_worker(worker)
    restarted = GuardStore(store.guard_home)
    worker2 = start_cloud_sync_sync_worker(restarted, poll_interval=0.2)
    try:
        assert worker2 is not None
        assert worker2.thread.is_alive()
    finally:
        stop_cloud_sync_sync_worker(worker2)
