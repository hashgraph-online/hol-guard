from __future__ import annotations

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def test_finalize_guard_connect_payload_keeps_first_sync_pending_on_transient_sync_error(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    connect_url = "https://hol.org/guard/connect"
    now = "2026-06-04T12:00:00+00:00"

    monkeypatch.setattr(
        store,
        "get_cloud_sync_profile",
        lambda: {"sync_url": "https://hol.org/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(
        store,
        "get_oauth_local_credential_health",
        lambda: {"configured": True, "state": "healthy"},
    )

    def _raise_runtime_error(_store: GuardStore) -> dict[str, object]:
        raise RuntimeError("temporary receipt sync failure")

    monkeypatch.setattr(guard_commands_module, "sync_receipts", _raise_runtime_error)

    payload = guard_commands_module._finalize_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload={"status": "connected"},
        now=now,
    )

    assert payload["status"] == "connected"
    assert payload["milestone"] == "first_sync_pending"
    assert payload["sync_succeeded"] is False
    assert payload["sync_error"] == "temporary receipt sync failure"
    assert "retry automatically" in str(payload["repair_message"])

    latest_state = payload["latest_connect_state"]
    assert isinstance(latest_state, dict)
    assert latest_state["status"] == "connected"
    assert latest_state["milestone"] == "first_sync_pending"


def test_guard_daemon_start_queues_pending_first_sync(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-06-04T12:00:00+00:00"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    calls: list[str] = []

    monkeypatch.setattr(
        store,
        "get_cloud_sync_profile",
        lambda: {"sync_url": "https://hol.org/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(
        store,
        "get_oauth_local_credential_health",
        lambda: {"configured": True, "state": "healthy"},
    )

    def _record_queue(*, store: GuardStore) -> dict[str, object]:
        calls.append(str(store.guard_home))
        return {"status": "queued", "message": "Guard Cloud sync started."}

    monkeypatch.setattr(daemon_server_module, "_queue_headless_cloud_sync", _record_queue)

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    try:
        daemon.start()
        assert calls == [str(store.guard_home)]
    finally:
        daemon.stop()


def test_finalize_guard_connect_payload_keeps_reauth_failures_in_retry_required_state(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    connect_url = "https://hol.org/guard/connect"
    now = "2026-06-04T12:00:00+00:00"

    monkeypatch.setattr(
        store,
        "get_cloud_sync_profile",
        lambda: {"sync_url": "https://hol.org/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(
        store,
        "get_oauth_local_credential_health",
        lambda: {"configured": True, "state": "healthy"},
    )

    def _raise_auth_expired(_store: GuardStore) -> dict[str, object]:
        raise guard_commands_module.GuardSyncAuthorizationExpiredError("reauth required")

    monkeypatch.setattr(guard_commands_module, "sync_receipts", _raise_auth_expired)

    payload = guard_commands_module._finalize_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload={"status": "connected"},
        now=now,
    )

    assert payload["status"] == "retry_required"
    assert payload["milestone"] == "first_sync_failed"
    assert payload["sync_succeeded"] is False
    assert payload["sync_error"] == "reauth required"
    assert payload["repair_message"] == "Run hol-guard connect again to refresh Guard Cloud authorization."
