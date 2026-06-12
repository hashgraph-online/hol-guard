from __future__ import annotations

from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli.connect_flow import CONNECT_SYNC_AUTH_CONTEXT_KEY
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import _dashboard_token, _read_json_response, _request


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

    def _raise_runtime_error(
        _store: GuardStore,
        *,
        auth_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert auth_context is None
        raise RuntimeError("temporary receipt sync failure")

    monkeypatch.setattr(guard_commands_module, "sync_local_guard_cloud_proof", _raise_runtime_error)

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


def test_finalize_guard_connect_payload_uses_fresh_oauth_access_token_once(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    connect_url = "https://hol.org/guard/connect"
    now = "2026-06-04T12:00:00+00:00"
    sync_calls: list[dict[str, object] | None] = []

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

    def _fake_sync(
        _store: GuardStore,
        *,
        auth_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        sync_calls.append(auth_context)
        return {
            "synced_at": "2026-06-04T12:00:05+00:00",
            "runtime_session_id": "session-1",
            "runtime_session_synced_at": "2026-06-04T12:00:05+00:00",
            "runtime_sessions_visible": 1,
            "receipts_stored": 0,
        }

    monkeypatch.setattr(guard_commands_module, "sync_local_guard_cloud_proof", _fake_sync)

    payload = guard_commands_module._finalize_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload={
            "status": "connected",
            CONNECT_SYNC_AUTH_CONTEXT_KEY: {
                "access_token": "access-token-1",
                "dpop_key_material": "dpop",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
            },
        },
        now=now,
    )

    assert sync_calls == [
        {
            "access_token": "access-token-1",
            "dpop_key_material": "dpop",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        }
    ]
    assert CONNECT_SYNC_AUTH_CONTEXT_KEY not in payload


def test_daemon_finalize_guard_connect_payload_uses_fresh_oauth_access_token_once(
    tmp_path,
    monkeypatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    connect_url = "https://hol.org/guard/connect"
    now = "2026-06-04T12:00:00+00:00"
    sync_calls: list[dict[str, object] | None] = []

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

    def _fake_sync(
        _store: GuardStore,
        *,
        auth_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        sync_calls.append(auth_context)
        return {
            "synced_at": "2026-06-04T12:00:05+00:00",
            "runtime_session_id": "session-1",
            "runtime_session_synced_at": "2026-06-04T12:00:05+00:00",
            "runtime_sessions_visible": 1,
            "receipts_stored": 0,
        }

    monkeypatch.setattr(daemon_server_module, "sync_local_guard_cloud_proof", _fake_sync)

    payload = daemon_server_module._finalize_daemon_guard_connect_payload(
        store=store,
        connect_url=connect_url,
        payload={
            "status": "connected",
            CONNECT_SYNC_AUTH_CONTEXT_KEY: {
                "access_token": "access-token-1",
                "dpop_key_material": "dpop",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
            },
        },
        now=now,
    )

    assert sync_calls == [
        {
            "access_token": "access-token-1",
            "dpop_key_material": "dpop",
            "sync_url": "https://hol.org/api/guard/receipts/sync",
        }
    ]
    assert CONNECT_SYNC_AUTH_CONTEXT_KEY not in payload


def test_queue_headless_cloud_sync_respects_cross_process_sync_lock(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")

    monkeypatch.setattr(
        store,
        "get_cloud_sync_profile",
        lambda: {"sync_url": "https://hol.org/api/guard/receipts/sync"},
    )

    with store.hold_cloud_sync_lock():
        payload = daemon_server_module._queue_headless_cloud_sync(store=store)

    assert payload == {
        "status": "in_progress",
        "message": "Guard Cloud sync already running.",
    }


def test_guard_daemon_runtime_request_queues_pending_first_sync(tmp_path, monkeypatch) -> None:
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
        assert calls == []
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/runtime",
                method="GET",
                token=_dashboard_token(auth_token),
            ),
        )
        assert status == 200
        assert payload["cloud_state"] == "paired_waiting"
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

    def _raise_auth_expired(
        _store: GuardStore,
        *,
        auth_context: dict[str, object] | None = None,
    ) -> dict[str, object]:
        assert auth_context is None
        raise guard_commands_module.GuardSyncAuthorizationExpiredError("reauth required")

    monkeypatch.setattr(guard_commands_module, "sync_local_guard_cloud_proof", _raise_auth_expired)

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


def test_headless_first_sync_auth_expiry_marks_connect_state_for_repair(tmp_path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "guard-home")
    now = "2026-06-04T12:00:00+00:00"
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=now,
    )
    queued_calls: list[str] = []

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

    def _record_queue(*, store: GuardStore) -> dict[str, object]:
        queued_calls.append(str(store.guard_home))
        return {"status": "queued", "message": "Guard Cloud sync started."}

    monkeypatch.setattr(daemon_server_module, "sync_local_guard_cloud_proof", _raise_auth_expired)
    monkeypatch.setattr(daemon_server_module, "_queue_headless_cloud_sync", _record_queue)

    daemon_server_module._run_headless_cloud_sync(store=store)

    latest_state = store.get_effective_guard_connect_state(now="2026-06-04T12:05:00+00:00")
    assert latest_state is not None
    assert latest_state["status"] == "retry_required"
    assert latest_state["milestone"] == "first_sync_failed"
    assert latest_state["reason"] == "reauth required"
    assert daemon_server_module._maybe_queue_first_cloud_sync(store=store) is None
    assert queued_calls == []
