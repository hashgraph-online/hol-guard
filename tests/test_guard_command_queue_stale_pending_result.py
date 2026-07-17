from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_queue
from tests.test_guard_command_queue import FakeStore, _context


def test_poll_once_drops_stale_pending_result_before_leasing(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    # This transport-state regression intentionally exercises an enabled queue;
    # signed capability behavior is covered in test_guard_command_capability.py.
    monkeypatch.setattr(command_queue, "command_queue_enabled", lambda _store: True)
    monkeypatch.setattr(
        command_queue,
        "command_capability_operations",
        lambda _store: ("guard.packageShims.status",),
    )
    stale_job = {
        "id": "job-3",
        "leaseId": "lease-3",
        "leaseExpiresAt": "2000-01-01T00:05:00+00:00",
        "expiresAt": "2000-01-01T00:15:00+00:00",
    }
    store.set_sync_payload(
        command_queue.COMMAND_QUEUE_STATE_KEY,
        {
            "state": "result_pending",
            "active_job": dict(stale_job),
            "pending_result": {
                "job": dict(stale_job),
                "payload": {
                    "leaseId": "lease-3",
                    "idempotencyKey": "job-3:lease-3:succeeded",
                    "status": "succeeded",
                    "result": {"data": {}},
                },
            },
        },
        "2000-01-01T00:00:00+00:00",
    )
    calls: list[str] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_guard_sync_auth_context",
        lambda current_store: {"sync_url": "https://hol.test/api/guard/receipts/sync", "access_token": "token"},
    )

    def fake_json_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        del auth_context, method, payload
        calls.append(path)
        assert path == "/lease"
        return {"item": None}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert calls == ["/lease"]
    assert status["active_job"] is None
    assert status["pending_result"] is None
