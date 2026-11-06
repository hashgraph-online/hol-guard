from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_executors, command_queue, command_queue_results
from tests.test_guard_command_queue import (  # noqa: F401 - autouse fixtures apply here too
    FakeStore,
    _context,
    _default_store_platform,
    _isolate_legacy_queue_mechanics,
)

_LEASED_JOB = {"id": "job-3", "leaseId": "lease-3", "operation": "guard.packageShims.status"}
_PENDING_STATE = {
    "state": "result_pending",
    "pending_result": {
        "job": {"id": "job-3", "leaseId": "lease-3"},
        "payload": {"leaseId": "lease-3", "idempotencyKey": "job-3:lease-3:failed", "status": "failed"},
    },
}


def _http_error(path: str, status_code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(f"https://hol.test/api/guard/commands{path}", status_code, "Refused", {}, None)


def _install_transport(monkeypatch, responses: dict[str, list[int]]) -> list[str]:
    """Answer each path with its next queued HTTP status (200 once the queue is empty)."""

    calls: list[str] = []
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda store, force_refresh=False: {
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "access_token": "t",
        },
    )
    monkeypatch.setattr(command_queue_results, "audit_command_decision", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(command_executors, "package_shim_status", lambda context: {"active_managers": []})

    def fake_json_request(auth_context, *, method: str, path: str, payload: dict[str, object]) -> dict[str, object]:
        del auth_context, method, payload
        calls.append(path)
        queued = responses.get(path) or []
        if queued:
            status_code = queued.pop(0)
            if status_code != 200:
                raise _http_error(path, status_code)
        if path == "/lease":
            return {"item": dict(_LEASED_JOB)} if responses.get("/lease-item") is None else {"item": None}
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_json_request", fake_json_request)
    return calls


@pytest.mark.parametrize("status_code", [400, 404, 409, 410, 422])
def test_fresh_result_refused_by_cloud_is_dropped(tmp_path: Path, monkeypatch, status_code: int) -> None:
    """A refused result cannot succeed on resend, so it must not stall the queue."""

    store = FakeStore(tmp_path / "guard-home")
    _install_transport(monkeypatch, {"/job-3/result": [status_code]})

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert status["pending_result"] is None
    assert status["active_job"] is None


def test_fresh_result_refused_after_oauth_refresh_is_dropped(tmp_path: Path, monkeypatch) -> None:
    store = FakeStore(tmp_path / "guard-home")
    calls = _install_transport(monkeypatch, {"/job-3/result": [401, 409]})

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert calls.count("/job-3/result") == 2
    assert status["state"] == "idle"
    assert status["pending_result"] is None


def test_refused_heartbeat_keeps_the_result_pending(tmp_path: Path, monkeypatch) -> None:
    """Cloud refusing a heartbeat says nothing about the result, so it is kept."""

    store = FakeStore(tmp_path / "guard-home")
    calls = _install_transport(monkeypatch, {"/job-3/heartbeat": [200, 409]})

    with pytest.raises(urllib.error.HTTPError):
        command_queue.poll_command_queue_once(store, _context(tmp_path))

    state = store.get_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY)
    assert isinstance(state, dict)
    assert "/job-3/result" not in calls
    assert state["state"] == "result_pending"
    assert state["pending_result"]["job"]["id"] == "job-3"


@pytest.mark.parametrize("statuses", [[409], [401, 409]])
def test_refused_pending_result_is_dropped_and_leasing_continues(
    tmp_path: Path, monkeypatch, statuses: list[int]
) -> None:
    store = FakeStore(tmp_path / "guard-home")
    store.set_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY, dict(_PENDING_STATE), "2026-06-13T00:00:00+00:00")
    calls = _install_transport(monkeypatch, {"/job-3/result": list(statuses), "/lease-item": []})

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert calls == ["/job-3/result"] * len(statuses) + ["/lease"]
    assert status["state"] == "idle"
    assert status["pending_result"] is None
