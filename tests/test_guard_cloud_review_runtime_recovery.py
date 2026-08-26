# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import threading
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_sync, cloud_review_sync_worker, command_queue
from codex_plugin_scanner.guard.runtime.command_capability import issue_command_capability
from codex_plugin_scanner.guard.runtime.command_executors import SUPPORTED_COMMAND_OPERATIONS
from codex_plugin_scanner.guard.runtime.exact_cloud_review import authorize_exact_cloud_review_job
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cloud_review_hardening_support import exact_job_store, harness_context, sync_auth


def _unauthorized(path: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        f"https://guard.example{path}",
        401,
        "Unauthorized",
        Message(),
        io.BytesIO(),
    )


def test_event_upload_refreshes_oauth_once_without_requeueing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, _job = exact_job_store(tmp_path, request_id="oauth-event-upload")
    auth = sync_auth(store, access_token="expired-token")
    uploads: list[str] = []
    refreshes: list[bool] = []

    def upload(auth_context: dict[str, object], *, events: list[dict[str, object]]) -> dict[str, object]:
        del events
        token = str(auth_context["access_token"])
        uploads.append(token)
        if token == "expired-token":
            raise _unauthorized("/api/guard/review/v2/events:batch")
        return {
            "accepted": 1,
            "rejected": 0,
            "perEventResults": [{"index": 0, "accepted": True, "code": None, "error": None}],
        }

    def refresh(_store: GuardStore, *, force_refresh: bool = False) -> dict[str, object]:
        refreshes.append(force_refresh)
        return sync_auth(store, access_token="refreshed-token")

    monkeypatch.setattr(cloud_review_sync, "post_review_events", upload)
    monkeypatch.setattr(cloud_review_sync, "_resolve_cloud_review_sync_auth_context", refresh)

    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert result["synced"] == 1
    outbox = result["outbox"]
    assert isinstance(outbox, dict) and outbox["depth"] == 0
    assert uploads == ["expired-token", "refreshed-token"]
    assert refreshes == [True]


def test_command_lease_refreshes_oauth_once_and_uses_new_token_for_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = exact_job_store(tmp_path, request_id="oauth-command-lease")
    issue_command_capability(
        store, operations=("guard.packageShims.status",), supported_operations=SUPPORTED_COMMAND_OPERATIONS
    )
    calls: list[tuple[str, str]] = []
    refreshes: list[bool] = []

    def request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        del method, payload
        token = str(auth_context["access_token"])
        calls.append((token, path))
        if path == "/lease" and token == "expired-token":
            raise _unauthorized("/api/guard/review/v2/commands/lease")
        if path == "/lease":
            return {"item": job, "protocolVersion": 2}
        return {"ok": True}

    def resolve(_store: GuardStore, *, force_refresh: bool = False) -> dict[str, object]:
        refreshes.append(force_refresh)
        return {
            "access_token": "refreshed-token" if any(refreshes) else "expired-token",
            "sync_url": "https://guard.example/api/guard/receipts/sync",
        }

    monkeypatch.setattr(command_queue, "_exact_json_request", request)
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda *_args, **_kwargs: pytest.fail("an exact-route 401 must refresh before generic fallback"),
    )
    monkeypatch.setattr(command_queue, "_resolve_command_queue_auth_context", resolve)

    identity = authorize_exact_cloud_review_job(store, job).identity
    status = command_queue.poll_command_queue_once(store, harness_context(tmp_path))

    assert status["state"] == "idle"
    assert refreshes == [False, True, False]
    assert calls[0:2] == [("expired-token", "/lease"), ("refreshed-token", "/lease")]
    assert all(token == "refreshed-token" for token, _path in calls[1:])
    assert all(token not in repr(identity) for token in ("expired-token", "refreshed-token"))
    resolved = store.get_approval_request("oauth-command-lease")
    assert resolved is not None and resolved["status"] == "resolved"


def test_restart_after_lease_before_application_releases_exact_request_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = exact_job_store(tmp_path, request_id="crash-after-lease")
    first_ack = True

    def crash_after_lease(
        _auth: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        nonlocal first_ack
        del method, payload
        if path == "/lease":
            return {"item": job, "protocolVersion": 2}
        if first_ack:
            first_ack = False
            raise SystemExit("simulated daemon crash after lease")
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", crash_after_lease)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {"access_token": "token", "sync_url": "https://guard.example"},
    )

    with pytest.raises(SystemExit, match="after lease"):
        command_queue.poll_command_queue_once(store, harness_context(tmp_path))
    leased = command_queue.command_queue_status(store)
    assert leased["state"] == "leased"
    pending_request = store.get_approval_request("crash-after-lease")
    assert pending_request is not None and pending_request["status"] == "pending"

    restarted = GuardStore(store.guard_home)
    status = command_queue.poll_command_queue_once(restarted, harness_context(tmp_path))

    assert status["state"] == "idle"
    resolved = restarted.get_approval_request("crash-after-lease")
    assert resolved is not None and resolved["status"] == "resolved"
    assert len(restarted.list_events(event_name="cloud_review.exact_used")) == 1


def test_restart_after_application_before_result_ack_retries_without_reapplying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = exact_job_store(tmp_path, request_id="crash-before-result-ack")
    post_attempts = 0

    def disconnect_before_result_ack(
        _auth: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        nonlocal post_attempts
        del method, payload
        if path == "/lease":
            return {"item": job, "protocolVersion": 2}
        if path.endswith("/result"):
            post_attempts += 1
            if post_attempts == 1:
                raise urllib.error.URLError("simulated disconnect before result acknowledgement")
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", disconnect_before_result_ack)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {"access_token": "token", "sync_url": "https://guard.example"},
    )

    with pytest.raises(urllib.error.URLError, match="before result acknowledgement"):
        command_queue.poll_command_queue_once(store, harness_context(tmp_path))
    pending = command_queue.command_queue_status(store)
    assert pending["state"] == "result_pending"
    resolved_request = store.get_approval_request("crash-before-result-ack")
    assert resolved_request is not None and resolved_request["status"] == "resolved"
    assert len(store.list_events(event_name="cloud_review.exact_used")) == 1

    restarted = GuardStore(store.guard_home)
    status = command_queue.poll_command_queue_once(restarted, harness_context(tmp_path))

    assert status["state"] == "idle"
    assert post_attempts == 2
    assert len(restarted.list_events(event_name="cloud_review.exact_used")) == 1


@pytest.mark.soak
def test_cloud_review_worker_survives_ten_thousand_recurring_disconnects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "soak")
    iterations = 10_000
    attempts = 0

    stop_event = threading.Event()

    def sync(_store: GuardStore, _auth: dict[str, object]) -> dict[str, object]:
        nonlocal attempts
        attempts += 1
        if attempts >= iterations:
            stop_event.set()
        if attempts % 3:
            raise urllib.error.URLError("recurring disconnect")
        return {"synced": 1}

    monkeypatch.setattr(cloud_review_sync, "_resolve_cloud_review_sync_auth_context", lambda _store: {})
    monkeypatch.setattr(cloud_review_sync, "sync_cloud_review_events_once", sync)
    monkeypatch.setattr(cloud_review_sync._LOGGER, "exception", lambda *_args, **_kwargs: None)

    cloud_review_sync_worker._cloud_sync_sync_loop(
        store,
        stop_event,
        cloud_review_sync_worker.review_event_wake_signal(store.path),
        poll_interval=0.001,
        error_backoff=0.001,
    )

    assert attempts == iterations
