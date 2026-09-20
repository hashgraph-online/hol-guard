"""Actual review worker threads recover after a failed start without new consent.

This composes the production settings and worker refresh helpers. Both original
loops resolve synthetic persisted credentials and make real loopback HTTP
requests. The local responder is a controlled protocol peer, not an OAuth
provider. Daemon startup, native publication and installed execution are outside
this test; no startup or readiness flags are fabricated.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair, resolve_guard_oauth_client_config
from codex_plugin_scanner.guard.daemon import command_queue_worker as decisions
from codex_plugin_scanner.guard.daemon.cloud_review_settings import (
    change_cloud_review_settings,
    cloud_review_settings_status,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime import cloud_review_sync_worker as events
from codex_plugin_scanner.guard.runtime import exact_cloud_review as exact
from codex_plugin_scanner.guard.runtime.auto_update import AUTO_UPDATE_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, remote_approval, review_request
from tests.guard_oauth_token_support import oauth_binding_access_token
from tests.guard_review_signing_helpers import review_trusted_keyring_payload


class _Peer:
    def __init__(self) -> None:
        self.polled = threading.Event()
        self.acknowledged = threading.Event()
        self.errors: list[str] = []


@contextmanager
def _local_peer() -> Iterator[tuple[str, _Peer]]:
    peer = _Peer()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object, **kwargs: object) -> None:
            pass  # Do not log synthetic credential headers or request bodies.

        def do_POST(self) -> None:
            try:
                if not self.headers.get("Authorization", "").startswith("Bearer "):
                    raise ValueError("authorization_required")
                if not self.headers.get("DPoP"):
                    raise ValueError("dpop_required")
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1_000_000:
                    raise ValueError("body_length_invalid")
                payload = json.loads(self.rfile.read(length))
                if payload["protocolVersion"] != 2:
                    raise ValueError("protocol_version_invalid")
                if self.path == "/api/guard/review/v2/commands/lease":
                    result: dict[str, object] = {"protocolVersion": 2, "item": None}
                    completed = peer.polled
                elif self.path == "/api/guard/review/v2/events:batch":
                    batch = payload["events"]
                    if not isinstance(batch, list) or not batch:
                        raise ValueError("events_invalid")
                    result = {
                        "protocolVersion": 2,
                        "acknowledgedThrough": payload["lastSequence"],
                        "accepted": len(batch),
                        "rejected": 0,
                        "results": [{"eventId": event["eventId"], "status": "accepted"} for event in batch],
                    }
                    completed = peer.acknowledged
                else:
                    raise ValueError("protocol_path_invalid")
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                completed.set()
            except Exception as error:
                peer.errors.append(type(error).__name__)
                self.send_error(500, "Local protocol fixture failed")

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", peer
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    "invalid",
    [
        "authorization",
        "dpop",
        "empty-body",
        "oversized-body",
        "version",
        "events-type",
        "events-empty",
        "path",
    ],
)
def test_local_peer_refuses_invalid_protocol_without_exposing_request(invalid: str) -> None:
    canary = "synthetic-private-protocol-canary"
    headers = {"Authorization": f"Bearer {canary}", "DPoP": canary}
    payload: dict[str, object] = {"protocolVersion": 2, "private": canary}
    path = "/api/guard/review/v2/commands/lease"
    if invalid == "authorization":
        headers["Authorization"] = canary
    elif invalid == "dpop":
        del headers["DPoP"]
    elif invalid == "version":
        payload["protocolVersion"] = 1
    elif invalid in {"events-type", "events-empty"}:
        path = "/api/guard/review/v2/events:batch"
        payload["events"] = canary if invalid == "events-type" else []
    elif invalid == "path":
        path = f"/invalid/{canary}"
    body = b"" if invalid == "empty-body" else json.dumps(payload).encode()
    headers["Content-Length"] = str(1_000_001 if invalid == "oversized-body" else len(body))

    with _local_peer() as (issuer, peer):
        target = urlsplit(issuer)
        assert target.hostname is not None
        connection = HTTPConnection(target.hostname, target.port, timeout=3)
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read().decode()
            assert response.status == 500
            assert response.reason == "Local protocol fixture failed"
            assert canary not in response_body
            assert peer.errors == ["ValueError"]
            assert not peer.polled.is_set()
            assert not peer.acknowledged.is_set()
        finally:
            connection.close()


def _connected_store(tmp_path: Path, issuer: str) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    device = key.public_jwk_thumbprint
    now = datetime.now(timezone.utc).isoformat()
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id=resolve_guard_oauth_client_config(issuer).client_id,
        refresh_token="synthetic-refresh-token",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=device,
        grant_id="grant-1",
        machine_id="machine-device-fixture",
        runtime_id="hol-guard",
        device_id=device,
        workspace_id="workspace-1",
        access_token=oauth_binding_access_token(device, "grant-1", "machine-device-fixture", "workspace-1"),
        access_token_expires_at="2099-01-01T00:00:00+00:00",
        now=now,
    )
    store.set_sync_payload("guard_review_verification_keyring", review_trusted_keyring_payload(), now)
    # Keep independent update work dormant through its normal persisted cadence.
    store.set_sync_payload(AUTO_UPDATE_STATE_KEY, {"last_check_at": now}, now)
    return store


def _authority(store: GuardStore) -> dict[str, tuple[tuple[object, ...], ...]]:
    with store._connect() as connection:
        return {
            table: tuple(tuple(row) for row in connection.execute(f"select * from {table} order by rowid"))
            for table in (
                "approval_requests",
                "guard_exact_cloud_review_receipts",
                "guard_local_once_approvals",
                "policy_decisions",
            )
        }


def _wait_for(predicate: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 10
    while not predicate():
        assert time.monotonic() < deadline, "Worker did not complete its local protocol operation"
        time.sleep(0.01)


@pytest.mark.daemon_service_workers
def test_retry_restores_actual_workers_after_event_thread_start_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    monkeypatch.setenv("GUARD_CLOUD_COMMAND_QUEUE_POLL_INTERVAL_SECONDS", "0.1")
    monkeypatch.setenv("GUARD_CLOUD_COMMAND_QUEUE_LEASE_WAIT_MS", "0")
    monkeypatch.setenv("GUARD_CLOUD_REVIEW_POLL_INTERVAL", "0.1")
    with _local_peer() as (issuer, peer):
        store = _connected_store(tmp_path, issuer)
        exact.enable_exact_cloud_review(store)
        for request_id in ("restoration-history", "restoration-pending"):
            add_review_request(store, review_request(request_id))
        exact.apply_exact_cloud_review(
            store,
            remote_approval=remote_approval(store, "restoration-history", receipt_id="restoration-receipt"),
        )
        store.upsert_policy(
            PolicyDecision(harness="codex", scope="artifact", action="block", artifact_id="synthetic:retained"),
            datetime.now(timezone.utc).isoformat(),
        )
        before = _authority(store)
        capability = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
        credentials = store.get_oauth_local_credentials(allow_primary=False)
        pending_uploads = store.review_event_outbox_status(now=datetime.now(timezone.utc).isoformat())["depth"]
        assert isinstance(pending_uploads, int) and pending_uploads > 0
        decision_worker: decisions.CommandQueueWorker | None = None
        event_worker: events.CloudReviewSyncWorker | None = None

        def refresh_workers() -> dict[str, object]:
            nonlocal decision_worker, event_worker
            decision_worker, running = decisions.refresh_command_queue_worker(
                store, decision_worker, shutting_down=False
            )
            event_worker, sync_running = events.refresh_cloud_review_sync_worker(
                store, event_worker, shutting_down=False
            )
            return {"running": running, "sync_running": sync_running}

        def change(action: str) -> dict[str, object]:
            return change_cloud_review_settings(
                store,
                {
                    "action": action,
                    "confirm": f"cloud-review.{action}",
                    "source": "default",
                    "workspace_id": "workspace-1",
                },
                refresh_workers=refresh_workers,
            )

        failed_starts: list[threading.Thread] = []
        real_start = threading.Thread.start

        def fail_event_start_once(thread: threading.Thread) -> None:
            if thread.name == "hol-guard-cloud-review-sync" and not failed_starts:
                failed_starts.append(thread)
                raise RuntimeError("Synthetic transient thread start failure")
            real_start(thread)

        try:
            with monkeypatch.context() as failure:
                failure.setattr(threading.Thread, "start", fail_event_start_once)
                failed = change("enable")
            assert len(failed_starts) == 1 and not failed_starts[0].is_alive()
            assert failed["consent_enabled"] is True
            assert failed["activation_error"] == "worker_refresh_failed"
            assert failed["delivery_ready"] is False
            saved = cloud_review_settings_status(GuardStore(store.guard_home))
            assert saved["activation_error"] == "worker_refresh_failed"
            assert peer.polled.wait(timeout=10), (peer.errors, store.get_sync_payload("guard_command_queue_state"))
            assert decision_worker is not None and decision_worker.thread.is_alive()
            assert event_worker is None
            assert not peer.acknowledged.is_set()
            first_decision_thread = decision_worker.thread

            restored = change("retry_delivery")
            assert restored["consent_enabled"] is True
            assert restored["activation_error"] is None
            assert restored["delivery_ready"] is True
            assert decision_worker is not None and event_worker is not None
            assert decision_worker.thread is first_decision_thread
            assert event_worker.thread is not first_decision_thread
            assert event_worker.thread is not failed_starts[0]
            assert decision_worker.thread.is_alive() and event_worker.thread.is_alive()
            assert not decision_worker.stop_event.is_set() and not event_worker.stop_event.is_set()
            assert peer.acknowledged.wait(timeout=10), "Real event worker never acknowledged a local HTTP batch"
            _wait_for(
                lambda: store.review_event_outbox_status(now=datetime.now(timezone.utc).isoformat())["depth"] == 0
            )
            assert peer.errors == []
            assert store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == capability
            assert store.get_oauth_local_credentials(allow_primary=False) == credentials
            assert len(store.list_events(event_name="cloud_review.exact_capability_issued")) == 1
            assert _authority(store) == before
            reloaded = cloud_review_settings_status(GuardStore(store.guard_home))
            assert reloaded["activation_error"] is None and reloaded["consent_enabled"] is True
            assert reloaded["delivery_ready"] is None  # Reload alone cannot assert live worker observations.
        finally:
            try:
                if decision_worker is not None:
                    decisions.stop_command_queue_worker(decision_worker)
                    assert not decision_worker.thread.is_alive()
            finally:
                if event_worker is not None:
                    events.stop_cloud_sync_sync_worker(event_worker)
                    assert not event_worker.thread.is_alive()
