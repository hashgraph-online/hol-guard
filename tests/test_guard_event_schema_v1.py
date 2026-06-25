from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

from codex_plugin_scanner.guard.edge_events import (
    build_access_graph_snapshot_event,
    build_agent_handshake_event,
    build_approval_event,
    build_notification_delivery_event,
    build_policy_event,
    build_receipt_event,
    build_runtime_session_event,
)
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.runner import sync_guard_events, sync_receipts
from codex_plugin_scanner.guard.schemas.guard_event_v1 import GuardEventV1
from codex_plugin_scanner.guard.store import GuardStore


def _seed_guard_cloud(store, *, workspace_id=None, sync_url=None, token="demo-token", now="2026-05-19T00:00:00Z"):
    """Seed OAuth credentials (replaces legacy set_sync_credentials scaffolding).

    Also installs a test-only resolver override so sync-path exercises stay hermetic
    (no OAuth token refresh against the network). Tests that need real sync against a
    local server pass sync_url=<url>.
    """
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token=token,
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id=workspace_id,
        now=now,
    )
    effective_sync_url = sync_url if sync_url is not None else "https://hol.org/api/guard/receipts/sync"
    guard_runner_module._test_sync_auth_context_override = {
        "sync_url": effective_sync_url,
        "access_token": token,
        "dpop_key_material": None,
    }


def _receipt() -> GuardReceipt:
    return GuardReceipt(
        receipt_id="receipt-1",
        timestamp="2026-04-24T00:00:00+00:00",
        harness="codex",
        artifact_id="artifact-1",
        artifact_hash="sha256:abc",
        policy_decision="review",
        capabilities_summary="requests network access",
        changed_capabilities=("network",),
        provenance_summary="local harness",
        artifact_name="Sensitive Tool",
        source_scope="workspace",
    )


class _EventIngestHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[dict[str, object]]] = []
    event_status: ClassVar[int] = 200

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b"{}"
        payload = json.loads(body.decode())
        type(self).requests.append(
            {
                "path": self.path,
                "payload": payload,
                "authorization": self.headers.get("Authorization"),
            }
        )
        status_code = type(self).event_status if self.path.endswith("/api/v1/guard/events") else 200
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if status_code == 404:
            self.wfile.write(json.dumps({"error": "not found"}).encode())
            return
        if self.path.endswith("/receipts/sync"):
            response = {"syncedAt": "2026-04-24T00:00:00+00:00", "receiptsStored": len(payload.get("receipts", []))}
        else:
            response = {
                "accepted": 1,
                "rejected": 0,
                "statuses": [
                    {
                        "eventId": payload["events"][0]["eventId"],
                        "status": "accepted",
                    }
                ],
            }
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, fmt: str, *args) -> None:
        return


class _RejectedEventHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b"{}"
        payload = json.loads(body.decode())
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "accepted": 0,
                    "rejected": 1,
                    "statuses": [
                        {
                            "eventId": payload["events"][0]["eventId"],
                            "status": "rejected",
                        }
                    ],
                }
            ).encode()
        )

    def log_message(self, fmt: str, *args) -> None:
        return


def test_receipt_event_uses_white_rabbit_contract() -> None:
    event = build_receipt_event(_receipt(), workspace_id="workspace-1", device_id="device-1")
    payload = event.to_dict()

    assert payload["eventType"] == "receipt.created"
    assert payload["workspaceId"] == "workspace-1"
    assert payload["idempotencyKey"] == "receipt.created:receipt-1"
    assert payload["payload"]["receiptId"] == "receipt-1"
    assert GuardEventV1.from_dict(payload).event_type == "receipt.created"


def test_receipt_persistence_dual_writes_pending_cloud_event(tmp_path) -> None:
    store = GuardStore(tmp_path)

    store.add_receipt(_receipt())

    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    assert pending[0]["event_type"] == "receipt.created"
    assert pending[0]["payload"]["payload"]["artifactId"] == "artifact-1"


def test_approval_and_policy_events_are_contract_valid() -> None:
    approval_event = build_approval_event(
        request_id="approval-1",
        event_type="approval.created",
        occurred_at="2026-04-24T00:00:00+00:00",
        payload={"artifactId": "artifact-1"},
        workspace_id="workspace-1",
    )
    policy_event = build_policy_event(
        policy_key="policy-1",
        occurred_at="2026-04-24T00:00:00+00:00",
        payload={"policyId": "policy-1"},
        workspace_id="workspace-1",
    )

    assert GuardEventV1.from_dict(approval_event.to_dict()).event_type == "approval.created"
    assert GuardEventV1.from_dict(policy_event.to_dict()).event_type == "policy.changed"


def test_new_guard_cloud_event_types_are_contract_valid() -> None:
    runtime_session = build_runtime_session_event(
        session_id="session-1",
        occurred_at="2026-04-24T00:00:00+00:00",
        payload={"status": "active"},
        workspace_id="workspace-1",
        device_id="device-1",
    )
    access_graph = build_access_graph_snapshot_event(
        snapshot_id="snapshot-1",
        occurred_at="2026-04-24T00:00:01+00:00",
        payload={
            "snapshotId": "snapshot-1",
            "generatedAt": "2026-04-24T00:00:01+00:00",
            "entities": [
                {
                    "entityType": "device",
                    "entityId": "device-1",
                    "displayName": "Local machine",
                    "fingerprint": "device:device-1",
                    "metadata": {},
                }
            ],
            "edges": [],
        },
        workspace_id="workspace-1",
        device_id="device-1",
    )
    handshake = build_agent_handshake_event(
        handshake_id="handshake-1",
        occurred_at="2026-04-24T00:00:02+00:00",
        payload={"agentId": "agent-1", "capabilities": ["chat"]},
        workspace_id="workspace-1",
        device_id="device-1",
    )
    notification = build_notification_delivery_event(
        delivery_id="delivery-1",
        occurred_at="2026-04-24T00:00:03+00:00",
        payload={"channel": "slack", "status": "delivered"},
        workspace_id="workspace-1",
        device_id="device-1",
    )

    events = [runtime_session, access_graph, handshake, notification]

    assert {event.event_type for event in events} == {
        "runtime.session",
        "access_graph.snapshot",
        "agent.handshake",
        "notification.delivery",
    }
    assert all(GuardEventV1.from_dict(event.to_dict()).workspace_id == "workspace-1" for event in events)
    assert all(event.to_dict()["schemaVersion"] == "guard.event.v1" for event in events)


def test_sync_guard_events_posts_to_v1_ingest(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(_receipt())
    _EventIngestHandler.requests = []
    server = HTTPServer(("127.0.0.1", 0), _EventIngestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _seed_guard_cloud(
            store,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="token-1",
        )

        result = sync_guard_events(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result["accepted"] == 1
    assert _EventIngestHandler.requests[0]["path"] == "/api/v1/guard/events"
    assert _EventIngestHandler.requests[0]["authorization"] == "Bearer token-1"
    assert _EventIngestHandler.requests[0]["payload"]["events"][0]["eventType"] == "receipt.created"
    assert store.list_guard_events_v1(uploaded=False, limit=10) == []


def test_sync_guard_events_normalizes_registry_base_url(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(_receipt())
    _EventIngestHandler.requests = []
    server = HTTPServer(("127.0.0.1", 0), _EventIngestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _seed_guard_cloud(store, sync_url=f"http://127.0.0.1:{server.server_port}/registry/api/v1", token="token-1")

        result = sync_guard_events(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result["accepted"] == 1
    assert _EventIngestHandler.requests[0]["path"] == "/api/v1/guard/events"


def test_sync_receipts_uploads_pending_guard_events(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(_receipt())
    _EventIngestHandler.requests = []
    server = HTTPServer(("127.0.0.1", 0), _EventIngestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _seed_guard_cloud(
            store,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="token-1",
        )

        result = sync_receipts(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result["guard_events_v1"]["accepted"] == 1
    assert [request["path"] for request in _EventIngestHandler.requests] == [
        "/api/guard/receipts/sync",
        "/api/v1/guard/events",
    ]
    assert store.list_guard_events_v1(uploaded=False, limit=10) == []


def test_sync_receipts_keeps_receipt_success_when_v1_events_endpoint_is_missing(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(_receipt())
    _EventIngestHandler.requests = []
    _EventIngestHandler.event_status = 404
    server = HTTPServer(("127.0.0.1", 0), _EventIngestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _seed_guard_cloud(
            store,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="token-1",
        )

        result = sync_receipts(store)
    finally:
        _EventIngestHandler.event_status = 200
        server.shutdown()
        thread.join(timeout=5)

    assert result["receipts"] == 1
    assert result["guard_events_v1"]["sync_skipped"] is True
    # Events must NOT be marked as skipped/dropped on 404 — they remain pending for retry
    assert result["guard_events_v1"]["skipped"] == 0
    pending = store.list_guard_events_v1(uploaded=False, limit=10)
    assert len(pending) == 1  # The receipt.created event is still pending


def test_sync_guard_events_marks_rejected_events_processed(tmp_path) -> None:
    store = GuardStore(tmp_path)
    store.add_receipt(_receipt())
    server = HTTPServer(("127.0.0.1", 0), _RejectedEventHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _seed_guard_cloud(
            store,
            sync_url=f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            token="token-1",
        )

        result = sync_guard_events(store)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result["accepted"] == 1
    assert store.list_guard_events_v1(uploaded=False, limit=10) == []
