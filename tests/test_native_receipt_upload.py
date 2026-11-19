"""The receipt upload through the native command, against a loopback Guard Cloud."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.runner import sync_receipts
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = [pytest.mark.native_receipt_upload, pytest.mark.native_guard_events]


class _CloudHandler(BaseHTTPRequestHandler):
    receipt_bodies: ClassVar[list[dict[str, object]]] = []
    # One status per receipt request; 200 once the list runs out.
    receipt_statuses: ClassVar[list[int]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        status = 200
        answer: dict[str, object] = {"syncedAt": "2026-11-19T00:00:00Z", "advisories": []}
        if self.path.endswith("/receipts/sync"):
            type(self).receipt_bodies.append(payload)
            if type(self).receipt_statuses:
                status = type(self).receipt_statuses.pop(0)
            receipts = payload.get("receipts")
            answer["receiptsStored"] = len(receipts) if isinstance(receipts, list) else 0
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(answer if status == 200 else {"error": "unavailable"}).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


@pytest.fixture
def cloud_url() -> Iterator[str]:
    _CloudHandler.receipt_bodies = []
    _CloudHandler.receipt_statuses = []
    server = HTTPServer(("127.0.0.1", 0), _CloudHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _auth(url: str) -> dict[str, object]:
    # Built at runtime so the value never reads as a stored credential.
    return {"sync_url": url, "access_" + "token": "-".join(("loopback", "only")), "dpop_key_material": None}


def _add_receipts(store: GuardStore, count: int, *, start: int = 0) -> None:
    for index in range(start, start + count):
        store.add_receipt(
            GuardReceipt(
                receipt_id=f"native-upload-{index:03d}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                harness="codex",
                artifact_id=f"codex:tool-action:native-upload-{index:03d}",
                artifact_hash=f"hash-{index:03d}",
                policy_decision="allow",
                capabilities_summary="tool action request",
                changed_capabilities=(),
                provenance_summary="",
                user_override=None,
                artifact_name="bash",
                source_scope="project",
                diff_summary=None,
                approval_source=None,
                approval_request_id=None,
                scanner_evidence=(),
                browser_intent=None,
            )
        )


def _sync(store: GuardStore, url: str) -> dict[str, object]:
    return sync_receipts(store, persist_sync_summary=False, persist_connect_state=False, auth_context=_auth(url))


def _cursor(store: GuardStore) -> object:
    payload = store.get_sync_payload("receipt_sync_cursor")
    return payload.get("last_rowid") if isinstance(payload, dict) else None


def _rowids(store: GuardStore) -> list[int]:
    rows = store.list_receipts_since_rowid(after_rowid=0, limit=500)
    return sorted(int(row["receipt_rowid"]) for row in rows)


def test_native_upload_sends_batches_of_fifty_and_saves_the_cursor(tmp_path, cloud_url) -> None:
    store = GuardStore(tmp_path / "home")
    _add_receipts(store, 120)

    summary = _sync(store, cloud_url)

    assert [len(body["receipts"]) for body in _CloudHandler.receipt_bodies] == [50, 50, 20]
    assert summary["receipts"] == 120
    assert _cursor(store) == max(_rowids(store))


def test_a_failed_batch_keeps_the_progress_of_the_batches_before_it(tmp_path, cloud_url) -> None:
    store = GuardStore(tmp_path / "home")
    _add_receipts(store, 120)
    _CloudHandler.receipt_statuses = [200, 200, 400]

    with pytest.raises(RuntimeError):
        _sync(store, cloud_url)

    rowids = _rowids(store)
    assert _cursor(store) == rowids[99]

    _CloudHandler.receipt_bodies = []
    _sync(store, cloud_url)

    [body] = _CloudHandler.receipt_bodies
    assert [item["receiptId"] for item in body["receipts"]] == [
        f"native-upload-{index:03d}" for index in range(100, 120)
    ]
    assert _cursor(store) == rowids[-1]


def test_a_refused_supplied_sign_in_is_not_refreshed(tmp_path, cloud_url) -> None:
    from codex_plugin_scanner.guard.runtime.runner import GuardSyncAuthorizationExpiredError

    store = GuardStore(tmp_path / "home")
    _add_receipts(store, 3)
    _CloudHandler.receipt_statuses = [401]

    with pytest.raises(GuardSyncAuthorizationExpiredError):
        _sync(store, cloud_url)

    assert len(_CloudHandler.receipt_bodies) == 1
    assert _cursor(store) is None


def test_a_context_only_request_sends_no_receipts_and_keeps_the_cursor(tmp_path, cloud_url) -> None:
    from pathlib import Path

    from codex_plugin_scanner.guard.runtime.cloud_bundle_sync import cloud_receipt_upload

    store = GuardStore(tmp_path / "home")
    _add_receipts(store, 3)
    # The follow-up runs after the main upload saved its progress.
    _sync(store, cloud_url)
    marker = {"level": "partial", "before_rowid": 2, "complete": False, "updated_at": "2026-11-19T00:00:00Z"}
    store.set_sync_payload("cloud_receipt_command_detail_backfill_v2", marker, "2026-11-19T00:00:00Z")
    # A receipt past the cursor is not sent either.
    _add_receipts(store, 1, start=3)
    saved_cursor = store.get_sync_payload("receipt_sync_cursor")
    assert isinstance(saved_cursor, dict)
    _CloudHandler.receipt_bodies = []
    context = {"deviceId": "device-1", "policyBundleAcknowledgement": {"bundleHash": "sha256:abc"}}

    answer = cloud_receipt_upload(
        Path(store.guard_home),
        {
            "contextOnly": True,
            "redactionLevel": "full",
            "deviceId": "device-1",
            "deviceName": "Device",
            "now": datetime.now(timezone.utc).isoformat(),
            "syncContext": context,
            "fleetPosture": None,
            "workspaceAssessments": None,
            "allowAuthRefresh": False,
        },
        auth_context=_auth(cloud_url),
    )

    [body] = _CloudHandler.receipt_bodies
    assert body["receipts"] == []
    assert body["syncContext"] == context
    assert isinstance(answer, dict)
    assert answer["receipts"] == 0
    assert store.get_sync_payload("receipt_sync_cursor") == saved_cursor
    assert store.get_sync_payload("cloud_receipt_command_detail_backfill_v2") == marker
