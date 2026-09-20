"""Independent workers preserve authority while either transport is delayed."""

from __future__ import annotations

import io
import json
import socket
import tempfile
import threading
import time
import urllib.error
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard import aibom_cli, store_connection_schema
from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.runtime import runner
from tests.support.optional_uploads import (
    OPTIONAL_UPLOAD_WORKSPACE,
    confirm_legacy_optional_uploads,
    enable_optional_upload_settings,
)
from tests.test_aibom_operation_authority import _selected
from tests.test_guard_receipt_redaction_cursor import _store_blocked_command_receipt
from tests.test_inventory_consumer_authority import _fixture
from tests.test_oauth_connection_authority import NOW


class Response(io.BytesIO):
    status = 200

    def getcode(self):
        return 200

    def __init__(self, payload):
        self.headers: dict[str, str] = {}
        super().__init__(json.dumps(payload).encode())


def denied(*args, **kwargs):
    raise AssertionError("Unexpected raw network")


def _prepare_scheduling_uploads(store, inputs, monkeypatch: pytest.MonkeyPatch) -> None:
    inputs["workspace_id"] = OPTIONAL_UPLOAD_WORKSPACE
    store.set_oauth_local_credentials(**inputs)
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    enable_optional_upload_settings(store)
    confirm_legacy_optional_uploads(store)


def _trial(boundary: str, deny_receipts: bool, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="inventory-scheduling-") as temp:
        store, inputs, context = _fixture(Path(temp))
        _prepare_scheduling_uploads(store, inputs, monkeypatch)
        store.set_sync_payload(
            "aibom_inventory_context", {**_selected(context), "workspace_id": OPTIONAL_UPLOAD_WORKSPACE}, NOW
        )
        _store_blocked_command_receipt(store, "synthetic-receipt")
        daemon = cast(Any, object.__new__(server.GuardDaemonServer))
        daemon._server = SimpleNamespace(store=store)
        daemon._shutdown_started = threading.Event()
        daemon._aibom_refresh_interval_seconds = 60
        daemon._aibom_refresh_backoff_seconds = 0.05
        daemon._aibom_home_dir = None
        daemon._aibom_workspace_dir = None
        daemon._aibom_context_source = None
        entered = threading.Event()
        release = threading.Event()
        collected = threading.Event()
        done = threading.Event()
        routes = []
        receipt_denials: list[int] = []
        errors = []
        collection_calls = []
        collect = aibom_cli.collect_aibom_snapshots
        cloud_wait = threading.Event()
        original_acquire: Callable[[Any], None] = vars(store_connection_schema)["_acquire_advisory_file_lock"]

        def acquire(handle: Any) -> None:
            try:
                original_acquire(handle)
            except BlockingIOError:
                if (
                    threading.current_thread().name == "inventory-worker"
                    and Path(handle.name).name == "cloud-sync.lock"
                ):
                    cloud_wait.set()
                raise

        def collection(*args, **kwargs):
            collection_calls.append(True)
            result = collect(*args, **kwargs)
            collected.set()
            return result

        def transport(request, *, timeout):
            url = request.full_url
            route = (
                "runtime"
                if "/runtime/sessions/" in url
                else "receipts"
                if "/receipts/" in url
                else "events"
                if url.rstrip("/").endswith("/events")
                else "other"
            )
            body = json.loads(request.data or b"{}")
            routes.append({"worker": threading.current_thread().name, "route": route, "timeout": timeout})
            if threading.current_thread().name == "receipt-worker" and route == boundary:
                entered.set()
                assert release.wait(10), "controlled response pause not released"
            if route == "receipts" and deny_receipts:
                receipt_denials.append(403)
                raise urllib.error.HTTPError(url, 403, "Controlled", Message(), io.BytesIO(b"{}"))
            return Response(
                {
                    "syncedAt": NOW,
                    "receiptsStored": len(body.get("receipts", [])),
                    "runtimeSessionsVisible": 1,
                    "accepted": len(body.get("events", [])),
                    "rejected": 0,
                    "statuses": [],
                }
            )

        def receipts():
            try:
                runner.sync_local_guard_cloud_proof(
                    store, home_dir=context.home_dir, workspace_dir=context.workspace_dir
                )
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                done.set()

        rt = threading.Thread(target=receipts, name="receipt-worker", daemon=True)
        it = threading.Thread(target=daemon._refresh_aibom_inventory_loop, name="inventory-worker", daemon=True)
        before = runner._receipt_sync_cursor_rowid(store)
        with (
            patch.object(runner, "managed_urlopen", transport),
            patch.object(store_connection_schema, "_acquire_advisory_file_lock", acquire),
            patch.object(runner, "_test_sync_auth_context_override", None),
            patch.object(runner, "_guard_runtime_was_upgraded", lambda: False),
            patch.object(runner, "_safe_private_ip", lambda: None),
            patch.object(aibom_cli, "collect_aibom_snapshots", collection),
            patch.object(socket, "create_connection", denied),
            patch.object(socket.socket, "connect", denied),
        ):
            try:
                rt.start()
                assert entered.wait(5), ("receipt boundary missing", errors, routes)
                it.start()
                deadline = time.monotonic() + 5
                blocked = False
                terminal = None
                while time.monotonic() < deadline:
                    terminal = store.get_sync_payload("aibom_inventory_daemon")
                    if isinstance(terminal, dict) and terminal.get("status") == "synced":
                        break
                    blocked = cloud_wait.is_set()
                    if blocked:
                        break
                    time.sleep(0.005)
                completed = isinstance(terminal, dict) and terminal.get("status") == "synced"
                assert store.cloud_sync_in_progress()
                assert runner._receipt_sync_cursor_rowid(store) == before
                observation: dict[str, Any] = {
                    "controlledBoundary": boundary,
                    "receiptDenied": deny_receipts,
                    "actualAdvisoryWaitObserved": blocked,
                    "actualCollectionBeforeRelease": collected.is_set(),
                    "terminalBeforeRelease": completed,
                    "receiptCursorUnchangedDuringPause": True,
                    "receiptWorkerStillPaused": not done.is_set(),
                }
                release.set()
                assert done.wait(5), ("receipt did not finish", errors)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    terminal = store.get_sync_payload("aibom_inventory_daemon")
                    if isinstance(terminal, dict) and terminal.get("status") == "synced":
                        break
                    time.sleep(0.01)
                assert isinstance(terminal, dict) and terminal.get("status") == "synced", (terminal, errors, routes)
                after = runner._receipt_sync_cursor_rowid(store)
                if deny_receipts:
                    assert errors == ["RuntimeError"] and after == before, (errors, before, after)
                else:
                    assert errors == [] and isinstance(after, int) and after > (before or 0), (errors, before, after)
                assert receipt_denials == ([403] if deny_receipts else [])
                assert any(route["worker"] == "receipt-worker" and route["route"] == "receipts" for route in routes)
                assert len(collection_calls) == 1
                assert sum(r["worker"] == "inventory-worker" and r["route"] == "events" for r in routes) == 1
                observation.update(
                    {
                        "terminalAfterRelease": terminal["status"],
                        "actualCollectionCalls": len(collection_calls),
                        "inventoryUploadCalls": 1,
                        "receiptErrorTypes": errors,
                        "receiptCursorCorrectAfterRelease": True,
                        "routes": routes,
                    }
                )
                return observation
            finally:
                release.set()
                daemon._shutdown_started.set()
                if rt.ident is not None:
                    rt.join(6)
                if it.ident is not None:
                    it.join(6)
                assert not rt.is_alive() and not it.is_alive(), "workers did not terminate"


@pytest.mark.parametrize("boundary", ["runtime", "receipts"])
@pytest.mark.parametrize("deny_receipts", [False, True])
def test_inventory_finishes_while_actual_cloud_response_is_pending(
    boundary: str, deny_receipts: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = _trial(boundary, deny_receipts, monkeypatch)
    assert observed["actualCollectionBeforeRelease"] is True
    assert observed["terminalBeforeRelease"] is True
    assert observed["actualAdvisoryWaitObserved"] is False
    assert observed["receiptWorkerStillPaused"] is True
    assert observed["receiptCursorUnchangedDuringPause"] is True
    assert observed["receiptCursorCorrectAfterRelease"] is True
    assert observed["actualCollectionCalls"] == 1
    assert observed["inventoryUploadCalls"] == 1


@pytest.mark.parametrize("mutation", ["unchanged", "refresh", "token-replacement", "workspace", "source-aba"])
@pytest.mark.parametrize("deny_receipts", [False, True])
def test_receipts_progress_while_inventory_waits_and_stale_inventory_cannot_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, deny_receipts: bool
) -> None:
    from tests.test_aibom_sync_admission import _finish, _start
    from tests.test_inventory_daemon_consumers import _daemon

    store, inputs, context = _fixture(tmp_path)
    _prepare_scheduling_uploads(store, inputs, monkeypatch)
    store.set_sync_payload(
        "aibom_inventory_context", {**_selected(context), "workspace_id": OPTIONAL_UPLOAD_WORKSPACE}, NOW
    )
    _store_blocked_command_receipt(store, "synthetic-receipt")
    sentinel = {"status": "prior"}
    store.set_sync_payload("aibom_inventory_daemon", sentinel, NOW)
    daemon = _daemon(store)
    entered = threading.Event()
    release = threading.Event()
    requests: list[str] = []
    receipt_denials: list[int] = []
    before = runner._receipt_sync_cursor_rowid(store)

    def transport(request: Any, *, timeout: int):
        body = json.loads(request.data or b"{}")
        route = "receipts" if "/receipts/" in request.full_url else "other"
        if threading.current_thread().name == "inventory-worker":
            assert request.full_url.rstrip("/").endswith("/events")
            assert timeout == 90
            requests.append("inventory")
            entered.set()
            assert release.wait(10)
        else:
            requests.append(route)
        if route == "receipts" and deny_receipts:
            receipt_denials.append(403)
            raise urllib.error.HTTPError(request.full_url, 403, "Controlled", Message(), io.BytesIO(b"{}"))
        return Response(
            {
                "syncedAt": NOW,
                "receiptsStored": len(body.get("receipts", [])),
                "runtimeSessionsVisible": 1,
                "accepted": len(body.get("events", [])),
                "rejected": 0,
                "statuses": [],
            }
        )

    def inventory() -> dict[str, object]:
        daemon._refresh_aibom_inventory_loop()
        return {"done": True}

    def receipts() -> dict[str, object]:
        try:
            result = runner.sync_local_guard_cloud_proof(
                store, home_dir=context.home_dir, workspace_dir=context.workspace_dir
            )
            return {"ok": True, "result": result}
        except RuntimeError:
            if not deny_receipts:
                raise
            return {"denied": True}

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: False)
    monkeypatch.setattr(runner, "_safe_private_ip", lambda: None)
    monkeypatch.setattr(server, "_now", lambda: NOW)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)
    first = _start(inventory, "inventory-worker")
    second = None
    try:
        assert entered.wait(5)
        second = _start(receipts, "receipt-worker")
        receipt_result = _finish(second)
        assert receipt_result.get("denied" if deny_receipts else "ok") is True
        assert receipt_denials == ([403] if deny_receipts else [])
        assert "receipts" in requests
        assert not release.is_set()
        assert first[0].is_alive()
        assert store.get_sync_payload("aibom_inventory_daemon") == sentinel
        after = runner._receipt_sync_cursor_rowid(store)
        if deny_receipts:
            assert after == before
        else:
            assert isinstance(after, int) and after > (before or 0)
        if mutation == "refresh":
            current = store.capture_oauth_connection()
            assert current is not None
            refreshed: dict[str, Any] = {**inputs, "access_token": "rotated-synthetic"}
            store.set_oauth_local_credentials(**refreshed, expected_connection=current)
        elif mutation == "token-replacement":
            replacement: dict[str, Any] = {**inputs, "access_token": "replacement-synthetic"}
            store.set_oauth_local_credentials(**replacement)
        elif mutation == "workspace":
            replacement = {**inputs, "workspace_id": "other-workspace"}
            store.set_oauth_local_credentials(**replacement)
        elif mutation == "source-aba":
            store.clear_oauth_local_credentials()
            store.set_oauth_local_credentials(**inputs)
    finally:
        release.set()
        first[0].join(timeout=10)
        if second is not None:
            second[0].join(timeout=10)
    assert _finish(first) == {"done": True}
    assert requests.count("inventory") == 1
    terminal = store.get_sync_payload("aibom_inventory_daemon")
    if mutation in {"unchanged", "refresh"}:
        assert isinstance(terminal, dict)
        assert terminal["synced"] is True
        assert terminal["status"] == "synced"
    else:
        assert terminal == sentinel
        assert store.get_sync_payload("aibom_sync_summary") is None
    assert runner._receipt_sync_cursor_rowid(store) == after
