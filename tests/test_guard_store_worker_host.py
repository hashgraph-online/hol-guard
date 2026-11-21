"""The native store owns the rows the request handlers and the worker host hand each other."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workers.host import DurableWorkerRefresh, WorkerHost

_NOW = "2026-11-21T00:00:00+00:00"


def test_attention_is_taken_once_in_operation_order(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.queue_approval_attention(operation_id="op-b", requests=[{"request_id": "b"}], now=_NOW)
    store.queue_approval_attention(operation_id="op-a", requests=[{"request_id": "a"}], now=_NOW)
    store.set_sync_payload("daemon_approval_attentionXop-c", {"operation_id": "op-c"}, _NOW)
    assert store.take_approval_attention() == [
        {"operation_id": "op-a", "requests": [{"request_id": "a"}]},
        {"operation_id": "op-b", "requests": [{"request_id": "b"}]},
    ]
    assert store.take_approval_attention() == []
    assert store.get_sync_payload("daemon_approval_attentionXop-c") == {"operation_id": "op-c"}


def test_an_empty_operation_id_writes_nothing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with pytest.raises(ValueError, match="invalid_operation_id"):
        store.queue_approval_attention(operation_id="", requests=[], now=_NOW)
    assert store.take_approval_attention() == []


def test_the_refresh_handshake_matches_its_nonce(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.take_worker_refresh_request() is None
    store.request_worker_refresh(nonce="n1", now=_NOW)
    assert store.worker_refresh_status(nonce="n1") is None
    assert store.take_worker_refresh_request() == "n1"
    assert store.take_worker_refresh_request() is None
    store.record_worker_refresh_status(nonce="n1", running=True, sync_running=False, now=_NOW)
    assert store.worker_refresh_status(nonce="n1") == {"running": True, "sync_running": False}
    assert store.worker_refresh_status(nonce="n2") is None


def test_a_malformed_refresh_request_is_left_unanswered(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("daemon_worker_refresh_request", {"nonce": 7}, _NOW)
    assert store.take_worker_refresh_request() is None
    assert store.get_sync_payload("daemon_worker_refresh_request") == {"nonce": 7}


def test_the_worker_host_answers_a_waiting_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    store.request_worker_refresh(nonce="n1", now=_NOW)
    host = WorkerHost.__new__(WorkerHost)
    host.store = store
    monkeypatch.setattr(host, "refresh_queues", lambda: (True, True), raising=False)
    host.answer_refresh_request()
    assert store.take_worker_refresh_request() is None
    assert store.worker_refresh_status(nonce="n1") == {"running": True, "sync_running": True}


def test_an_unanswered_refresh_reports_nothing_running(tmp_path: Path) -> None:
    answer = DurableWorkerRefresh(GuardStore(tmp_path), wait_seconds=0.0).refresh_command_queue_worker()
    assert answer == {"operation": "guard.review.resolveExact", "running": False, "sync_running": False}


def test_the_repair_self_check_status_round_trips(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    assert store.repair_self_check_status() is None
    store.record_repair_self_check(status={"ok": True, "checks": [1]}, now=_NOW)
    assert store.repair_self_check_status() == {"ok": True, "checks": [1]}
    store.set_sync_payload("daemon_repair_self_check_status", [1], _NOW)
    assert store.repair_self_check_status() is None
