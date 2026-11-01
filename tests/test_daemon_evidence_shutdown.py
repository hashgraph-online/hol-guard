"""Concurrent HTTP/service cleanup shares ordered evidence ownership."""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_module
from codex_plugin_scanner.guard.daemon.bounded_http import BoundedThreadingHTTPServer
from codex_plugin_scanner.guard.daemon.hook_direct_evidence_drain import DirectHookEvidenceDrain
from codex_plugin_scanner.guard.daemon.hook_evidence_dispatch import HookEvidenceDispatch
from codex_plugin_scanner.guard.daemon.hook_evidence_shutdown import shutdown_hook_evidence
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker


def service(tmp_path, monkeypatch, *, producer, dispatch, writer, finalizer_entered=None):
    http = object.__new__(daemon_module._GuardDaemonHTTPServer)

    def stop_requests():
        if finalizer_entered is not None and threading.current_thread().name == "service-finalizer":
            finalizer_entered.set()
        return True

    http._stop_request_executors = stop_requests
    http.stop_unclassified_watchdog = lambda: True
    http.audit_persistence = http.codex_binding_capture_writer = None
    http.hook_worker = producer
    http.runtime_hook_evidence_dispatch = dispatch
    http.runtime_hook_evidence_writer = writer
    http.store = SimpleNamespace(guard_home=tmp_path, clear_runtime_state=lambda **_kwargs: None)
    http.runtime_session_id = "owned-unit-session"
    http.server_address = ("127.0.0.1", 0)
    daemon = object.__new__(daemon_module.GuardDaemonServer)
    daemon._server = http
    daemon.port = 0
    daemon._shutdown_started = threading.Event()
    daemon._command_queue_worker = daemon._cloud_review_sync_worker = None
    daemon._join_service_background_threads = lambda: True
    daemon._diagnostics = SimpleNamespace(close=lambda **_kwargs: None)
    daemon._record_quarantine_state = lambda *, contained: contained
    daemon._is_quarantined = lambda: False
    daemon._thread = threading.main_thread()  # HTTP close is exercised separately.
    daemon._owner_lock = None
    monkeypatch.setattr(BoundedThreadingHTTPServer, "server_close", lambda _self: None)
    monkeypatch.setattr(daemon_module, "clear_guard_daemon_state_if_current", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(daemon_module, "release_guard_daemon_owner_lock", lambda _owner: None)
    return daemon, http


def test_concurrent_http_and_service_close_drain_once_before_stopping_writer(tmp_path, monkeypatch):
    producer_entered, release, finalizer_entered = threading.Event(), threading.Event(), threading.Event()
    producer_closed, writer_called, writer_alive = threading.Event(), threading.Event(), threading.Event()
    writer_alive.set()
    dispatch = HookEvidenceDispatch()
    records, producer_calls, writer_calls, errors, results = [], [], [], [], []

    def close_producer():
        producer_calls.append(True)
        producer_entered.set()
        assert release.wait(2)
        dispatch.run(lambda: records.append(("receipt", writer_alive.is_set())))
        dispatch.run(lambda: records.append(("activity", writer_alive.is_set())))
        producer_closed.set()
        return True

    def close_writer(**_kwargs):
        writer_called.set()
        writer_calls.append(producer_closed.is_set())
        writer_alive.clear()
        return True

    producer = SimpleNamespace(close=close_producer, close_contained=close_producer)
    daemon, http = service(
        tmp_path,
        monkeypatch,
        producer=producer,
        dispatch=dispatch,
        writer=SimpleNamespace(stop=close_writer),
        finalizer_entered=finalizer_entered,
    )

    def run(work):
        try:
            results.append(work())
        except BaseException as error:
            errors.append(error)

    first = threading.Thread(target=run, args=(http.server_close,), name="http-close")
    second = threading.Thread(target=run, args=(daemon._finish_service_locked,), name="service-finalizer")
    try:
        first.start()
        assert producer_entered.wait(1)
        second.start()
        assert finalizer_entered.wait(1)
        assert not writer_called.wait(0.15), "writer stopped while its producer was still running"
        release.set()
        first.join(2)
        second.join(2)
        assert not first.is_alive() and not second.is_alive() and not errors
        assert producer_calls == [True]
        assert writer_calls == [True]
        assert records == [("receipt", True), ("activity", True)]
        assert True in results
    finally:
        release.set()
        first.join(2)
        if second.ident is not None:
            second.join(2)
        assert dispatch.stop(1)


@pytest.mark.parametrize("blocked", ["producer", "dispatch"])
@pytest.mark.parametrize("unconfirmed", [False, None])
def test_incomplete_producer_or_dispatch_retains_native_writer_for_retry(tmp_path, monkeypatch, blocked, unconfirmed):
    ready, calls = {"value": False}, []

    def producer():
        calls.append("producer")
        return (True if ready["value"] else unconfirmed) if blocked == "producer" else True

    def dispatch(*_args):
        calls.append("dispatch")
        return (True if ready["value"] else unconfirmed) if blocked == "dispatch" else True

    def writer(**_kwargs):
        calls.append("writer")
        return True

    daemon, _http = service(
        tmp_path,
        monkeypatch,
        producer=SimpleNamespace(close=producer, close_contained=producer),
        dispatch=SimpleNamespace(stop=dispatch),
        writer=SimpleNamespace(stop=writer),
    )
    assert daemon._finish_service_locked() is False
    assert "writer" not in calls
    ready["value"] = True
    assert daemon._finish_service_locked() is True
    assert calls.count("writer") == 1


@pytest.mark.parametrize("unconfirmed", [False, None])
def test_unfinished_writer_retry_does_not_reopen_closed_producers(tmp_path, monkeypatch, unconfirmed):
    replies, calls = iter((unconfirmed, True)), []

    def producer():
        calls.append("producer")
        return True

    def dispatch(*_args):
        calls.append("dispatch")
        return True

    def writer(**_kwargs):
        calls.append("writer")
        return next(replies)

    daemon, _http = service(
        tmp_path,
        monkeypatch,
        producer=SimpleNamespace(close=producer, close_contained=producer),
        dispatch=SimpleNamespace(stop=dispatch),
        writer=SimpleNamespace(stop=writer),
    )
    assert daemon._finish_service_locked() is False
    assert daemon._finish_service_locked() is True
    assert calls == ["producer", "dispatch", "writer", "writer"]


def test_contended_close_keeps_its_own_wait_budget_and_cannot_stop_the_writer():
    entered, release = threading.Event(), threading.Event()
    writer_calls, results = [], []

    def producer():
        entered.set()
        return release.wait(2)

    host = SimpleNamespace(
        hook_worker=SimpleNamespace(close_contained=producer),
        runtime_hook_evidence_dispatch=SimpleNamespace(stop=lambda _budget: True),
        runtime_hook_evidence_writer=SimpleNamespace(stop=lambda **_kwargs: writer_calls.append(True) or True),
    )
    thread = threading.Thread(target=lambda: results.append(shutdown_hook_evidence(host)))
    try:
        thread.start()
        assert entered.wait(1)
        started = time.monotonic()
        assert shutdown_hook_evidence(host, timeout_seconds=0.01) is False
        assert time.monotonic() - started < 0.5
        assert writer_calls == []
        release.set()
        thread.join(1)
        assert results == [True] and writer_calls == [True]
        assert shutdown_hook_evidence(host)
        assert writer_calls == [True]
    finally:
        release.set()
        thread.join(1)


def test_direct_drain_stop_reports_an_owned_thread_that_has_not_exited():
    drain = object.__new__(DirectHookEvidenceDrain)
    drain._stop = threading.Event()
    released = threading.Event()
    thread = threading.Thread(target=released.wait, daemon=True)
    drain._thread = thread
    drained = []
    drain.drain_once = lambda: drained.append(True)
    thread.start()
    try:
        assert drain.stop(timeout_seconds=0.01) is False
        assert drained == []
        released.set()
        thread.join(1)
        assert drain.stop(timeout_seconds=0.01) is True
        assert drained == [True]
    finally:
        released.set()
        thread.join(1)


def test_hook_worker_keeps_its_unfinished_direct_drain_and_does_not_close_publisher():
    worker = object.__new__(HookWorker)
    ready, events = {"value": False}, []
    drain = SimpleNamespace(stop=lambda: ready["value"])
    worker._direct_evidence_drain = drain
    worker._owns_policy_snapshot_publisher = True
    worker.policy_snapshot_publisher = SimpleNamespace(
        enable_direct_evidence_drain=lambda enabled: events.append(("enabled", enabled)),
        close_contained=lambda: events.append(("publisher", False)) or True,
    )
    assert worker.close_contained() is False
    assert worker._direct_evidence_drain is drain
    assert ("publisher", False) not in events
    ready["value"] = True
    assert worker.close_contained() is True
    assert worker._direct_evidence_drain is None
    assert events.count(("publisher", False)) == 1
