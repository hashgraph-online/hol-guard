"""Frozen-daemon onefile extraction sweeps: worker gating, status, shutdown."""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import onefile_extraction
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.onefile_extraction import ExtractionReclaimResult


class _StubDiagnostics:
    def __init__(self) -> None:
        self.events: list[str] = []

    def record(self, event: str, *, detail: str | None = None) -> bool:
        self.events.append(event)
        return True

    def record_exception(self, event: str, **kwargs: object) -> bool:
        self.events.append(event)
        return True


class _StubHttpServer:
    """The healthz handler reads ``onefile_extraction_status`` off the HTTP
    server (``daemon_server.onefile_extraction_status``), not the service."""

    onefile_extraction_status: dict[str, object] | None = None


def _bare_daemon_server() -> GuardDaemonServer:
    server = GuardDaemonServer.__new__(GuardDaemonServer)
    server._shutdown_started = threading.Event()
    server._onefile_extraction_reclaim_thread = None
    server._server = _StubHttpServer()
    server._diagnostics = _StubDiagnostics()
    return server


def test_reclaim_worker_starts_only_when_frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    server = _bare_daemon_server()
    server._start_onefile_extraction_reclaim()
    assert server._onefile_extraction_reclaim_thread is None

    calls: list[dict[str, object]] = []

    def fake_reclaim(**kwargs: object) -> ExtractionReclaimResult:
        calls.append(kwargs)
        return ExtractionReclaimResult(
            reclaimed_count=2,
            reclaimed_bytes=2048,
            killed_launches=2,
            unmarked_count=1,
            unmarked_bytes_estimate=512,
        )

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(onefile_extraction, "reclaim_orphaned_extraction_dirs", fake_reclaim)
    server._start_onefile_extraction_reclaim()
    thread = server._onefile_extraction_reclaim_thread
    assert thread is not None
    try:
        deadline = time.monotonic() + 5
        while server._server.onefile_extraction_status is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert calls, "reclaim worker never ran"
        assert calls[0]["temp_root"] == Path(tempfile.gettempdir())
        assert calls[0]["current_meipass"] is None

        status = server._server.onefile_extraction_status
        assert status is not None
        assert status["reclaimed_count"] == 2
        assert status["reclaimed_bytes"] == 2048
        assert status["killed_launches_last_run"] == 2
        assert status["unmarked_legacy_count"] == 1
        assert status["unmarked_legacy_bytes_estimate"] == 512
        assert status["error_count"] == 0
        assert isinstance(status["last_run_at"], str)
        assert "onefile_extraction_reclaimed" in server._diagnostics.events
    finally:
        server._shutdown_started.set()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_reclaim_result_reaches_the_healthz_attribute(monkeypatch: pytest.MonkeyPatch) -> None:
    """The status the healthz payload serves lives on the HTTP server object."""

    server = _bare_daemon_server()
    monkeypatch.setattr(
        onefile_extraction,
        "reclaim_orphaned_extraction_dirs",
        lambda **kwargs: ExtractionReclaimResult(reclaimed_count=3, reclaimed_bytes=99),
    )

    server._reclaim_onefile_extraction_dirs_once()

    # Same attribute the handler's daemon_server (the _GuardDaemonHTTPServer)
    # exposes to the /v1/healthz/details payload.
    status = server._server.onefile_extraction_status
    assert status is not None
    assert status["reclaimed_count"] == 3
    assert status["reclaimed_bytes"] == 99


def test_reclaim_failure_records_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _bare_daemon_server()

    def boom(**kwargs: object) -> ExtractionReclaimResult:
        raise RuntimeError("sweep crashed")

    monkeypatch.setattr(onefile_extraction, "reclaim_orphaned_extraction_dirs", boom)
    server._reclaim_onefile_extraction_dirs_once()

    status = server._server.onefile_extraction_status
    assert status is not None
    assert status["error"] == "reclaim_failed"
    assert isinstance(status["last_run_at"], str)
    assert "onefile_extraction_reclaim_failed" in server._diagnostics.events


def test_reclaim_loop_exits_immediately_when_shutdown() -> None:
    server = _bare_daemon_server()
    server._shutdown_started.set()

    calls: list[object] = []

    def never_called(**kwargs: object) -> ExtractionReclaimResult:
        calls.append(kwargs)
        return ExtractionReclaimResult()

    original = onefile_extraction.reclaim_orphaned_extraction_dirs
    onefile_extraction.reclaim_orphaned_extraction_dirs = never_called
    try:
        server._onefile_extraction_reclaim_loop()
    finally:
        onefile_extraction.reclaim_orphaned_extraction_dirs = original

    assert calls == []
    assert server._server.onefile_extraction_status is None


def test_reclaim_loop_reruns_after_wait_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _bare_daemon_server()
    sweeps = 0

    def count_sweep(**kwargs: object) -> ExtractionReclaimResult:
        nonlocal sweeps
        sweeps += 1
        return ExtractionReclaimResult()

    waits = 0

    def fake_wait(timeout: float) -> bool:
        nonlocal waits
        waits += 1
        return waits > 1  # first wait "times out" and loops, second exits

    monkeypatch.setattr(onefile_extraction, "reclaim_orphaned_extraction_dirs", count_sweep)
    monkeypatch.setattr(server._shutdown_started, "wait", fake_wait)

    server._onefile_extraction_reclaim_loop()

    assert sweeps == 2


def test_start_reclaim_is_noop_while_thread_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    server = _bare_daemon_server()
    blocker = threading.Event()
    alive = threading.Thread(target=blocker.wait, args=(5,), daemon=True)
    alive.start()
    server._onefile_extraction_reclaim_thread = alive

    server._start_onefile_extraction_reclaim()

    assert server._onefile_extraction_reclaim_thread is alive
    blocker.set()
    alive.join(timeout=5)
