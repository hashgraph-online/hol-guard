"""The idle watchdog must not shut the daemon down under an in-flight request."""

from __future__ import annotations

import http.client
import time
import urllib.error
import urllib.request

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


def _started_daemon(tmp_path, monkeypatch: pytest.MonkeyPatch) -> GuardDaemonServer:
    store = GuardStore(tmp_path / "pytest-of-user" / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=60.0)
    monkeypatch.setattr(
        daemon._server.hook_process_runner,
        "enable_full_capacity",
        lambda **_kwargs: None,
    )
    daemon.start()
    return daemon


def test_idle_watchdog_waits_for_in_flight_requests(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = _started_daemon(tmp_path, monkeypatch)
    server = daemon._server
    try:
        with server.request_capacity_lock:
            server.active_requests += 1
        # Let any watchdog pass that read the count before the increment finish.
        time.sleep(1.2)
        # The request started long before the idle window and is still running.
        server.last_activity_monotonic = time.monotonic() - 61.0
        assert not daemon._shutdown_started.wait(timeout=1.5)

        with server.request_capacity_lock:
            server.active_requests -= 1
        assert daemon._shutdown_started.wait(timeout=3)
    finally:
        daemon.stop()


def test_releasing_a_request_restarts_the_idle_clock(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = _started_daemon(tmp_path, monkeypatch)
    server = daemon._server

    class _Request:
        pass

    request = _Request()
    try:
        with server.request_capacity_lock:
            server.active_requests += 1
            server.request_accepted_at[id(request)] = time.monotonic()
        server.connection_capacity.acquire()
        server.last_activity_monotonic = time.monotonic() - 61.0
        monkeypatch.setattr(server, "classify_connection", lambda _request: None)
        monkeypatch.setattr(server, "_guard_release_request", lambda: None)

        server._release_request_capacity(request)

        assert server.active_requests == 0
        assert time.monotonic() - server.last_activity_monotonic < 5.0
        assert not daemon._shutdown_started.wait(timeout=1.5)
    finally:
        daemon.stop()


def test_admission_refuses_requests_once_idle_shutdown_is_claimed(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    daemon = _started_daemon(tmp_path, monkeypatch)
    server = daemon._server
    try:
        with server.request_capacity_lock:
            server.idle_shutdown_claimed = True
            rejected_before = server.rejected_requests
        with pytest.raises((urllib.error.URLError, ConnectionError, http.client.HTTPException)):
            urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/v1/healthz", timeout=5)
        with server.request_capacity_lock:
            assert server.active_requests == 0
            assert server.rejected_requests == rejected_before + 1
            server.idle_shutdown_claimed = False
    finally:
        daemon.stop()
