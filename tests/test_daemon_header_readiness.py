"""Completed headers wake the bounded classifier without a polling pause."""

from __future__ import annotations

import http.client
import socket
import threading
import time
from contextlib import contextmanager

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def running(tmp_path, monkeypatch, *, interval=5.0):
    monkeypatch.setattr(daemon_manager, "_guard_daemon_process_inventory_for_guard_home", lambda _: [])
    # Enlarge only this fixture's poll period so readiness, rather than a lucky
    # production timer tick, must deliver the response. Production stays 25 ms.
    monkeypatch.setattr(daemon_server, "_DAEMON_UNCLASSIFIED_WATCHDOG_POLL_SECONDS", interval)
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard", prime_policy_integrity=False), host="127.0.0.1", port=0, idle_timeout_seconds=0
    )
    waiting, parked = threading.Event(), threading.Event()
    original_wait = daemon._server.unclassified_watchdog_stop.wait
    original_submit = daemon._server._submit_transport_request

    def wait(timeout):
        waiting.set()
        return original_wait(timeout)

    def submit(request, address, **options):
        result = original_submit(request, address, **options)
        with daemon._server.unclassified_connections_lock:
            if id(request) in daemon._server.pending_classifications:
                parked.set()
        return result

    monkeypatch.setattr(daemon._server.unclassified_watchdog_stop, "wait", wait)
    monkeypatch.setattr(daemon._server, "_submit_transport_request", submit)
    daemon.start()
    client = None
    try:
        assert waiting.wait(1)
        client = socket.create_connection(("127.0.0.1", daemon.port), timeout=1)
        client.settimeout(1)
        assert parked.wait(1), "owned connection was not deferred before its first header byte"
        yield daemon, client
    finally:
        if client is not None:
            client.close()
        daemon.stop()


def test_first_header_bytes_wake_a_parked_request(native_context_digest, tmp_path, monkeypatch):
    del native_context_digest
    with running(tmp_path, monkeypatch) as (daemon, client):
        client.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(client)
        response.begin()
        assert response.status == 200
        assert b'"ok": true' in response.read()
        assert daemon._server.rejected_requests == 0


def test_stop_wakes_the_classifier_with_an_unread_peer(native_context_digest, tmp_path, monkeypatch):
    del native_context_digest
    with running(tmp_path, monkeypatch) as (daemon, _client):
        assert daemon._server.stop_unclassified_watchdog()
        assert daemon._server.unclassified_watchdog_thread is None


def test_partial_headers_do_not_spin_or_take_a_request_worker(native_context_digest, tmp_path, monkeypatch):
    del native_context_digest
    with running(tmp_path, monkeypatch, interval=0.05) as (daemon, client):
        checked = 0
        original = daemon._server._buffered_request_headers_complete

        def complete(request, *, pending=False):
            nonlocal checked
            checked += 1
            return original(request, pending=pending)

        monkeypatch.setattr(daemon._server, "_buffered_request_headers_complete", complete)
        client.sendall(b"GET /hea")
        time.sleep(0.15)
        assert checked < 20, "unchanged readable prefix spun instead of retaining the existing polling bound"
        with daemon._server.unclassified_connections_lock:
            assert len(daemon._server.pending_classifications) == 1
        client.sendall(b"lthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(client)
        response.begin()
        assert response.status == 200
        response.read()
