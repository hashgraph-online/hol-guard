from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler

from codex_plugin_scanner.guard.daemon.bounded_http import (
    BoundedThreadingHTTPServer,
    daemon_admission_snapshot,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


class _Handler(BaseHTTPRequestHandler):
    release = threading.Event()
    entered = threading.Event()
    hold_count = 0
    hold_lock = threading.Lock()
    two_holds = threading.Event()

    def do_GET(self) -> None:
        if self.path == "/hold":
            self.entered.set()
            with _Handler.hold_lock:
                _Handler.hold_count += 1
                if _Handler.hold_count >= 2:
                    _Handler.two_holds.set()
            self.release.wait(timeout=2)
        payload = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args


def _serve() -> tuple[BoundedThreadingHTTPServer, threading.Thread]:
    server = BoundedThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _get(port: int, path: str) -> tuple[int, bytes]:
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_bounded_server_recovers_after_client_abort() -> None:
    server, thread = _serve()
    port = server.server_address[1]
    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=1)
        client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        client.close()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            status, body = _get(port, "/")
            if status == 200:
                assert json.loads(body) == {"ok": True}
                break
            time.sleep(0.01)
        else:
            raise AssertionError("daemon did not recover after a client abort")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_bounded_server_returns_fast_retryable_overload(monkeypatch) -> None:
    monkeypatch.setenv("HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS", "2")
    _Handler.release.clear()
    _Handler.entered.clear()
    _Handler.two_holds.clear()
    _Handler.hold_count = 0
    server, thread = _serve()
    port = server.server_address[1]
    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            first = executor.submit(_get, port, "/hold")
            second = executor.submit(_get, port, "/hold")
            assert _Handler.two_holds.wait(timeout=1)
            deadline = time.monotonic() + 1
            third = executor.submit(_get, port, "/")
            status, body = third.result(timeout=1)
            elapsed = 1 - max(0.0, deadline - time.monotonic())
            assert status == 503
            assert json.loads(body)["error"] == "daemon_overloaded"
            assert elapsed < 0.75
            _Handler.release.set()
            assert first.result(timeout=2)[0] == 200
            assert second.result(timeout=2)[0] == 200
        snapshot = daemon_admission_snapshot()
        assert snapshot["high_water"] <= 2
        assert snapshot["rejected"] >= 1
    finally:
        _Handler.release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_bounded_server_times_out_incomplete_request(monkeypatch) -> None:
    monkeypatch.setenv("HOL_GUARD_DAEMON_SOCKET_TIMEOUT_SECONDS", "0.25")
    server, thread = _serve()
    port = server.server_address[1]
    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=1)
        client.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n")
        time.sleep(0.6)
        client.settimeout(1)
        assert client.recv(1) == b""
        client.close()
        assert _get(port, "/")[0] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_daemon_admission_snapshot_is_aggregate_only() -> None:
    payload = daemon_admission_snapshot()
    assert set(payload) == {
        "active",
        "high_water",
        "accepted",
        "rejected",
        "client_aborts",
        "timeouts",
        "non_loopback_rejections",
    }
    assert all(isinstance(value, int) and value >= 0 for value in payload.values())


def test_real_daemon_subclass_enforces_bounded_admission(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS", "1")
    monkeypatch.setenv("HOL_GUARD_DAEMON_SOCKET_TIMEOUT_SECONDS", "0.5")
    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    daemon.start()
    held = socket.create_connection(("127.0.0.1", daemon.port), timeout=1)
    try:
        held.sendall(b"POST /v1/health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n")
        deadline = time.monotonic() + 1
        while daemon_admission_snapshot()["active"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        status, body = _get(daemon.port, "/v1/health")
        assert status == 503
        assert json.loads(body)["error"] == "daemon_overloaded"
    finally:
        held.close()
        daemon.stop()
