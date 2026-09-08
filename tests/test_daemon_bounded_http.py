from __future__ import annotations

import json
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler

import pytest

from codex_plugin_scanner.guard.daemon import bounded_http
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


def test_bounded_server_honors_stop_requested_before_loop_entry() -> None:
    server = BoundedThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.request_serve_stop()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        server.server_close()


def test_bounded_server_rolls_back_listener_and_wakeup_sockets_on_setblocking_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TrackedWakeupSocket:
        def __init__(self, wrapped: socket.socket) -> None:
            self.wrapped = wrapped
            self.closed = False

        def setblocking(self, _flag: bool) -> None:
            raise OSError("injected wakeup setblocking failure")

        def close(self) -> None:
            self.closed = True
            self.wrapped.close()

    wakeups: list[_TrackedWakeupSocket] = []
    original_socketpair = socket.socketpair

    def failing_socketpair() -> tuple[_TrackedWakeupSocket, _TrackedWakeupSocket]:
        reader, writer = original_socketpair()
        tracked = (_TrackedWakeupSocket(reader), _TrackedWakeupSocket(writer))
        wakeups.extend(tracked)
        return tracked

    listeners: list[BoundedThreadingHTTPServer] = []
    original_parent_init = bounded_http.ThreadingHTTPServer.__init__

    def capture_listener(server: BoundedThreadingHTTPServer, *args: object, **kwargs: object) -> None:
        original_parent_init(server, *args, **kwargs)
        listeners.append(server)

    monkeypatch.setattr(bounded_http.socket, "socketpair", failing_socketpair)
    monkeypatch.setattr(bounded_http.ThreadingHTTPServer, "__init__", capture_listener)

    with pytest.raises(OSError, match="setblocking"):
        BoundedThreadingHTTPServer(("127.0.0.1", 0), _Handler)

    assert all(endpoint.closed for endpoint in wakeups)
    assert listeners
    assert listeners[0].socket.fileno() == -1


def test_bounded_server_rolls_back_listener_and_wakeup_sockets_on_capacity_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TrackedWakeupSocket:
        def __init__(self, wrapped: socket.socket) -> None:
            self.wrapped = wrapped
            self.closed = False

        def setblocking(self, flag: bool) -> None:
            self.wrapped.setblocking(flag)

        def close(self) -> None:
            self.closed = True
            self.wrapped.close()

    wakeups: list[_TrackedWakeupSocket] = []
    original_socketpair = socket.socketpair

    def tracked_socketpair() -> tuple[_TrackedWakeupSocket, _TrackedWakeupSocket]:
        reader, writer = original_socketpair()
        tracked = (_TrackedWakeupSocket(reader), _TrackedWakeupSocket(writer))
        wakeups.extend(tracked)
        return tracked

    listeners: list[BoundedThreadingHTTPServer] = []
    original_parent_init = bounded_http.ThreadingHTTPServer.__init__
    original_bounded_int = bounded_http._bounded_int

    def capture_listener(server: BoundedThreadingHTTPServer, *args: object, **kwargs: object) -> None:
        original_parent_init(server, *args, **kwargs)
        listeners.append(server)

    def fail_capacity(name: str, default: int, maximum: int) -> int:
        if name == "HOL_GUARD_DAEMON_MAX_ACTIVE_REQUESTS":
            raise RuntimeError("injected capacity failure")
        return original_bounded_int(name, default, maximum)

    monkeypatch.setattr(bounded_http.socket, "socketpair", tracked_socketpair)
    monkeypatch.setattr(bounded_http.ThreadingHTTPServer, "__init__", capture_listener)
    monkeypatch.setattr(bounded_http, "_bounded_int", fail_capacity)

    with pytest.raises(RuntimeError, match="capacity"):
        BoundedThreadingHTTPServer(("127.0.0.1", 0), _Handler)

    assert all(endpoint.closed for endpoint in wakeups)
    assert listeners
    assert listeners[0].socket.fileno() == -1


def test_bounded_server_releases_admission_when_socket_timeout_fails() -> None:
    class _FailingTimeoutSocket:
        closed = False

        def settimeout(self, _timeout: float) -> None:
            raise OSError("injected request timeout failure")

        def close(self) -> None:
            self.closed = True

    server = BoundedThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    before = daemon_admission_snapshot()
    request = _FailingTimeoutSocket()
    try:
        assert not server._guard_admit_request(request)  # pyright: ignore[reportArgumentType]
        after = daemon_admission_snapshot()
        assert request.closed
        assert after["active"] == before["active"]
        assert after["accepted"] == before["accepted"] + 1
        assert server._guard_slots.acquire(blocking=False)
        server._guard_slots.release()
    finally:
        server.server_close()


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
