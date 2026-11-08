from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import native_edge, native_edge_handshake


class _RecordingServer:
    address_family = socket.AF_INET
    request_queue_size = 8

    def __init__(self, listener: socket.socket) -> None:
        self.socket = listener
        self.processed: list[Any] = []
        self.processed_event = threading.Event()

    def verify_request(self, request: Any, client_address: Any) -> bool:
        return True

    def process_request(self, request: Any, client_address: Any) -> None:
        self.processed.append(client_address)
        request.sendall(b"served")
        request.close()
        self.processed_event.set()

    def shutdown_request(self, request: Any) -> None:
        request.close()

    def handle_error(self, request: Any, client_address: Any) -> None:
        raise AssertionError("unexpected request error")


def _listener() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    return listener


def _edge_process(code: str) -> native_edge._EdgeProcess:
    liveness, child_end = socket.socketpair()
    child_end.close()
    return native_edge._EdgeProcess(subprocess.Popen((sys.executable, "-c", code)), liveness)


def test_no_edge_leaves_the_server_on_its_public_socket(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    public = _listener()
    server = _RecordingServer(public)
    monkeypatch.setattr(native_edge, "_resolve_executable", lambda guard_home: None)
    try:
        assert native_edge.start_native_daemon_edge(server, guard_home=tmp_path, host="127.0.0.1") is None
        assert server.socket is public
    finally:
        public.close()


def test_edge_switch_off_skips_the_runtime_lookup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    public = _listener()
    server = _RecordingServer(public)
    monkeypatch.setenv(native_edge.EDGE_ENV, "0")

    def unexpected(guard_home: Path) -> Path | None:
        raise AssertionError("runtime looked up with the edge switched off")

    monkeypatch.setattr(native_edge, "_resolve_executable", unexpected)
    try:
        assert native_edge.start_native_daemon_edge(server, guard_home=tmp_path, host="127.0.0.1") is None
        assert server.socket is public
    finally:
        public.close()


@pytest.mark.skipif(sys.platform == "win32", reason="the native edge runs on POSIX only")
def test_edge_moves_the_server_to_a_private_port_and_passes_the_public_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public = _listener()
    public_port = public.getsockname()[1]
    server = _RecordingServer(public)
    spawned: list[tuple[int, int]] = []
    monkeypatch.delenv(native_edge.EDGE_ENV, raising=False)
    monkeypatch.setattr(native_edge, "_resolve_executable", lambda guard_home: Path(sys.executable))

    def fake_spawn(executable: Path, listener: socket.socket, upstream_port: int, *_: Any) -> native_edge._EdgeProcess:
        spawned.append((listener.getsockname()[1], upstream_port))
        return _edge_process("import time; time.sleep(30)")

    monkeypatch.setattr(native_edge, "_spawn", fake_spawn)
    edge = native_edge.start_native_daemon_edge(server, guard_home=tmp_path, host="127.0.0.1")
    assert edge is not None
    try:
        private_port = server.socket.getsockname()[1]
        assert server.socket is not public
        assert private_port != public_port
        assert spawned == [(public_port, private_port)]
    finally:
        process_id = edge.process_id
        edge.close()
        server.socket.close()
    assert process_id is not None
    assert edge.process_id is None
    assert public.fileno() == -1


@pytest.mark.skipif(sys.platform == "win32", reason="the native edge runs on POSIX only")
def test_daemon_serves_the_public_port_itself_when_the_edge_keeps_failing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    public = _listener()
    public_port = public.getsockname()[1]
    server = _RecordingServer(_listener())
    monkeypatch.setattr(native_edge, "_RESTART_DELAYS_SECONDS", (0.01,))
    monkeypatch.setattr(
        native_edge,
        "_spawn",
        lambda executable, listener, upstream_port, *_: _edge_process("pass"),
    )
    edge = native_edge.NativeDaemonEdge(
        server=server,
        public=public,
        upstream_port=server.socket.getsockname()[1],
        process=_edge_process("pass"),
        resolve_executable=lambda: Path(sys.executable),
    )
    try:
        deadline = time.monotonic() + 20
        while not edge.serving_in_process and time.monotonic() < deadline:
            time.sleep(0.02)
        assert edge.serving_in_process
        with socket.create_connection(("127.0.0.1", public_port), timeout=10) as client:
            assert client.recv(16) == b"served"
        assert server.processed_event.wait(10)
    finally:
        edge.close()
        server.socket.close()


@pytest.mark.skipif(sys.platform == "win32", reason="the native edge runs on POSIX only")
def test_edge_that_cannot_start_its_supervisor_leaves_the_public_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    public = _listener()
    server = _RecordingServer(public)
    started: list[native_edge._EdgeProcess] = []
    monkeypatch.delenv(native_edge.EDGE_ENV, raising=False)
    monkeypatch.setattr(native_edge, "_resolve_executable", lambda guard_home: Path(sys.executable))

    def fake_spawn(executable: Path, listener: socket.socket, upstream_port: int, *_: Any) -> native_edge._EdgeProcess:
        started.append(_edge_process("import time; time.sleep(30)"))
        return started[-1]

    def no_thread(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(native_edge, "_spawn", fake_spawn)
    monkeypatch.setattr(threading.Thread, "start", no_thread)
    try:
        assert native_edge.start_native_daemon_edge(server, guard_home=tmp_path, host="127.0.0.1") is None
        assert server.socket is public
        assert public.fileno() != -1
        assert started[0].process.poll() is not None
    finally:
        public.close()


def test_handshake_names_the_store_and_clamps_the_busy_timeout(tmp_path: Path) -> None:
    line = native_edge_handshake.edge_handshake(
        auth_token="token",
        guard_home=tmp_path,
        store_path=tmp_path / "guard.db",
        source="default",
        busy_timeout_seconds=600.0,
        dashboard_build=None,
    )
    assert line.endswith(b"\n") and line.count(b"\n") == 1
    assert json.loads(line) == {
        "schema": native_edge_handshake.HANDSHAKE_SCHEMA,
        "auth_token": "token",
        "guard_home": str(tmp_path),
        "store_path": str(tmp_path / "guard.db"),
        "source": "default",
        "busy_timeout_ms": 60_000,
    }
    assert (
        json.loads(
            native_edge_handshake.edge_handshake(
                auth_token="token",
                guard_home=tmp_path,
                store_path=tmp_path / "guard.db",
                source="default",
                busy_timeout_seconds=0.0,
                dashboard_build="abc123",
            )
        )["busy_timeout_ms"]
        == 1
    )


def test_edge_activity_reaches_the_daemon_after_the_handshake() -> None:
    daemon_end, edge_end = socket.socketpair()
    touched = threading.Event()
    try:
        native_edge._offer_handshake(daemon_end, lambda: b"hello\n", touched.set)
        edge_end.settimeout(10)
        assert edge_end.recv(16) == b"hello\n"
        edge_end.sendall(b"a")
        assert touched.wait(10)
    finally:
        native_edge._close_liveness(daemon_end)
        edge_end.close()


def test_edge_gets_no_handshake_when_activity_cannot_be_read(monkeypatch: pytest.MonkeyPatch) -> None:
    daemon_end, edge_end = socket.socketpair()

    def no_thread(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", no_thread)
    try:
        native_edge._offer_handshake(daemon_end, lambda: b"hello\n", lambda: None)
        daemon_end.close()
        edge_end.settimeout(10)
        assert edge_end.recv(16) == b""
    finally:
        edge_end.close()


@pytest.mark.skipif(sys.platform == "win32", reason="the native edge runs on POSIX only")
def test_a_restarted_edge_gets_the_handshake_again(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _RecordingServer(_listener())
    public = _listener()
    respawned = threading.Event()
    received: list[tuple[Any, Any]] = []

    def handshake() -> bytes:
        return b"hello\n"

    def on_activity() -> None:
        return None

    def fake_spawn(
        executable: Path, listener: socket.socket, upstream_port: int, *callbacks: Any
    ) -> native_edge._EdgeProcess:
        received.append(callbacks)
        respawned.set()
        return _edge_process("import time; time.sleep(30)")

    monkeypatch.setattr(native_edge, "_RESTART_DELAYS_SECONDS", (0.01,))
    monkeypatch.setattr(native_edge, "_spawn", fake_spawn)
    edge = native_edge.NativeDaemonEdge(
        server=server,
        public=public,
        upstream_port=server.socket.getsockname()[1],
        process=_edge_process("pass"),
        resolve_executable=lambda: Path(sys.executable),
        handshake=handshake,
        on_activity=on_activity,
    )
    try:
        assert respawned.wait(20)
        assert received[0] == (handshake, on_activity)
    finally:
        edge.close()
        server.socket.close()


def test_edge_callbacks_read_the_server_store_and_touch_its_heartbeat(tmp_path: Path) -> None:
    touched: list[str] = []

    class _Store:
        guard_home = tmp_path
        path = tmp_path / "guard.db"
        guard_source = "default"

    class _Heartbeat:
        def touch(self, now: str) -> None:
            touched.append(now)

    class _Server:
        store = _Store()
        auth_token = "token"
        runtime_heartbeat = _Heartbeat()
        last_activity_monotonic = 0.0

    server = _Server()
    handshake, on_activity = native_edge_handshake.daemon_edge_callbacks(server, tmp_path / "static")
    payload = json.loads(handshake())
    assert payload["store_path"] == str(tmp_path / "guard.db")
    assert payload["source"] == "default"
    assert "dashboard_build" not in payload
    assert payload["user_home"] == str(Path.home())
    on_activity()
    assert server.last_activity_monotonic > 0
    assert len(touched) == 1
