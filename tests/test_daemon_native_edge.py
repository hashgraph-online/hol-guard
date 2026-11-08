from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import native_edge


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

    def fake_spawn(executable: Path, listener: socket.socket, upstream_port: int) -> subprocess.Popen[bytes]:
        spawned.append((listener.getsockname()[1], upstream_port))
        return subprocess.Popen((sys.executable, "-c", "import time; time.sleep(30)"))

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
        lambda executable, listener, upstream_port: subprocess.Popen((sys.executable, "-c", "pass")),
    )
    edge = native_edge.NativeDaemonEdge(
        server=server,
        public=public,
        upstream_port=server.socket.getsockname()[1],
        process=subprocess.Popen((sys.executable, "-c", "pass")),
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
