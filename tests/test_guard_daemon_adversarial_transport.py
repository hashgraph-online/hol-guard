# pyright: reportAny=false, reportImplicitStringConcatenation=false, reportPrivateUsage=false
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Generator
from contextlib import contextmanager, suppress
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def _running_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[GuardDaemonServer]:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    daemon = GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"),
        host="127.0.0.1",
        port=0,
        idle_timeout_seconds=0,
    )
    daemon.start()
    try:
        yield daemon
    finally:
        daemon.stop()


def _raw_request(port: int, request: bytes) -> bytes:
    client = socket.create_connection(("127.0.0.1", port), timeout=1)
    client.settimeout(2)
    try:
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        return _recv_all(client)
    finally:
        client.close()


def _recv_all(client: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = client.recv(4096)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _status_code(response: bytes) -> int:
    status_line = response.split(b"\r\n", 1)[0]
    return int(status_line.split()[1])


@pytest.mark.parametrize(
    ("headers", "body", "expected_status"),
    [
        (b"Content-Length: nope\r\n", b"{}", 400),
        (b"Content-Length: -1\r\n", b"", 400),
        (b"Content-Length: 1000001\r\n", b"", 413),
        (b"Content-Length: 2\r\nContent-Length: 2\r\n", b"{}", 400),
        (b"Transfer-Encoding: chunked\r\n", b"2\r\n{}\r\n0\r\n\r\n", 400),
        (b"Content-Type: application/json\r\nContent-Length: 1\r\n", b"\xff", 400),
        (b"Content-Type: application/json\r\nContent-Length: 1\r\n", b"{", 400),
    ],
)
def test_malformed_request_framing_returns_bounded_error_without_handler_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    headers: bytes,
    body: bytes,
    expected_status: int,
) -> None:
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors: list[object] = []
        monkeypatch.setattr(
            daemon._server,
            "handle_error",
            lambda _request, address: handler_errors.append(address),
        )
        request = (
            b"POST /v1/hooks/pi HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            + headers
            + f"X-Guard-Token: {daemon._server.auth_token}\r\n".encode()
            + b"\r\n"
            + body
        )

        response = _raw_request(daemon.port, request)

    assert _status_code(response) == expected_status
    assert handler_errors == []


def test_truncated_request_body_returns_400_without_handler_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        handler_errors: list[object] = []
        monkeypatch.setattr(
            daemon._server,
            "handle_error",
            lambda _request, address: handler_errors.append(address),
        )
        response = _raw_request(
            daemon.port,
            (
                b"POST /v1/hooks/pi HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 10\r\n" + f"X-Guard-Token: {daemon._server.auth_token}\r\n".encode() + b"\r\n{}"
            ),
        )

    assert _status_code(response) == 400
    assert b"incomplete_request_body" in response
    assert handler_errors == []


def test_slow_request_body_expires_and_releases_handler_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 0.05)
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        client = socket.create_connection(("127.0.0.1", daemon.port), timeout=1)
        client.settimeout(1)
        try:
            client.sendall(
                b"POST /v1/hooks/pi HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 10\r\n" + f"X-Guard-Token: {daemon._server.auth_token}\r\n".encode() + b"\r\n{"
            )
            response = _recv_all(client)
        finally:
            client.close()
        deadline = time.monotonic() + 1
        while daemon._server.active_requests and time.monotonic() < deadline:
            time.sleep(0.01)

        assert _status_code(response) == 408
        assert b"request_body_timeout" in response
        assert daemon._server.active_requests == 0


def test_disconnected_slow_clients_do_not_emit_handler_exception_storm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 0.05)
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        assert daemon._server.request_queue_size == daemon._server.connection_capacity_limit
        handler_errors: list[object] = []
        monkeypatch.setattr(
            daemon._server,
            "handle_error",
            lambda _request, address: handler_errors.append(address),
        )
        clients: list[socket.socket] = []
        for _ in range(64):
            client = socket.create_connection(("127.0.0.1", daemon.port), timeout=1)
            client.sendall(
                b"POST /v1/hooks/pi HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 9999\r\n" + f"X-Guard-Token: {daemon._server.auth_token}\r\n".encode() + b"\r\n{"
            )
            clients.append(client)
        for client in clients:
            client.close()
        deadline = time.monotonic() + 2
        while daemon._server.active_requests and time.monotonic() < deadline:
            time.sleep(0.01)
        with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=0.5) as response:
            assert json.loads(response.read())["ok"] is True

    assert handler_errors == []
    assert daemon._server.active_requests == 0


def test_partial_connections_are_bounded_before_handler_threads_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 1.0)
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        daemon._server.connection_capacity_limit = 2
        daemon._server.connection_capacity = threading.BoundedSemaphore(2)
        clients = [socket.create_connection(("127.0.0.1", daemon.port), timeout=1) for _ in range(3)]
        try:
            deadline = time.monotonic() + 0.2
            while time.monotonic() < deadline:
                with daemon._server.request_capacity_lock:
                    if daemon._server.active_requests == 2:
                        break
                time.sleep(0.01)
            with daemon._server.request_capacity_lock:
                assert daemon._server.active_requests == 2
            with daemon._server.unclassified_connections_lock:
                assert len(daemon._server.unclassified_connections) == 2
            clients[0].settimeout(0.2)
            with suppress(ConnectionResetError):
                assert clients[0].recv(1) == b""
        finally:
            for client in clients:
                client.close()


def test_absolute_header_deadline_closes_trickle_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        client = socket.create_connection(("127.0.0.1", daemon.port), timeout=1)
        client.settimeout(1)
        started = time.monotonic()
        try:
            for byte in b"GET /healthz HTTP/1.1\r\n":
                try:
                    client.sendall(bytes((byte,)))
                except OSError:
                    break
                time.sleep(0.04)
            with suppress(ConnectionResetError):
                assert client.recv(1) == b""
        finally:
            client.close()
        elapsed = time.monotonic() - started
        deadline = time.monotonic() + 1
        while daemon._server.active_requests and time.monotonic() < deadline:
            time.sleep(0.01)

    assert daemon_server._DAEMON_REQUEST_READ_TIMEOUT_SECONDS == 0.4
    assert elapsed < 1.0
    assert daemon._server.active_requests == 0


def test_liveness_progresses_during_continuous_slow_client_replenishment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        daemon._server.connection_capacity_limit = 4
        daemon._server.connection_capacity = threading.BoundedSemaphore(4)
        slow_clients = [socket.create_connection(("127.0.0.1", daemon.port), timeout=1) for _ in range(4)]
        health_latencies: list[float] = []
        try:
            for _ in range(12):
                started = time.monotonic()
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{daemon.port}/healthz",
                    timeout=0.5,
                ) as response:
                    assert json.loads(response.read())["ok"] is True
                health_latencies.append(time.monotonic() - started)
                slow_clients.append(socket.create_connection(("127.0.0.1", daemon.port), timeout=1))
        finally:
            for client in slow_clients:
                client.close()

    assert max(health_latencies) < 0.25


def test_liveness_uses_reserved_capacity_when_general_requests_are_saturated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        acquired = [
            daemon._server.request_capacity.acquire(blocking=False)
            for _ in range(daemon._server.request_capacity_limit)
        ]
        try:
            started = time.monotonic()
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=1) as response:
                health = json.loads(response.read())
            elapsed = time.monotonic() - started
        finally:
            for held in acquired:
                if held:
                    daemon._server.request_capacity.release()

    assert health["ok"] is True
    assert elapsed < 0.5


def test_128_connection_storm_keeps_fixed_workers_and_control_liveness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 2.0)
    daemon: GuardDaemonServer | None = None
    executor_threads: tuple[threading.Thread, ...] = ()
    clients: list[socket.socket] = []
    with _running_daemon(tmp_path, monkeypatch) as running:
        daemon = running
        executor_threads = (
            *daemon._server.general_request_executor.threads,
            *daemon._server.control_request_executor.threads,
        )
        clients = [socket.create_connection(("127.0.0.1", daemon.port), timeout=1) for _ in range(128)]
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            with daemon._server.request_capacity_lock:
                if daemon._server.active_requests == 128:
                    break
            time.sleep(0.01)

        with daemon._server.request_capacity_lock:
            assert daemon._server.active_requests == 128
        assert len(daemon._server.general_request_executor.threads) == 32
        assert len(daemon._server.control_request_executor.threads) == 8
        assert all(thread.is_alive() for thread in executor_threads)

        started = time.monotonic()
        with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=0.5) as response:
            assert json.loads(response.read())["ok"] is True
        assert time.monotonic() - started < 0.5

        for client in clients:
            client.close()
        clients.clear()

    assert daemon is not None
    assert daemon._server.active_requests == 0
    assert daemon._server.unclassified_connections == {}
    assert all(not thread.is_alive() for thread in executor_threads)


def test_transport_queue_delay_returns_typed_hook_deadline_overload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(daemon_server, "_DAEMON_REQUEST_READ_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(daemon_server, "_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS", 0.05)
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        slow_clients = [socket.create_connection(("127.0.0.1", daemon.port), timeout=1) for _ in range(32)]
        try:
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                with daemon._server.request_capacity_lock:
                    if daemon._server.active_requests == 32:
                        break
                time.sleep(0.01)
            query = urllib.parse.urlencode(
                {
                    "guard-home": str(daemon._server.store.guard_home),
                    "workspace": str(tmp_path),
                }
            )
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "read",
                        "tool_input": {},
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=1) as response:
                result = json.loads(response.read())
        finally:
            for client in slow_clients:
                client.close()

    assert result["decision"] == "deny"
    assert result["reason_code"] == "daemon_hook_deadline_exhausted"


@pytest.mark.parametrize(
    ("path", "payload", "assertion"),
    [
        (
            "/v1/hooks/pi",
            {"hook_event_name": "PreToolUse", "tool_name": "read", "tool_input": {}},
            ("decision", "deny"),
        ),
        (
            "/v1/hooks/claude-code",
            {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {}},
            ("permissionDecision", "deny"),
        ),
        (
            "/v1/hooks/claude-code",
            {"hook_event_name": "PermissionRequest", "tool_name": "Read", "tool_input": {}},
            ("behavior", "deny"),
        ),
    ],
)
def test_hook_overload_returns_native_fail_safe_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    payload: dict[str, object],
    assertion: tuple[str, str],
) -> None:
    with _running_daemon(tmp_path, monkeypatch) as daemon:
        daemon._server.runtime_hook_scheduler = daemon_server.RuntimeHookScheduler(retained_bytes_limit=1)
        query = urllib.parse.urlencode(
            {
                "guard-home": str(daemon._server.store.guard_home),
                "workspace": str(tmp_path),
            }
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}{path}?{query}",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=1) as response:
            result = json.loads(response.read())

    assert result["reason_code"] == "daemon_hook_queue_bytes"
    if assertion[0] == "decision":
        assert result["decision"] == assertion[1]
    elif assertion[0] == "permissionDecision":
        assert result["hookSpecificOutput"]["permissionDecision"] == assertion[1]
    else:
        assert result["hookSpecificOutput"]["decision"]["behavior"] == assertion[1]


def test_unknown_harnesses_share_one_bounded_capacity_bucket(tmp_path: Path) -> None:
    daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
    try:
        capacity_harnesses = {
            daemon._server.canonical_hook_capacity_harness(f"unknown-{index}") for index in range(1_000)
        }
    finally:
        daemon._server.server_close()

    assert capacity_harnesses == {"other"}


def test_partial_start_failure_rolls_back_workers_state_and_owner_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    original_start_maintenance = daemon._start_command_activity_maintenance
    started_threads: list[threading.Thread] = []

    def fail_after_all_background_workers_start() -> None:
        original_start_maintenance()
        started_threads.extend(
            thread
            for thread in (
                daemon._watchdog_thread,
                daemon._bundle_refresh_thread,
                daemon._aibom_refresh_thread,
                daemon._headless_cloud_sync_thread,
                daemon._command_activity_maintenance_thread,
                daemon._server.runtime_heartbeat._thread,
                daemon._server.unclassified_watchdog_thread,
                daemon._server.approval_attention._thread,
            )
            if thread is not None
        )
        raise RuntimeError("injected partial startup failure")

    monkeypatch.setattr(
        daemon,
        "_start_command_activity_maintenance",
        fail_after_all_background_workers_start,
    )
    with pytest.raises(RuntimeError, match="injected partial startup failure"):
        daemon.start()

    assert started_threads
    assert all(not thread.is_alive() for thread in started_threads)
    assert daemon._owner_lock is None
    assert daemon._server.hook_process_runner.stats()["workers"] == 0
    assert daemon._server.runtime_heartbeat._thread is None
    assert daemon._server.unclassified_watchdog_thread is None
    assert daemon._server.approval_attention._thread is None
    assert daemon._watchdog_thread is None
    assert daemon._bundle_refresh_thread is None
    assert daemon._aibom_refresh_thread is None
    assert daemon._headless_cloud_sync_thread is None
    assert daemon._command_activity_maintenance_thread is None
    assert daemon._command_queue_worker is None
    assert daemon._live_request_sync_worker is None
    assert store.get_runtime_state() is None

    owner_lock = daemon_manager.acquire_guard_daemon_owner_lock(store.guard_home)
    daemon_manager.release_guard_daemon_owner_lock(owner_lock)

    monkeypatch.setattr(
        daemon,
        "_start_command_activity_maintenance",
        original_start_maintenance,
    )
    try:
        daemon.start()
        assert daemon._thread is not None
        assert daemon._thread.is_alive()
    finally:
        daemon.stop()


def test_partial_start_retains_owner_until_worker_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        daemon_manager,
        "_guard_daemon_process_inventory_for_guard_home",
        lambda _guard_home: [],
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0, idle_timeout_seconds=0)
    close_runner = daemon._server.hook_process_runner.close_contained

    def fail_startup() -> None:
        raise RuntimeError("injected partial startup failure")

    monkeypatch.setattr(daemon._server.hook_process_runner, "close_contained", lambda: False)
    monkeypatch.setattr(daemon, "_start_watchdog", fail_startup)
    try:
        with pytest.raises(RuntimeError, match="injected partial startup failure"):
            daemon.start()

        assert daemon._owner_lock is not None
        with pytest.raises(RuntimeError, match="already active"):
            daemon_manager.acquire_guard_daemon_owner_lock(store.guard_home)
        assert daemon._server.hook_process_runner.stats()["workers"] > 0
        assert daemon._server.runtime_heartbeat._thread is None
        assert store.get_runtime_state() is None
    finally:
        monkeypatch.setattr(daemon._server.hook_process_runner, "close_contained", close_runner)
        assert daemon._finish_service()
        daemon._server.server_close()
