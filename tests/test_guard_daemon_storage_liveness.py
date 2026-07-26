from __future__ import annotations

import json
import socket
import sqlite3
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.client import HTTPResponse
from pathlib import Path
from types import SimpleNamespace
from typing import TypeGuard, cast, final

import pytest

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.discovery import (
    DAEMON_DISCOVERY_PROTOCOL_VERSION,
    load_authenticated_daemon_state,
)
from codex_plugin_scanner.guard.daemon.runtime_heartbeat import RuntimeHeartbeatWriter
from codex_plugin_scanner.guard.daemon.server import (
    GuardDaemonServer,
    _GuardDaemonHttpServer,
)
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_seconds
from codex_plugin_scanner.guard.store import GuardStore


def _is_string_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in cast(dict[object, object], value))


def _open_json(
    request: str | urllib.request.Request,
    *,
    timeout_seconds: float = 1,
) -> tuple[dict[str, object], float]:
    started = time.monotonic()
    with cast(HTTPResponse, urllib.request.urlopen(request, timeout=timeout_seconds)) as response:
        raw_payload = cast(object, json.loads(response.read().decode("utf-8")))
    assert _is_string_object_dict(raw_payload)
    return raw_payload, time.monotonic() - started


def test_critical_daemon_liveness_does_not_wait_for_locked_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def empty_inventory(_home: Path) -> list[tuple[int, int]]:
        return []

    monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", empty_inventory)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    blocker = sqlite3.connect(store.path, timeout=0.1, isolation_level=None)

    try:
        initial_runtime = store.get_runtime_state()
        assert initial_runtime is not None
        initial_heartbeat = str(initial_runtime["last_heartbeat_at"])
        state = load_authenticated_daemon_state(store.guard_home)
        assert state is not None
        _ = blocker.execute("begin exclusive")

        health, health_elapsed = _open_json(f"http://127.0.0.1:{daemon.port}/healthz")
        identity_request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/daemon/identity-challenge",
            data=json.dumps(
                {
                    "nonce": "a" * 64,
                    "hook_event": "PreToolUse",
                    "state_id": state["state_id"],
                    "protocol_version": DAEMON_DISCOVERY_PROTOCOL_VERSION,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        identity, identity_elapsed = _open_json(identity_request)

        assert health["ok"] is True
        assert isinstance(identity.get("proof"), str)
        assert health_elapsed < 0.25
        assert identity_elapsed < 0.25

        _ = blocker.execute("rollback")
        deadline = time.monotonic() + 2
        persisted_heartbeat = initial_heartbeat
        while time.monotonic() < deadline:
            runtime = store.get_runtime_state()
            assert runtime is not None
            persisted_heartbeat = str(runtime["last_heartbeat_at"])
            if datetime.fromisoformat(persisted_heartbeat) > datetime.fromisoformat(initial_heartbeat):
                break
            time.sleep(0.02)
        assert datetime.fromisoformat(persisted_heartbeat) > datetime.fromisoformat(initial_heartbeat)
    finally:
        if blocker.in_transaction:
            blocker.rollback()
        blocker.close()
        daemon.stop()


def test_locked_storage_hook_burst_fails_safe_without_stranding_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def empty_inventory(_home: Path) -> list[tuple[int, int]]:
        return []

    monkeypatch.setattr(
        daemon_manager_module,
        "_guard_daemon_process_inventory_for_guard_home",
        empty_inventory,
    )
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    blocker = sqlite3.connect(store.path, timeout=0.1, isolation_level=None)
    _ = blocker.execute("begin exclusive")
    endpoint = (
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?guard-home={store.guard_home}&home={tmp_path}&workspace={tmp_path}"
    )

    def review(index: int) -> tuple[dict[str, object], float]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": f"echo bounded-{index}"},
                }
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Guard-Token": daemon._server.auth_token,  # pyright: ignore[reportPrivateUsage]
            },
            method="POST",
        )
        return _open_json(request, timeout_seconds=1.75)

    try:
        with ThreadPoolExecutor(max_workers=24) as executor:
            futures = [executor.submit(review, index) for index in range(24)]
            health, health_elapsed = _open_json(f"http://127.0.0.1:{daemon.port}/healthz")
            results = [future.result(timeout=2) for future in futures]
        assert health["ok"] is True
        assert health_elapsed < 0.25
        assert max(elapsed for _payload, elapsed in results) < 1.6
        assert all(payload.get("decision") == "deny" for payload, _elapsed in results)
        assert daemon._server.active_hook_requests == 0  # pyright: ignore[reportPrivateUsage]
    finally:
        blocker.rollback()
        blocker.close()

    try:
        assert daemon._server.hook_process_runner.wait_for_capacity(  # pyright: ignore[reportPrivateUsage]
            minimum_workers=1,
            timeout_seconds=15,
        )
        worker_stats = daemon._server.hook_process_runner.stats()  # pyright: ignore[reportPrivateUsage]
        resumed_payload, resumed_elapsed = review(100)
        assert worker_stats["timeouts"] == 0
        assert worker_stats["ready"] >= 1
        assert resumed_payload.get("policy_action") in {"allow", "warn"}
        assert resumed_elapsed < 1.0
    finally:
        daemon.stop()


def test_runtime_heartbeat_writer_coalesces_pending_updates() -> None:
    @final
    class DelayedStore:
        def __init__(self) -> None:
            self.attempts: list[str] = []
            self.allow_write: bool = False

        def try_touch_runtime_state(
            self,
            *,
            session_id: str,
            last_heartbeat_at: str,
            timeout_seconds: float,
        ) -> bool:
            assert session_id == "session"
            assert timeout_seconds == 0.01
            self.attempts.append(last_heartbeat_at)
            return self.allow_write

    store = DelayedStore()
    writer = RuntimeHeartbeatWriter(
        store=store,
        session_id="session",
        write_timeout_seconds=0.01,
        retry_interval_seconds=0.01,
    )
    writer.start()
    try:
        for index in range(100):
            writer.touch(f"heartbeat-{index}")
        deadline = time.monotonic() + 1
        while not store.attempts and time.monotonic() < deadline:
            time.sleep(0.005)
        store.allow_write = True
        writer.touch("heartbeat-final")
        deadline = time.monotonic() + 1
        while (not store.attempts or store.attempts[-1] != "heartbeat-final") and time.monotonic() < deadline:
            time.sleep(0.005)
    finally:
        writer.stop()

    assert store.attempts[-1] == "heartbeat-final"
    assert len(store.attempts) < 20


def test_bounded_runtime_heartbeat_connection_closes_after_write_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    closed = False

    @final
    class FailingConnection:
        def execute(
            self,
            _statement: str,
            _parameters: tuple[object, ...] = (),
        ) -> None:
            raise sqlite3.OperationalError("database is locked")

        def close(self) -> None:
            nonlocal closed
            closed = True

    def failing_connect(*_args: object, **_kwargs: object) -> FailingConnection:
        return FailingConnection()

    monkeypatch.setattr(sqlite3, "connect", failing_connect)

    assert not store.try_touch_runtime_state(
        session_id="session",
        last_heartbeat_at="2026-07-25T00:00:00+00:00",
        timeout_seconds=0.01,
    )
    assert closed


def test_internal_hook_sqlite_timeout_is_bounded_without_changing_default() -> None:
    assert sqlite_connect_timeout_seconds({}) == 30.0
    assert sqlite_connect_timeout_seconds({"HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS": "125"}) == 0.125
    assert sqlite_connect_timeout_seconds({"HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS": "10000"}) == 0.25
    assert sqlite_connect_timeout_seconds({"HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS": "invalid"}) == 30.0
    assert sqlite_connect_timeout_seconds({"HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS": "0"}) == 30.0


def test_unclassified_watchdog_distinguishes_complete_headers_from_trickle() -> None:
    if not hasattr(socket, "MSG_DONTWAIT"):
        pytest.skip("nonblocking socket peeking is unavailable")
    server_socket, client_socket = socket.socketpair()
    try:
        client_socket.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert _GuardDaemonHttpServer._buffered_request_headers_complete(server_socket) is True
        _ = server_socket.recv(65_536)
        client_socket.sendall(b"GET /healthz HTTP/1.1\r\nHost:")
        assert _GuardDaemonHttpServer._buffered_request_headers_complete(server_socket) is False
    finally:
        server_socket.close()
        client_socket.close()


def test_storage_maintenance_failure_requests_immediate_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingStore:
        guard_home = tmp_path

        @staticmethod
        def maintain_storage(**_kwargs: object) -> None:
            raise sqlite3.OperationalError("database is locked")

    daemon = object.__new__(GuardDaemonServer)
    object.__setattr__(daemon, "_server", SimpleNamespace(store=FailingStore()))
    monkeypatch.setattr(
        daemon_server_module,
        "load_guard_config",
        lambda _guard_home: SimpleNamespace(evidence_retain_days=30),
    )

    assert daemon._maintain_storage_best_effort() is False  # pyright: ignore[reportPrivateUsage]
