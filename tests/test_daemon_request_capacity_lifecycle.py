"""Actual HTTP request permits end before socket teardown or keep-alive waiting."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

import json
import socket
import threading
from collections.abc import Generator
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager, server
from codex_plugin_scanner.guard.daemon.discovery import (
    DAEMON_DISCOVERY_PROTOCOL_VERSION,
    load_authenticated_daemon_state,
)
from codex_plugin_scanner.guard.store import GuardStore


@contextmanager
def running_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[server.GuardDaemonServer]:
    def inventory(_home: Path) -> list[tuple[int, int]]:
        return []

    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", inventory)
    daemon = server.GuardDaemonServer(
        GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0, idle_timeout_seconds=0
    )
    daemon.start()
    try:
        yield daemon
    finally:
        daemon.stop()


def read_response(connection: HTTPConnection) -> tuple[int, bytes]:
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        response.close()


def general_request(port: int) -> int:
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", "/v1/capacity-fixture-missing")
        status, _ = read_response(connection)
        return status
    finally:
        connection.close()


def test_completed_request_releases_handler_slot_before_socket_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with running_daemon(tmp_path, monkeypatch) as daemon:
        http = daemon._server
        http.request_capacity = threading.BoundedSemaphore(1)
        http.request_capacity_limit = 1
        cleanup_entered = threading.Event()
        cleanup_release = threading.Event()
        original_shutdown = http.shutdown_request
        first_socket: list[socket.socket] = []

        def delayed_shutdown(request: socket.socket) -> None:
            if not first_socket:
                first_socket.append(request)
                cleanup_entered.set()
                assert cleanup_release.wait(5), "test must release actual socket cleanup"
            original_shutdown(request)

        monkeypatch.setattr(http, "shutdown_request", delayed_shutdown)
        try:
            assert general_request(daemon.port) == 401
            assert cleanup_entered.wait(2)
            with http.request_capacity_lock:
                assert id(first_socket[0]) in http.active_connections
                assert http.active_requests >= 1
            # The first response has been read completely; its connection still
            # consumes the independent socket limit until actual teardown.
            assert general_request(daemon.port) == 401
        finally:
            cleanup_release.set()


def test_identity_keep_alive_does_not_hold_critical_request_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with running_daemon(tmp_path, monkeypatch) as daemon:
        http = daemon._server
        http.critical_request_capacity = threading.BoundedSemaphore(1)
        http.critical_request_capacity_limit = 1
        state = load_authenticated_daemon_state(http.store.guard_home)
        assert state is not None
        connection = HTTPConnection("127.0.0.1", daemon.port, timeout=2)
        try:
            connection.request(
                "POST",
                "/v1/daemon/identity-challenge",
                body=json.dumps(
                    {
                        "nonce": "a" * 64,
                        "hook_event": "PreToolUse",
                        "state_id": state["state_id"],
                        "protocol_version": DAEMON_DISCOVERY_PROTOCOL_VERSION,
                    }
                ),
                headers={"Content-Type": "application/json"},
            )
            status, body = read_response(connection)
            assert status == 200
            assert json.loads(body)["nonce"] == "a" * 64
            original_socket = connection.sock
            assert original_socket is not None
            health = HTTPConnection("127.0.0.1", daemon.port, timeout=2)
            try:
                health.request("GET", "/healthz")
                assert read_response(health)[0] == 200
            finally:
                health.close()
            # The existing connection remains usable and does not gain authority.
            connection.request("GET", "/v1/capacity-fixture-missing")
            assert connection.sock is original_socket
            assert read_response(connection)[0] == 401
        finally:
            connection.close()


def test_inflight_handler_still_owns_capacity_and_recovers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with running_daemon(tmp_path, monkeypatch) as daemon:
        http = daemon._server
        http.request_capacity = threading.BoundedSemaphore(1)
        http.request_capacity_limit = 1
        entered = threading.Event()
        release = threading.Event()
        original_get = server._GuardDaemonHandler.do_GET

        def held_get(handler: server._GuardDaemonHandler) -> None:
            if handler.path == "/v1/capacity-held-fixture":
                entered.set()
                assert release.wait(5), "test must release the active handler"
            original_get(handler)

        monkeypatch.setattr(server._GuardDaemonHandler, "do_GET", held_get)
        connection = HTTPConnection("127.0.0.1", daemon.port, timeout=2)
        try:
            connection.request("GET", "/v1/capacity-held-fixture")
            assert entered.wait(2)
            assert general_request(daemon.port) == 503
            release.set()
            assert read_response(connection)[0] == 401
            assert general_request(daemon.port) == 401
        finally:
            release.set()
            connection.close()
