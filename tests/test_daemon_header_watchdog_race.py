"""Header expiry must not close a request after its handler takes ownership."""

from __future__ import annotations

import http.client
import socket
import threading
from contextlib import suppress
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHttpServer


def _server(request: socket.socket) -> _GuardDaemonHttpServer:
    """Create a single-iteration watchdog with no worker or listener threads."""
    server = object.__new__(_GuardDaemonHttpServer)
    server.unclassified_connections = {id(request): (request, 0.0)}
    server.pending_classifications = {}
    server.saturation_probes = {}
    server.unclassified_connections_lock = threading.Lock()
    iterations = iter((False, True))
    server.unclassified_watchdog_stop = SimpleNamespace(wait=lambda _delay: next(iterations))
    return server


def test_classification_during_watchdog_peek_preserves_complete_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reproduce an accepted response losing its body to a stale expiry snapshot."""
    sender, receiver = socket.socketpair()
    receiver.settimeout(1)
    server = _server(sender)
    body = b'{"decision":"allow"}'

    def classification_won(request: socket.socket) -> bool:
        server.classify_connection(request)
        request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n")
        # The handler consumed the input headers; a subsequent peek finds none.
        return False

    monkeypatch.setattr(server, "_buffered_request_headers_complete", classification_won)
    try:
        server._watch_unclassified_connections()
        with suppress(OSError):
            sender.sendall(body)
        response = http.client.HTTPResponse(receiver)
        response.begin()
        assert response.read() == body
        assert server.unclassified_connections == {}
    finally:
        sender.close()
        receiver.close()


@pytest.mark.parametrize("headers_complete", [False, True])
def test_current_expiry_keeps_complete_headers_and_closes_trickle(
    monkeypatch: pytest.MonkeyPatch, headers_complete: bool
) -> None:
    """A real unclassified expiry remains bounded; complete buffered headers survive."""
    sender, receiver = socket.socketpair()
    receiver.settimeout(1)
    server = _server(sender)
    monkeypatch.setattr(server, "_buffered_request_headers_complete", lambda _request: headers_complete)
    try:
        server._watch_unclassified_connections()
        assert server.unclassified_connections == {}
        if headers_complete:
            sender.sendall(b"alive")
            assert receiver.recv(5) == b"alive"
        else:
            assert receiver.recv(1) == b""
    finally:
        sender.close()
        receiver.close()


def test_refreshed_registration_is_not_closed_by_earlier_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A later registration deadline invalidates the previously expired entry."""
    sender, receiver = socket.socketpair()
    receiver.settimeout(1)
    server = _server(sender)

    def refresh(request: socket.socket) -> bool:
        with server.unclassified_connections_lock:
            server.unclassified_connections[id(request)] = (request, float("inf"))
        return False

    monkeypatch.setattr(server, "_buffered_request_headers_complete", refresh)
    try:
        server._watch_unclassified_connections()
        sender.sendall(b"alive")
        assert receiver.recv(5) == b"alive"
        assert id(sender) in server.unclassified_connections
    finally:
        sender.close()
        receiver.close()
