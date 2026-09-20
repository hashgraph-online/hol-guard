"""HTTP bind metadata must not perform a resolver lookup during startup."""

from __future__ import annotations

import socket
from http.server import BaseHTTPRequestHandler
from socketserver import TCPServer

import pytest

from codex_plugin_scanner.guard.daemon.bounded_http import BoundedThreadingHTTPServer


@pytest.mark.parametrize("address", (("127.0.0.1", 4781), ("::1", 4782, 0, 0)))
def test_bind_preserves_bound_address_and_port_without_reverse_dns(
    monkeypatch: pytest.MonkeyPatch, address: tuple[str, int] | tuple[str, int, int, int]
) -> None:
    server = BoundedThreadingHTTPServer.__new__(BoundedThreadingHTTPServer)
    called = []

    def bind(instance: TCPServer) -> None:
        called.append(instance)
        instance.server_address = address

    def forbidden(*_args: object) -> str:
        raise AssertionError("local bind attempted reverse DNS")

    monkeypatch.setattr(TCPServer, "server_bind", bind)
    monkeypatch.setattr(socket, "getfqdn", forbidden)
    monkeypatch.setattr(socket, "gethostbyaddr", forbidden)
    server.server_bind()
    assert called == [server]
    assert server.server_name == address[0]
    assert server.server_port == address[1]


def test_real_listener_uses_bound_port_without_reverse_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object) -> str:
        raise AssertionError("local bind attempted reverse DNS")

    monkeypatch.setattr(socket, "getfqdn", forbidden)
    monkeypatch.setattr(socket, "gethostbyaddr", forbidden)
    try:
        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    except PermissionError:
        pytest.skip("host does not permit local listener or socketpair creation")
    try:
        assert server.server_name == "127.0.0.1"
        assert server.server_port == server.socket.getsockname()[1]
        assert server.server_port > 0
    finally:
        server.server_close()
