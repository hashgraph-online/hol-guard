from __future__ import annotations

import json
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_session as session_module


def _daemon(port: int = 12345) -> session_module.GuardDaemonServer:
    return cast(
        session_module.GuardDaemonServer,
        SimpleNamespace(port=port, _server=SimpleNamespace(auth_token="fixture-auth")),
    )


def _request(daemon: session_module.GuardDaemonServer, tmp_path: Path) -> object:
    return session_module._request(
        daemon,
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        harness="cursor",
        request_payload={"hook_event_name": "PostToolUse"},
    )


def test_concurrent_transport_opens_fresh_authenticated_loopback_connections_without_proxies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[tuple[str, str | None, bytes]] = []
    connections: list[HTTPConnection] = []
    ready = threading.Barrier(4, timeout=5)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, self.headers.get("X-Guard-Token"), body))
            response = b'{"decision":"allow"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args: object) -> None:
            pass

    def unexpected_proxy(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("loopback transport consulted proxy settings")

    def connection(host: str, port: int, *, timeout: int) -> HTTPConnection:
        assert host == "127.0.0.1"
        assert timeout == 5
        created = HTTPConnection(host, port, timeout=timeout)
        connections.append(created)
        ready.wait()
        return created

    monkeypatch.setattr(urllib.request, "getproxies", unexpected_proxy)
    monkeypatch.setattr(urllib.request, "urlopen", unexpected_proxy)
    monkeypatch.setattr(session_module, "HTTPConnection", connection)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
    thread.start()
    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_request, _daemon(server.server_port), tmp_path) for _ in range(4)]
            assert [future.result(timeout=5) for future in futures] == [{"decision": "allow"}] * 4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert len(connections) == 4
    assert len({id(connection) for connection in connections}) == 4
    assert all(connection.sock is None for connection in connections)
    assert len(requests) == 4
    for path, auth, body in requests:
        assert path.startswith("/v1/hooks/cursor?home=")
        assert "workspace=" in path
        assert auth == "fixture-auth"
        assert json.loads(body) == {"hook_event_name": "PostToolUse"}


@pytest.mark.parametrize(
    ("status", "body", "failure"),
    [
        (200, b'{"decision":"allow"}', None),
        (503, b"busy", None),
        (500, b'{"decision":"allow"}', "adapter request failed"),
        (302, b'{"decision":"allow"}', "adapter request failed"),
        (200, b"x" * 33, "adapter response exceeded bound"),
        (200, b"invalid", "adapter response was not JSON"),
        (200, b"[]", "adapter response was not an object"),
    ],
)
def test_loopback_response_status_and_body_bounds_close_owned_connections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    body: bytes,
    failure: str | None,
) -> None:
    closed: list[str] = []
    reads: list[int] = []
    response = SimpleNamespace(
        status=status,
        read=lambda limit: reads.append(limit) or body,
        close=lambda: closed.append("response"),
    )
    connection = SimpleNamespace(
        request=lambda *_args, **_kwargs: None,
        getresponse=lambda: response,
        close=lambda: closed.append("connection"),
    )
    monkeypatch.setattr(session_module, "HTTPConnection", lambda *_args, **_kwargs: connection)
    monkeypatch.setattr(session_module, "_MAX_HTTP_RESPONSE_BYTES", 32)
    if failure is not None:
        with pytest.raises(RuntimeError, match=failure):
            _request(_daemon(), tmp_path)
    elif status == 503:
        assert _request(_daemon(), tmp_path) == session_module._CAPACITY_FAIL_SAFE
    else:
        assert _request(_daemon(), tmp_path) == {"decision": "allow"}
    assert reads == [33]
    assert closed == ["response", "connection"]


@pytest.mark.parametrize("stage", ["request", "read", "close"])
def test_loopback_transport_failure_closes_owned_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    closed: list[str] = []

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("fixture transport error")

    def close_response() -> None:
        closed.append("response")
        if stage == "close":
            fail()

    response = SimpleNamespace(
        status=200,
        read=fail if stage == "read" else lambda _limit: b"{}",
        close=close_response,
    )
    connection = SimpleNamespace(
        request=fail if stage == "request" else lambda *_args, **_kwargs: None,
        getresponse=lambda: response,
        close=lambda: closed.append("connection"),
    )
    monkeypatch.setattr(session_module, "HTTPConnection", lambda *_args, **_kwargs: connection)
    with pytest.raises(RuntimeError, match="adapter request failed"):
        _request(_daemon(), tmp_path)
    assert closed == (["connection"] if stage == "request" else ["response", "connection"])


def test_loopback_transport_preserves_session_owned_connection() -> None:
    closed: list[str] = []
    response = SimpleNamespace(status=200, read=lambda _limit: b"{}", close=lambda: closed.append("response"))
    connection = SimpleNamespace(
        request=lambda *_args, **_kwargs: None,
        getresponse=lambda: response,
        close=lambda: closed.append("connection"),
    )
    assert session_module._loopback_response(
        _daemon(), path="/v1/hooks/cursor", encoded="{}", connection=cast(HTTPConnection, connection)
    ) == (200, b"{}")
    assert closed == ["response"]
