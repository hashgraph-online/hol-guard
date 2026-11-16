"""Pooled connections for authenticated Guard requests."""

from __future__ import annotations

import http.client
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard.mdm import network_keepalive
from codex_plugin_scanner.no_redirect import RejectRedirects


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.peers: list[tuple[str, int]] = []
        self.paths: list[str] = []
        self.drop_next_idle = False


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.peers.append(self.client_address)
        self.server.paths.append(self.path)
        if self.path == "/vanish":
            self.close_connection = True
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status = 403 if self.path == "/forbidden" else 200
        payload = json.dumps({"path": self.path, "echo": body.decode()}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        if self.server.drop_next_idle:
            self.server.drop_next_idle = False
            self.close_connection = True


class _KeepAliveHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pool: network_keepalive._ConnectionPool) -> None:
        super().__init__()
        self._pool = pool

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return network_keepalive.open_keepalive(
            req,
            key="test",
            connect=lambda host, timeout: http.client.HTTPConnection(host, timeout=timeout),
            pool=self._pool,
        )


@pytest.fixture
def server():
    instance = _Server()
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()


@pytest.fixture
def pool():
    instance = network_keepalive._ConnectionPool()
    yield instance
    instance.clear()


def _post(server: _Server, pool: network_keepalive._ConnectionPool, path: str, body: str = "{}") -> dict[str, object]:
    opener = urllib.request.build_opener(RejectRedirects(), _KeepAliveHTTPHandler(pool))
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.server_address[1]}{path}",
        data=body.encode(),
        method="POST",
        headers={"Authorization": "Bearer test", "Content-Type": "application/json"},
    )
    with opener.open(request, timeout=5) as response:
        return json.loads(response.read())


def test_sequential_requests_share_one_connection(server: _Server, pool: network_keepalive._ConnectionPool) -> None:
    assert _post(server, pool, "/lease", '{"a":1}') == {"path": "/lease", "echo": '{"a":1}'}
    assert _post(server, pool, "/ack")["path"] == "/ack"
    assert _post(server, pool, "/result")["path"] == "/result"

    assert len(server.peers) == 3
    assert len(set(server.peers)) == 1


def test_http_errors_keep_urllib_semantics_and_the_connection(
    server: _Server, pool: network_keepalive._ConnectionPool
) -> None:
    with pytest.raises(urllib.error.HTTPError) as caught:
        _post(server, pool, "/forbidden")
    assert caught.value.code == 403
    assert json.loads(caught.value.read())["path"] == "/forbidden"
    caught.value.close()

    assert _post(server, pool, "/after")["path"] == "/after"
    assert len(set(server.peers)) == 1


def test_redirects_are_still_rejected(server: _Server, pool: network_keepalive._ConnectionPool) -> None:
    with pytest.raises(urllib.error.HTTPError) as caught:
        _post(server, pool, "/redirect")
    assert caught.value.code == 302
    caught.value.close()


def test_a_socket_the_server_closed_is_replaced_once(server: _Server, pool: network_keepalive._ConnectionPool) -> None:
    server.drop_next_idle = True
    _post(server, pool, "/first")

    assert _post(server, pool, "/second")["path"] == "/second"
    assert [peer for peer in server.peers if peer] and len(set(server.peers)) == 2


def test_unread_bodies_are_not_returned_to_the_pool(server: _Server, pool: network_keepalive._ConnectionPool) -> None:
    opener = urllib.request.build_opener(_KeepAliveHTTPHandler(pool))
    request = urllib.request.Request(f"http://127.0.0.1:{server.server_address[1]}/unread", data=b"{}", method="POST")
    opener.open(request, timeout=5).close()

    assert _post(server, pool, "/next")["path"] == "/next"
    assert len(set(server.peers)) == 2


def test_idle_connections_expire(
    server: _Server, pool: network_keepalive._ConnectionPool, monkeypatch: pytest.MonkeyPatch
) -> None:
    _post(server, pool, "/first")
    monkeypatch.setattr(network_keepalive, "_IDLE_SECONDS", -1.0)

    _post(server, pool, "/second")
    assert len(set(server.peers)) == 2


def test_a_post_the_server_may_have_handled_is_not_sent_again(
    server: _Server, pool: network_keepalive._ConnectionPool
) -> None:
    _post(server, pool, "/first")

    with pytest.raises(urllib.error.URLError):
        _post(server, pool, "/vanish")
    assert server.paths.count("/vanish") == 1


def test_sockets_of_a_retired_key_are_closed(pool: network_keepalive._ConnectionPool) -> None:
    retired = http.client.HTTPConnection("127.0.0.1")
    closed: list[bool] = []
    retired.close = lambda: closed.append(True)  # type: ignore[method-assign]
    pool.give("old-context", retired)
    pool._idle["old-context"] = [(0.0, retired)]

    assert pool.take("new-context") is None
    assert closed == [True]
    assert "old-context" not in pool._idle
