"""Response ownership must not depend on read1 closing at Content-Length zero."""

import http.client
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth as auth


class Response:
    def __init__(self, body: bytes, status: int = 200):
        self.body = body
        self.status = status
        self.closed = False

    def read1(self, size: int) -> bytes:
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


class Connection:
    sock = None


@pytest.mark.parametrize(
    ("body", "status", "error"),
    [(b'{"ok": true}', 200, None), (b"not json", 200, ValueError), (b"forbidden", 403, auth._DaemonResponseError)],
)
def test_reader_closes_owned_response(body, status, error):
    response = Response(body, status)
    arguments = dict(label="challenge", connection=Connection(), deadline=time.monotonic() + 10, authenticated=False)
    if error is None:
        assert auth._http_json_response(response, **arguments) == {"ok": True}
    else:
        with pytest.raises(error):
            auth._http_json_response(response, **arguments)
    assert response.closed


def test_reader_closes_response_on_expired_deadline():
    response = Response(b"{}")
    with pytest.raises(TimeoutError):
        auth._http_json_response(
            response, label="challenge", connection=Connection(), deadline=time.monotonic() - 1, authenticated=False
        )
    assert response.closed


def test_reader_closes_oversized_response(monkeypatch):
    monkeypatch.setattr(auth, "_MAX_DAEMON_RESPONSE_BYTES", 16)
    response = Response(b"x" * 17)
    with pytest.raises(ValueError, match="too large"):
        auth._http_json_response(
            response,
            label="challenge",
            connection=Connection(),
            deadline=time.monotonic() + 5,
            authenticated=False,
        )
    assert response.closed


def test_reader_closes_response_on_read_error():
    class BrokenResponse(Response):
        def read1(self, size):
            raise OSError("read failed")

    response = BrokenResponse(b"")
    with pytest.raises(OSError, match="read failed"):
        auth._http_json_response(
            response,
            label="challenge",
            connection=Connection(),
            deadline=time.monotonic() + 5,
            authenticated=False,
        )
    assert response.closed


def test_authenticated_followup_reuses_same_socket():
    ports = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            ports.append(self.client_address[1])
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class RetainedResponse(http.client.HTTPResponse):
        # Reproduce Python 3.10's read1 lifecycle on newer interpreters too.
        def _close_conn(self):
            pass

        def close(self):
            if self.fp is not None:
                http.client.HTTPResponse._close_conn(self)
            super().close()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    connection.response_class = RetainedResponse
    try:
        for path in ("/challenge", "/authenticated-hook"):
            connection.request("GET", path)
            assert auth._http_json_response(
                connection.getresponse(),
                label=path,
                connection=connection,
                deadline=time.monotonic() + 5,
                authenticated=path != "/challenge",
            ) == {"ok": True}
        assert len(ports) == 2 and ports[0] == ports[1]
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
