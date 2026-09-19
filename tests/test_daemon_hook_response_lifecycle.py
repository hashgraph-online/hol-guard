"""A consumed challenge releases its response while retaining the authenticated socket."""

from __future__ import annotations

import http.client
import io
import time
from collections.abc import Iterator

import pytest

from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import (
    _DaemonResponseError,
    _http_json_response,
)


class _ResponseSocket:
    def __init__(self, responses: Iterator[bytes]) -> None:
        self.responses = responses
        self.closed = False

    def makefile(self, _mode: str) -> io.BytesIO:
        return io.BytesIO(next(self.responses))

    def sendall(self, _data: bytes) -> None:
        assert not self.closed

    def settimeout(self, _timeout: float) -> None:
        assert not self.closed

    def close(self) -> None:
        self.closed = True


def _wire_response(body: bytes, status: int = 200) -> bytes:
    return (
        f"HTTP/1.1 {status} response\r\nContent-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode() + body


@pytest.mark.parametrize(
    ("body", "status", "failure"),
    [
        (b'{"ok":true}', 200, None),
        (b"malformed", 200, ValueError),
        (b'{"error":"denied"}', 403, _DaemonResponseError),
        (b"x" * 1_000_001, 200, ValueError),
    ],
    ids=["valid", "malformed-json", "error-status", "oversize"],
)
def test_json_response_closes_reader_and_preserves_same_connection(
    body: bytes,
    status: int,
    failure: type[Exception] | None,
) -> None:
    socket = _ResponseSocket(iter([_wire_response(body, status), _wire_response(b'{"second":true}')]))
    connection = http.client.HTTPConnection("127.0.0.1")
    connection.sock = socket  # type: ignore[assignment]
    try:
        connection.request("POST", "/challenge", body=b"{}")
        response = connection.getresponse()
        if failure is None:
            assert _http_json_response(
                response, label="challenge", connection=connection,
                deadline=time.monotonic() + 2, authenticated=False,
            ) == {"ok": True}
        else:
            with pytest.raises(failure):
                _http_json_response(
                    response, label="challenge", connection=connection,
                    deadline=time.monotonic() + 2, authenticated=False,
                )
        assert response.closed
        assert connection.sock is socket
        assert socket.closed is False
        if failure is None:
            connection.request("POST", "/hook", body=b"{}")
            assert _http_json_response(
                connection.getresponse(), label="hook", connection=connection,
                deadline=time.monotonic() + 2, authenticated=True,
            ) == {"second": True}
    finally:
        connection.close()


def test_json_response_deadline_closes_reader_without_waiting_for_body() -> None:
    socket = _ResponseSocket(iter([_wire_response(b'{"ok":true}')]))
    connection = http.client.HTTPConnection("127.0.0.1")
    connection.sock = socket  # type: ignore[assignment]
    try:
        connection.request("POST", "/challenge", body=b"{}")
        response = connection.getresponse()
        with pytest.raises(TimeoutError, match="exceeded the hook deadline"):
            _http_json_response(
                response, label="challenge", connection=connection,
                deadline=time.monotonic() - 1, authenticated=False,
            )
        assert response.closed
        assert connection.sock is socket
    finally:
        connection.close()
