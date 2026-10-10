"""Real loopback HTTP: chunked bodies and the truncated-body retry share one byte budget and deadline."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard.daemon.client import (
    GuardDaemonRequestError,
    GuardDaemonResponseSchemaError,
    GuardDaemonTimeoutError,
    GuardDaemonTransportError,
    GuardSurfaceDaemonClient,
)

# Each callable writes one complete raw HTTP response for the request it serves.
Responder = Callable[[BaseHTTPRequestHandler], None]


def _json_of_size(size: int) -> bytes:
    body = json.dumps({"pad": ""}).encode()
    padded = json.dumps({"pad": "x" * (size - len(body))}).encode()
    assert len(padded) == size
    return padded


def _chunked(body: bytes, *, chunk: int = 4096) -> Responder:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        )
        for start in range(0, len(body), chunk):
            part = body[start : start + chunk]
            handler.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        handler.wfile.write(b"0\r\n\r\n")

    return respond


def _truncated(body: bytes) -> Responder:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.wfile.write(
            f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        handler.wfile.write(body[: len(body) // 2])

    return respond


def _http_error(status: int, body: bytes) -> Responder:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.wfile.write(
            f"HTTP/1.1 {status} ERR\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        )
        handler.wfile.write(body)

    return respond


def _complete(body: bytes, *, delay: float = 0.0) -> Responder:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        time.sleep(delay)
        handler.wfile.write(
            f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        handler.wfile.write(body)

    return respond


@contextmanager
def _server(*responders: Responder) -> Iterator[tuple[GuardSurfaceDaemonClient, list[str]]]:
    queue = list(responders)
    served: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            served.append(self.path)
            queue.pop(0)(self)
            self.close_connection = True

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return None

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield GuardSurfaceDaemonClient(f"http://127.0.0.1:{httpd.server_address[1]}", "token"), served
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(5)


CAP = 65_536 * 3 + 17


def test_chunked_body_at_the_cap_is_accepted() -> None:
    with _server(_chunked(_json_of_size(CAP))) as (client, served):
        assert client._get("/v1/x", timeout=10, max_bytes=CAP) == json.loads(_json_of_size(CAP))
    assert served == ["/v1/x"]


def test_chunked_body_one_byte_over_the_cap_is_refused() -> None:
    with (
        _server(_chunked(_json_of_size(CAP + 1))) as (client, _served),
        pytest.raises(GuardDaemonResponseSchemaError, match="exceeded the size limit"),
    ):
        client._get("/v1/x", timeout=10, max_bytes=CAP)


def test_truncated_body_is_retried_once_under_the_same_budget() -> None:
    body = _json_of_size(CAP)
    with _server(_truncated(body), _complete(body)) as (client, served):
        assert client._get("/v1/x", timeout=10, max_bytes=CAP) == json.loads(body)
    assert served == ["/v1/x", "/v1/x"]


def test_retry_body_over_the_cap_is_refused() -> None:
    with (
        _server(_truncated(_json_of_size(CAP)), _complete(_json_of_size(CAP + 1))) as (client, _served),
        pytest.raises(GuardDaemonResponseSchemaError, match="exceeded the size limit"),
    ):
        client._get("/v1/x", timeout=10, max_bytes=CAP)


def test_second_truncation_fails_without_a_third_request() -> None:
    body = _json_of_size(CAP)
    with (
        _server(_truncated(body), _truncated(body), _complete(body)) as (client, served),
        pytest.raises(GuardDaemonTransportError, match="truncated"),
    ):
        client._get("/v1/x", timeout=10, max_bytes=CAP)
    assert served == ["/v1/x", "/v1/x"]


def test_retry_http_error_keeps_status_and_code() -> None:
    body = _json_of_size(1024)
    error_body = json.dumps({"error": "daemon_busy", "recovery": {"action": "retry"}}).encode()
    with (
        _server(_truncated(body), _http_error(503, error_body)) as (client, served),
        pytest.raises(GuardDaemonRequestError) as caught,
    ):
        client._get("/v1/x", timeout=10, max_bytes=CAP)
    assert served == ["/v1/x", "/v1/x"]
    error = caught.value
    assert type(error) is GuardDaemonRequestError
    assert error.status == 503
    assert error.code == "daemon_busy"
    assert error.recovery_action == "retry"


def test_retry_shares_the_original_deadline() -> None:
    body = _json_of_size(1024)
    with _server(_truncated(body), _complete(body, delay=3.0)) as (client, _served):
        started = time.monotonic()
        with pytest.raises(GuardDaemonTimeoutError):
            client._get("/v1/x", timeout=1.0, max_bytes=CAP)
        assert time.monotonic() - started < 2.0
