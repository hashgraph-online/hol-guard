"""Authenticated daemon health stays within the audited loopback transport boundary."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard.daemon import client, live_identity


@pytest.mark.security_critical
@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, b'{"ok":true}', {"ok": True}),
        (302, b'{"ok":true}', None),
        (500, b'{"ok":true}', None),
        (200, b"[]", None),
        (200, b"not-json", None),
        (200, b"\xff", None),
        (200, b" " * 65_537, None),
    ],
)
def test_health_probe_is_bounded_proxy_free_and_does_not_follow_redirects(
    monkeypatch: pytest.MonkeyPatch, status: int, body: bytes, expected: object
) -> None:
    """Use a real loopback server to verify token delivery and refusal of unsafe responses."""
    requests: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Return the selected response and record any attempted redirect follow-up."""
            requests.append((self.path, self.headers.get("X-Guard-Token")))
            self.send_response(status)
            self.send_header("Location", "/redirected")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, message_format: str, *args: object) -> None:
            """Keep the test server's expected error statuses out of console output."""

    for key in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            assert live_identity._proxy_disabled_health_details(url, "test-token") == expected
            assert requests == [("/v1/healthz/details", "test-token")]
        finally:
            server.shutdown()
            thread.join(timeout=2)


@pytest.mark.security_critical
@pytest.mark.parametrize(
    "url",
    [
        "http://example.test:1234",
        "https://127.0.0.1:1234",
        "http://127.0.0.1",
        "http://user:password@127.0.0.1:1234",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:1234/wrong-path",
        "http://127.0.0.1:1234?redirect=external",
        "http://[::1]:1234#fragment",
    ],
)
def test_health_probe_rejects_invalid_authorities_before_connecting(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    """Malformed and non-loopback URLs must not open a socket with the daemon token."""

    def unexpected_connection(*args: object, **kwargs: object) -> None:
        """Fail immediately if URL validation allows a network connection."""
        pytest.fail("Invalid daemon authority reached the network transport")

    monkeypatch.setattr(client, "HTTPConnection", unexpected_connection)
    assert client.read_guard_health_details(url, "test-token") is None


@pytest.mark.security_critical
@pytest.mark.parametrize("drip_headers", [False, True])
def test_health_probe_enforces_deadline_against_byte_drip(monkeypatch: pytest.MonkeyPatch, drip_headers: bool) -> None:
    """Neither a partial header nor a slowly arriving body can extend the total deadline."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Drip bytes more frequently than the socket timeout until the client closes."""
            if not drip_headers:
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.04)
            except OSError:
                pass  # The deadline deliberately closes the client connection.

        def log_message(self, message_format: str, *args: object) -> None:
            """Suppress expected loopback-test access logs."""

    monkeypatch.setattr(client, "_HEALTH_PROBE_DEADLINE_SECONDS", 0.2)
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            result = client.read_guard_health_details(f"http://127.0.0.1:{server.server_port}", "test-token")
            elapsed = time.monotonic() - started
            assert result is None
            assert elapsed < 1.0
        finally:
            server.shutdown()
            thread.join(timeout=2)
