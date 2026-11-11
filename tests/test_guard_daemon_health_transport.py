"""Authenticated daemon health stays within the audited loopback transport boundary."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard import native_daemon_client as client


def _authenticated_state(guard_home) -> dict[str, object]:
    return {
        "package_version": "3.0.181",
        "host": "127.0.0.1",
        "port": 24781,
        "pid": 321,
        "compatibility_version": 2,
        "runtime_fingerprint": "runtime-generation-1",
        "generation": "daemon-generation-1",
        "user": "uid:501",
        "start_marker": "process-start-1",
        "guard_home": str(guard_home),
    }


def _health_details(state: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "guard_home": state["guard_home"],
        "package_version": state["package_version"],
        "compatibility_version": state["compatibility_version"],
        "runtime_fingerprint": state["runtime_fingerprint"],
        "pid": state["pid"],
    }


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
def test_health_probe_rejects_invalid_authorities_before_connecting(url: str) -> None:
    """Malformed and non-loopback URLs must not open a socket with the daemon key.

    The native client refuses them before connecting (`only_loopback_daemon_urls_are_reached`).
    """

    assert client.read_guard_health_details(url, "test-token") is None


@pytest.mark.security_critical
@pytest.mark.parametrize("drip_headers", [False, True])
@pytest.mark.parametrize("outer_deadline", [False, True])
def test_health_probe_enforces_deadline_against_byte_drip(
    monkeypatch: pytest.MonkeyPatch,
    drip_headers: bool,
    outer_deadline: bool,
) -> None:
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
            result = client.read_guard_health_details(
                f"http://127.0.0.1:{server.server_port}",
                "test-token",
                deadline_monotonic=started + 0.08 if outer_deadline else None,
            )
            elapsed = time.monotonic() - started
            assert result is None
            assert elapsed < (0.5 if outer_deadline else 1.0)
        finally:
            server.shutdown()
            thread.join(timeout=2)


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True, -1.0])
def test_health_probe_invalid_or_expired_operation_deadline_never_connects(monkeypatch, deadline):
    def unexpected_connection(*args, **kwargs):
        pytest.fail("expired or invalid operation opened a connection")

    monkeypatch.setattr(client, "_exchange", unexpected_connection)
    assert (
        client.read_guard_health_details(
            "http://127.0.0.1:1234",
            "test-token",
            deadline_monotonic=deadline,
        )
        is None
    )
