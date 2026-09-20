"""The existing authenticated status route uses bounded loopback reads."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import cloud_review_status_reader as reader
from codex_plugin_scanner.guard.daemon.local_status_transport import read_local_status


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, b'{"worker":{"running":true}}', True),
        (302, b"{}", False),
        (200, b"[]", False),
        (200, b" " * 65_537, False),
    ],
)
def test_status_reader_sends_token_only_to_verified_loopback_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int, body: bytes, expected: bool
) -> None:
    requests: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append((self.path, self.headers.get("X-Guard-Token")))
            self.send_response(status)
            self.send_header("Location", "http://example.invalid/stolen")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    for key in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        monkeypatch.setattr(
            reader,
            "verified_live_guard_daemon_identity",
            lambda _home: {"daemon_url": f"http://127.0.0.1:{server.server_port}"},
        )
        monkeypatch.setattr(reader, "load_guard_daemon_auth_token", lambda _home: "test-status-token")
        try:
            result = reader.read_cloud_review_worker_observation(tmp_path)
            assert result == (json.loads(body)["worker"] if expected else None)
            assert requests == [("/v1/cloud-review", "test-status-token")]
        finally:
            server.shutdown()
            thread.join(timeout=1)


def test_status_transport_rejects_unknown_path_without_sending_token() -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("unapproved status path reached the transport")

    assert (
        read_local_status("http://127.0.0.1:1234", "test-token", path="/unapproved", connection_factory=unexpected)
        is None
    )
