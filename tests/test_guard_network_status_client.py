from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from codex_plugin_scanner.guard.native_daemon_client import (
    GuardDaemonRequestError,
    GuardSurfaceDaemonClient,
)
from codex_plugin_scanner.guard.runtime.network_status import build_network_status


def test_network_status_client_uses_fast_status_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    observed: dict[str, object] = {}

    def fake_get(path: str, *, timeout: float) -> dict[str, object]:
        observed.update(path=path, timeout=timeout)
        return build_network_status(platform_name="darwin")

    monkeypatch.setattr(client, "_get", fake_get)
    client.network_status()
    assert observed == {"path": "/v1/network/status", "timeout": 0.25}


def test_dashboard_session_rejects_redirect_without_sending_session_to_target() -> None:
    paths: list[tuple[str, str | None]] = []

    class RedirectingHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            paths.append((self.path, self.headers.get("X-Guard-Dashboard-Session")))
            self.send_response(302)
            self.send_header("Location", "/collect")
            self.end_headers()

        def do_GET(self) -> None:
            paths.append((self.path, self.headers.get("X-Guard-Dashboard-Session")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectingHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{server.server_port}", "private-auth-token")
        with pytest.raises(GuardDaemonRequestError):
            client.dashboard_session_capabilities(timeout=0.5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert len(paths) == 1
    assert paths[0][0] == "/v1/initialize"
    assert paths[0][1] is not None and paths[0][1].startswith("gld1.")


class _RawResponse:
    def __init__(self, *, payload: bytes | None = None, read_error: Exception | None = None) -> None:
        self.payload = payload
        self.read_error = read_error
        self.read_timeout: float | None = None
        self.consumed = False
        self.closed = False

    def __enter__(self) -> _RawResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _amount: int = -1) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        assert self.payload is not None
        if self.consumed:
            return b""
        self.consumed = True
        return self.payload

    def settimeout(self, timeout: float) -> None:
        self.read_timeout = timeout

    def close(self) -> None:
        self.closed = True
