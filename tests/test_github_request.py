"""Tests for the shared GitHub API request helper boundary."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.error import URLError
from urllib.request import Request

import pytest

from codex_plugin_scanner.github_request import _SameHostRedirectHandler, github_request_json


class _RecordingApiServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _LocalGitHubApiHandler)
        self.received_headers: dict[str, str | None] = {}


class _LocalGitHubApiHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        assert isinstance(server, _RecordingApiServer)
        port = server.server_address[1]
        server.received_headers["authorization"] = self.headers.get("Authorization")
        if self.path == "/redirect-same-host":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port}/ok")
            self.end_headers()
            return
        if self.path == "/redirect-cross-host":
            self.send_response(302)
            self.send_header("Location", "http://evil.example.com/steal")
            self.end_headers()
            return
        body = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return


@pytest.fixture()
def local_api_server() -> Iterator[_RecordingApiServer]:
    server = _RecordingApiServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _server_url(server: _RecordingApiServer) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def test_github_request_json_rejects_non_https_destination() -> None:
    with pytest.raises(URLError, match="non-HTTPS"):
        github_request_json("GET", "http://github.example.com/api", "token", user_agent="guard-test")


def test_github_request_json_allows_loopback_and_returns_json(local_api_server: _RecordingApiServer) -> None:
    result = github_request_json("GET", f"{_server_url(local_api_server)}/ok", "token", user_agent="guard-test")
    assert result == {"ok": True}
    assert local_api_server.received_headers["authorization"] == "Bearer token"


def test_github_request_json_follows_same_host_redirects(local_api_server: _RecordingApiServer) -> None:
    result = github_request_json(
        "GET", f"{_server_url(local_api_server)}/redirect-same-host", "token", user_agent="guard-test"
    )
    assert result == {"ok": True}


def test_github_request_json_rejects_cross_host_redirects(local_api_server: _RecordingApiServer) -> None:
    with pytest.raises(URLError, match="cross-host"):
        github_request_json(
            "GET", f"{_server_url(local_api_server)}/redirect-cross-host", "token", user_agent="guard-test"
        )


def _unused_request() -> Request:
    return Request("https://unused.example.test/probe")


def test_redirect_handler_rejects_remote_https_to_http_downgrade() -> None:
    handler = _SameHostRedirectHandler("api.github.example.com")
    with pytest.raises(URLError, match="downgraded"):
        handler.redirect_request(
            _unused_request(), None, 302, "Found", None, "http://api.github.example.com/steal"
        )


def test_redirect_handler_rejects_remote_cross_host_before_downgrade_check() -> None:
    handler = _SameHostRedirectHandler("api.github.example.com")
    with pytest.raises(URLError, match="cross-host"):
        handler.redirect_request(_unused_request(), None, 302, "Found", None, "http://evil.example.com/steal")
