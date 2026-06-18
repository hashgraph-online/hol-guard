"""Security and transport tests for the Claude daemon hook bridge."""

from __future__ import annotations

import io
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge


class _CapturingProxyHandler(BaseHTTPRequestHandler):
    captured_paths: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        type(self).captured_paths.append(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                }
            ).encode("utf-8")
        )

    def log_message(self, fmt: str, *args: object) -> None:
        return


def test_assert_loopback_http_url_rejects_remote_host() -> None:
    with pytest.raises(ValueError, match="loopback"):
        bridge._assert_loopback_http_url("http://evil.example:5474/v1/hooks/claude-code")


def test_daemon_url_rejects_non_loopback_fallback() -> None:
    with pytest.raises(ValueError, match="loopback"):
        bridge._daemon_url("/nonexistent/daemon-state.json", "http://proxy.internal:5474/")


class _DaemonHandler(BaseHTTPRequestHandler):
    response_marker = "from-real-daemon"
    captured_guard_token: ClassVar[str | None] = None
    raw_response_body: ClassVar[bytes | None] = None

    def do_POST(self) -> None:
        type(self).captured_guard_token = self.headers.get("X-Guard-Token")
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if type(self).raw_response_body is not None:
            self.wfile.write(type(self).raw_response_body)
            return
        self.wfile.write(
            json.dumps(
                {
                    "marker": type(self).response_marker,
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                    },
                }
            ).encode("utf-8")
        )

    def log_message(self, fmt: str, *args: object) -> None:
        return


def test_post_to_loopback_daemon_ignores_http_proxy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _CapturingProxyHandler.captured_paths = []
    proxy_server = HTTPServer(("127.0.0.1", 0), _CapturingProxyHandler)
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()

    auth_token = "test-guard-token"
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-auth-token").write_text(auth_token, encoding="utf-8")
    state_path = guard_home / "daemon-state.json"

    daemon_server = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon_server.serve_forever, daemon=True)
    daemon_thread.start()
    daemon_port = daemon_server.server_address[1]
    _DaemonHandler.captured_guard_token = None
    _DaemonHandler.raw_response_body = None

    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy_server.server_address[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy_server.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    try:
        response_body = bridge._post_to_loopback_daemon(
            f"http://127.0.0.1:{daemon_port}/v1/hooks/claude-code?guard-home=%2Ftmp",
            "{}",
            state_path=state_path,
        )
    finally:
        proxy_server.shutdown()
        daemon_server.shutdown()
        proxy_thread.join(timeout=5)
        daemon_thread.join(timeout=5)

    payload = json.loads(response_body)
    assert payload["marker"] == _DaemonHandler.response_marker
    assert _CapturingProxyHandler.captured_paths == []
    assert _DaemonHandler.captured_guard_token == auth_token


def test_main_degrades_when_daemon_returns_malformed_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state_path = guard_home / "daemon-state.json"
    daemon_server = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon_server.serve_forever, daemon=True)
    daemon_thread.start()
    daemon_port = daemon_server.server_address[1]
    _DaemonHandler.raw_response_body = b"not-json"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(
            state_path=state_path,
            fallback_daemon_url=f"http://127.0.0.1:{daemon_port}",
            fallback_command=("python3", "-c", "print('{}')"),
            query="guard-home=%2Ftmp",
        )
        assert exit_code == 0
    finally:
        daemon_server.shutdown()
        daemon_thread.join(timeout=5)
        _DaemonHandler.raw_response_body = None
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_run_local_fallback_degrades_invalid_json() -> None:
    response = bridge._run_local_fallback(
        "daemon unavailable",
        json.dumps({"hook_event_name": "PreToolUse"}),
        ("python3", "-c", "print('not-json')"),
    )

    payload = json.loads(response)
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "malformed hook JSON" in payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_bridge_timeouts_stay_under_harness_budget() -> None:
    assert bridge._DAEMON_TIMEOUT_SECONDS <= 10
    assert bridge._FALLBACK_TIMEOUT_SECONDS <= 10


def test_loopback_redirect_handler_rejects_remote_redirect() -> None:
    handler = bridge._LoopbackOnlyRedirectHandler()
    with pytest.raises(ValueError, match="loopback"):
        handler.redirect_request(
            urllib.request.Request("http://127.0.0.1:5474/"),
            None,
            302,
            "Found",
            {},
            "http://evil.example/allow",
        )
