"""Security and transport tests for the Claude daemon hook bridge."""

from __future__ import annotations

import io
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
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


class _StreamingDaemonHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        try:
            for _ in range(50):
                self.wfile.write(b"{")
                self.wfile.flush()
                time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, fmt: str, *args: object) -> None:
        return


def test_post_to_loopback_daemon_ignores_http_proxy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _CapturingProxyHandler.captured_paths = []
    proxy_server = HTTPServer(("127.0.0.1", 0), _CapturingProxyHandler)
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()

    auth_token = "test-guard-token"
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text(auth_token, encoding="utf-8")
    if os.name != "nt":
        os.chmod(token_path, 0o600)
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


def test_post_to_loopback_daemon_enforces_absolute_streaming_deadline(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StreamingDaemonHandler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    started_at = time.monotonic()

    try:
        with pytest.raises(TimeoutError, match="absolute deadline"):
            bridge._post_to_loopback_daemon(
                f"http://127.0.0.1:{server.server_address[1]}/v1/hooks/claude-code",
                "{}",
                state_path=guard_home / "daemon-state.json",
            )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    assert time.monotonic() - started_at < bridge._DAEMON_IO_TIMEOUT_SECONDS + 1


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
    _DaemonHandler.captured_guard_token = None
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


def test_valid_hook_json_degrades_empty_daemon_body() -> None:
    response = bridge._valid_hook_json_or_degraded(
        "",
        reason="daemon returned empty hook JSON",
        data=json.dumps({"hook_event_name": "PreToolUse"}),
    )

    payload = json.loads(response)
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "full HOL Guard approval flow" in payload["systemMessage"]


def test_bridge_timeouts_stay_under_harness_budget() -> None:
    assert bridge._HARNESS_TIMEOUT_BUDGET_SECONDS == 10
    assert (
        2 * bridge._DAEMON_IO_TIMEOUT_SECONDS
    ) + bridge._RECOVERY_TIMEOUT_SECONDS + bridge._FALLBACK_TIMEOUT_SECONDS < bridge._HARNESS_TIMEOUT_BUDGET_SECONDS


def test_main_recovers_missing_daemon_and_retries_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempts = 0
    recovery_commands: list[tuple[str, ...]] = []

    def fake_post(endpoint: str, data: str, *, state_path: str | Path) -> str:
        del endpoint, data, state_path
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise urllib.error.URLError("daemon unavailable")
        return json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                }
            }
        )

    def fake_recover(command: tuple[str, ...]) -> bool:
        recovery_commands.append(command)
        return True

    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", fake_post)
    monkeypatch.setattr(bridge, "_run_recovery_command", fake_recover)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    result = bridge.main(
        state_path=tmp_path / "guard-home" / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474",
        fallback_command=("python3", "-c", "raise SystemExit(99)"),
        query="guard-home=%2Ftmp",
    )

    assert result == 0
    assert attempts == 2
    assert len(recovery_commands) == 1
    assert recovery_commands[0][1:3] == ("-I", "-c")
    assert "recover_guard_daemon_after_hook_failure" in recovery_commands[0][3]
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_recovery_only_restarts_for_transport_auth_and_server_failures() -> None:
    assert not bridge._daemon_failure_is_recoverable(ValueError("invalid loopback URL"))
    assert not bridge._daemon_failure_is_recoverable(
        urllib.error.HTTPError("http://127.0.0.1", 400, "Bad Request", {}, None)
    )
    assert bridge._daemon_failure_is_recoverable(
        urllib.error.HTTPError("http://127.0.0.1", 503, "Unavailable", {}, None)
    )
    assert bridge._daemon_failure_is_recoverable(urllib.error.URLError("connection refused"))


def test_recovery_command_preserves_custom_home_and_guard_home(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard home"
    home_dir = tmp_path / "user home"

    command = bridge._recovery_command(
        guard_home / "daemon-state.json",
        f"guard-home={guard_home.as_posix()}&home={home_dir.as_posix()}",
    )

    assert command[1:3] == ("-I", "-c")
    assert "recover_guard_daemon_after_hook_failure" in command[3]
    assert str(guard_home) in command[3]
    assert str(home_dir) in command[3]


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
