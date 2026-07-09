"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge


class _DaemonHandler(BaseHTTPRequestHandler):
    captured_guard_token: ClassVar[str | None] = None
    response_body: ClassVar[bytes] = b"{}"

    def do_POST(self) -> None:
        type(self).captured_guard_token = self.headers.get("X-Guard-Token")
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


class _ProxyHandler(BaseHTTPRequestHandler):
    captured_paths: ClassVar[list[str]] = []

    def do_POST(self) -> None:
        type(self).captured_paths.append(self.path)
        self.send_response(502)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _bridge_config(guard_home: Path, port: int) -> dict[str, object]:
    return {
        "state_path": str(guard_home / "daemon-state.json"),
        "fallback_daemon_url": f"http://127.0.0.1:{port}",
        "fallback_command": [sys.executable, "-c", "print('{}')"],
        "start_command": [sys.executable, "-c", "raise SystemExit(1)"],
        "query": f"guard-home={guard_home}",
        "hook_timeouts": {
            "PreToolUse": 10,
            "PermissionRequest": 10,
            "UserPromptSubmit": 10,
            "PostToolUse": 10,
        },
    }


def test_assert_loopback_http_url_rejects_remote_and_credentialed_urls() -> None:
    with pytest.raises(ValueError, match="loopback"):
        bridge._assert_loopback_http_url("http://evil.example:5474/v1/hooks/codex")
    with pytest.raises(ValueError, match="credentials"):
        bridge._assert_loopback_http_url("http://attacker@127.0.0.1:5474/v1/hooks/codex")


def test_fail_closed_uses_supported_codex_deny_shapes() -> None:
    pretool = bridge._fail_closed("PreToolUse", "review failed")
    permission = bridge._fail_closed("PermissionRequest", "review failed")
    posttool = bridge._fail_closed("PostToolUse", "review failed")
    prompt = bridge._fail_closed("UserPromptSubmit", "review failed")

    assert pretool["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert posttool["continue"] is False
    assert prompt["continue"] is False


def test_main_posts_to_authenticated_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-auth-token").write_text("fixture-token", encoding="utf-8")
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    proxy = HTTPServer(("127.0.0.1", 0), _ProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    port = daemon.server_address[1]
    (guard_home / "daemon-state.json").write_text(json.dumps({"port": port}), encoding="utf-8")
    _DaemonHandler.captured_guard_token = None
    _DaemonHandler.response_body = b'{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}'
    _ProxyHandler.captured_paths = []
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        proxy.shutdown()
        daemon_thread.join(timeout=5)
        proxy_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert _ProxyHandler.captured_paths == []
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


def test_malformed_daemon_and_fallback_outputs_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    port = daemon.server_address[1]
    (guard_home / "daemon-state.json").write_text(json.dumps({"port": port}), encoding="utf-8")
    _DaemonHandler.response_body = b"not-json"
    config = _bridge_config(guard_home, port)
    config["fallback_command"] = [sys.executable, "-c", "print('still-not-json')"]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_unavailable_daemon_preserves_local_fallback_denial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    denial = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "blocked by fixture policy",
        }
    }
    config = _bridge_config(guard_home, 1)
    config["fallback_command"] = [
        sys.executable,
        "-c",
        f"import json; print(json.dumps({denial!r}))",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    exit_code = bridge.main(**config)

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == denial


def test_main_starts_daemon_once_then_retries_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    responses: list[dict[str, object] | None] = []
    starts: list[tuple[str, ...]] = []

    def daemon_response(**kwargs: object) -> dict[str, object]:
        responses.append(None)
        if len(responses) == 1:
            raise urllib.error.URLError("daemon cold")
        return {}

    def start_daemon(command: tuple[str, ...], *, timeout_seconds: float) -> bool:
        starts.append(tuple(command))
        assert timeout_seconds == 8
        return True

    config = _bridge_config(guard_home, 1)
    monkeypatch.setattr(bridge, "_daemon_response", daemon_response)
    monkeypatch.setattr(bridge, "_run_daemon_start", start_daemon)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    exit_code = bridge.main(**config)

    assert exit_code == 0
    assert len(responses) == 2
    assert starts == [tuple(config["start_command"])]
    assert json.loads(capsys.readouterr().out) == {}


def test_bridge_script_cold_start_stays_below_hook_budget(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    port = daemon.server_address[1]
    (guard_home / "daemon-state.json").write_text(json.dumps({"port": port}), encoding="utf-8")
    config = _bridge_config(guard_home, port)
    command = [sys.executable, str(Path(bridge.__file__).resolve()), json.dumps(config)]
    payload = json.dumps({"hook_event_name": "PreToolUse"})

    try:
        started_at = time.perf_counter()
        result = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        elapsed = time.perf_counter() - started_at
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert result.returncode == 0
    assert json.loads(result.stdout) == {}
    assert elapsed < 0.75
