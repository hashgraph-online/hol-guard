"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.discovery import (
    DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS,
    authenticated_challenge_payload,
    load_daemon_discovery_key,
)
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


class _DaemonHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    captured_challenge_guard_token: ClassVar[str | None] = None
    captured_guard_token: ClassVar[str | None] = None
    captured_hook_body: ClassVar[str | None] = None
    response_body: ClassVar[bytes] = b"{}"
    guard_home: ClassVar[Path | None] = None
    auth_token: ClassVar[str] = "fixture-token"
    challenge_mode: ClassVar[str] = "valid"
    challenge_count: ClassVar[int] = 0

    def _write_json(self, payload: dict[str, object], *, status: int = 200, keep_alive: bool = False) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive" if keep_alive else "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        if self.path == "/v1/daemon/identity-challenge":
            type(self).challenge_count += 1
            type(self).captured_challenge_guard_token = self.headers.get("X-Guard-Token")
            if type(self).challenge_mode == "redirect":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            request = json.loads(raw_body)
            guard_home = type(self).guard_home
            assert guard_home is not None
            state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
            discovery_key = load_daemon_discovery_key(guard_home)
            assert discovery_key is not None
            issued_at_ms = int(time.time() * 1000)
            expires_at_ms = issued_at_ms + DAEMON_DISCOVERY_CHALLENGE_TTL_SECONDS * 1000
            if type(self).challenge_mode == "expired":
                issued_at_ms -= 10_000
                expires_at_ms -= 10_000
            response = authenticated_challenge_payload(
                discovery_key=discovery_key,
                state=state,
                nonce=request["nonce"],
                hook_event=request["hook_event"],
                issued_at_ms=issued_at_ms,
                expires_at_ms=expires_at_ms,
            )
            if type(self).challenge_mode == "wrong-proof":
                response["proof"] = "0" * 64
            if type(self).challenge_mode == "replace-state":
                daemon_manager.write_guard_daemon_state(
                    guard_home,
                    self.server.server_address[1],
                    type(self).auth_token,
                    pid=os.getpid(),
                    state_id="replacement-state",
                )
            self._write_json(response, keep_alive=True)
            return
        type(self).captured_guard_token = self.headers.get("X-Guard-Token")
        type(self).captured_hook_body = raw_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).response_body)))
        self.send_header("Connection", "close")
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


def _write_authenticated_daemon_files(guard_home: Path, port: int) -> None:
    daemon_manager.write_guard_daemon_state(
        guard_home,
        port,
        _DaemonHandler.auth_token,
        pid=os.getpid(),
        state_id="fixture-state",
    )
    _DaemonHandler.guard_home = guard_home
    _DaemonHandler.captured_challenge_guard_token = None
    _DaemonHandler.captured_guard_token = None
    _DaemonHandler.captured_hook_body = None
    _DaemonHandler.response_body = b"{}"
    _DaemonHandler.challenge_mode = "valid"
    _DaemonHandler.challenge_count = 0


def test_assert_loopback_http_url_rejects_remote_and_credentialed_urls() -> None:
    with pytest.raises(ValueError, match="loopback"):
        bridge._assert_loopback_http_url("http://evil.example:5474/v1/hooks/codex")
    with pytest.raises(ValueError, match="credentials"):
        bridge._assert_loopback_http_url("http://attacker@127.0.0.1:5474/v1/hooks/codex")
    bridge._assert_loopback_http_url("http://[::1]:5474/v1/hooks/codex")


@pytest.mark.parametrize(
    ("host", "expected_url"),
    [
        ("127.0.0.1", "http://127.0.0.1:5474"),
        ("localhost", "http://localhost:5474"),
        ("::1", "http://[::1]:5474"),
    ],
)
def test_daemon_url_accepts_only_authenticated_ipv4_and_ipv6_loopback_state(
    tmp_path: Path,
    host: str,
    expected_url: str,
) -> None:
    guard_home = tmp_path / host.replace(":", "_")
    daemon_manager.write_guard_daemon_state(
        guard_home,
        5474,
        "fixture-token",
        host=host,
    )

    assert bridge._daemon_url(guard_home / "daemon-state.json") == expected_url


def test_daemon_url_requires_authenticated_guard_owned_state(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unavailable"):
        bridge._daemon_url(
            tmp_path / "missing-daemon-state.json",
        )

    guard_home = tmp_path / "non-loopback"
    daemon_manager.write_guard_daemon_state(
        guard_home,
        5474,
        "fixture-token",
        host="192.0.2.1",
    )
    with pytest.raises(ValueError, match="identity is incomplete"):
        bridge._daemon_url(guard_home / "daemon-state.json")


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
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    proxy = HTTPServer(("127.0.0.1", 0), _ProxyHandler)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    _DaemonHandler.response_body = b'{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}'
    _ProxyHandler.captured_paths = []
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    complete_command = "trap - DEBUG; { cat .env; } > /dev/null\ncat <<'EOF'\nharmless\nEOF"
    hook_payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": complete_command},
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook_payload)))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, port))
    finally:
        daemon.shutdown()
        proxy.shutdown()
        daemon_thread.join(timeout=5)
        proxy_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_challenge_guard_token is None
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert json.loads(str(_DaemonHandler.captured_hook_body)) == hook_payload
    assert json.loads(str(_DaemonHandler.captured_hook_body))["tool_input"]["command"] == complete_command
    assert _ProxyHandler.captured_paths == []
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


@pytest.mark.parametrize(
    "challenge_mode",
    [
        pytest.param("wrong-proof", id="stale-port-reused-by-unproven-process"),
        pytest.param("expired", id="stale-expired-challenge"),
        pytest.param("redirect", id="redirect-refused"),
        pytest.param("replace-state", id="concurrent-restart-replaces-state"),
    ],
)
def test_failed_daemon_identity_never_receives_token_or_hook_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    challenge_mode: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = challenge_mode
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_challenge_guard_token is None
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


def test_tampered_state_is_rejected_before_candidate_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    state_path = guard_home / "daemon-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["state_id"] = "untrusted-replacement"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    os.chmod(state_path, 0o600)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 0
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode enforcement")
@pytest.mark.parametrize("private_file", ["daemon-state.json", "daemon-discovery-key", "daemon-auth-token"])
def test_non_private_discovery_files_never_release_token_or_hook_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    private_file: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    os.chmod(guard_home / private_file, 0o644)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


def test_missing_token_never_falls_back_to_mutable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    (guard_home / "daemon-auth-token").unlink()
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 1
    assert _DaemonHandler.captured_guard_token is None
    assert _DaemonHandler.captured_hook_body is None
    assert json.loads(capsys.readouterr().out) == {}


def test_bridge_authenticates_real_daemon_before_hook_delivery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    config = _bridge_config(guard_home, daemon.port)
    config["query"] = urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(workspace),
        }
    )
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "echo hello"},
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    response = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert "could not authenticate the local daemon" not in json.dumps(response).lower()


def test_real_daemon_rejects_consumed_challenge_replay(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    state = json.loads((guard_home / "daemon-state.json").read_text(encoding="utf-8"))
    nonce = "a" * 64
    challenge_body = json.dumps(
        {
            "protocol_version": 1,
            "nonce": nonce,
            "state_id": state["state_id"],
            "hook_event": "PreToolUse",
        }
    )
    hook_body = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
        }
    )
    hook_path = "/v1/hooks/codex?" + urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(workspace),
        }
    )

    try:
        connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=5)
        connection.request(
            "POST",
            "/v1/daemon/identity-challenge",
            body=challenge_body,
            headers={"Content-Type": "application/json", "Connection": "keep-alive"},
        )
        challenge_response = connection.getresponse()
        challenge = json.loads(challenge_response.read())
        proof_headers = {
            "Content-Type": "application/json",
            "Connection": "close",
            "X-Guard-Token": daemon._server.auth_token,
            "X-Guard-Daemon-Nonce": nonce,
            "X-Guard-Daemon-Proof": challenge["proof"],
        }
        connection.request("POST", hook_path, body=hook_body, headers=proof_headers)
        first_response = connection.getresponse()
        _ = first_response.read()
        connection.close()

        replay_connection = http.client.HTTPConnection("127.0.0.1", daemon.port, timeout=5)
        replay_connection.request("POST", hook_path, body=hook_body, headers=proof_headers)
        replay_response = replay_connection.getresponse()
        _ = replay_response.read()
        replay_connection.close()
    finally:
        daemon.stop()

    assert challenge_response.status == 200
    assert first_response.status == 200
    assert replay_response.status == 401


def test_malformed_daemon_and_fallback_outputs_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
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


def test_post_tool_use_stdout_is_exactly_one_json_object_with_noisy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config = _bridge_config(guard_home, 1)
    config["fallback_command"] = [
        sys.executable,
        "-c",
        "print('Guard integrity warning'); print('{\"continue\": true}')",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PostToolUse"})))

    exit_code = bridge.main(**config)

    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert exit_code == 0
    assert output["continue"] is False
    assert captured.out == json.dumps(output, separators=(",", ":"))
    assert captured.err == ""


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
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    config = _bridge_config(guard_home, port)
    config["manifest_path"] = str(guard_home / "managed" / "codex" / "hooks-fixture.manifest.json")
    command = [sys.executable, "-I", str(Path(bridge.__file__).resolve()), json.dumps(config)]
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
    # Keep the bridge comfortably below its two-second process timeout while
    # allowing for scheduler jitter on shared CI runners.
    assert elapsed < 1.0
