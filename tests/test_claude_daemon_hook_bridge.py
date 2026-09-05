"""Security and transport tests for the Claude daemon hook bridge."""

from __future__ import annotations

import io
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from typing_extensions import override

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport import DaemonIdentityError
from tests.codex_daemon_hook_bridge_fixtures import (
    _DaemonHandler as _AuthenticatedDaemonHandler,
)
from tests.codex_daemon_hook_bridge_fixtures import (
    _write_authenticated_daemon_files,
)


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


class _StreamingDaemonHandler(_AuthenticatedDaemonHandler):
    status_code = 200

    @override
    def do_POST(self) -> None:
        if self.path == "/v1/daemon/identity-challenge":
            super().do_POST()
            return
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        self.send_response(self.status_code)
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


class _StreamingErrorDaemonHandler(_StreamingDaemonHandler):
    status_code = 503


def test_post_to_loopback_daemon_ignores_http_proxy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _CapturingProxyHandler.captured_paths = []
    proxy_server = HTTPServer(("127.0.0.1", 0), _CapturingProxyHandler)
    proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    proxy_thread.start()

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    state_path = guard_home / "daemon-state.json"

    daemon_server = HTTPServer(("127.0.0.1", 0), _AuthenticatedDaemonHandler)
    daemon_thread = threading.Thread(target=daemon_server.serve_forever, daemon=True)
    daemon_thread.start()
    daemon_port = daemon_server.server_address[1]
    _write_authenticated_daemon_files(guard_home, daemon_port)
    _AuthenticatedDaemonHandler.response_body = json.dumps({"marker": "from-real-daemon"}).encode()

    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy_server.server_address[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy_server.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    try:
        response_body = bridge._post_to_loopback_daemon(
            f"http://127.0.0.1:{daemon_port}/v1/hooks/claude-code?guard-home={guard_home}",
            '{"hook_event_name":"PreToolUse"}',
            state_path=state_path,
        )
    finally:
        proxy_server.shutdown()
        daemon_server.shutdown()
        proxy_thread.join(timeout=5)
        daemon_thread.join(timeout=5)
        _AuthenticatedDaemonHandler.response_body = b"{}"

    payload = json.loads(response_body)
    assert payload["marker"] == "from-real-daemon"
    assert _CapturingProxyHandler.captured_paths == []
    assert _AuthenticatedDaemonHandler.captured_challenge_guard_token is None
    assert _AuthenticatedDaemonHandler.captured_guard_token is None


def test_post_to_loopback_daemon_does_not_send_token_before_identity_proof(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    daemon_server = HTTPServer(("127.0.0.1", 0), _AuthenticatedDaemonHandler)
    daemon_thread = threading.Thread(target=daemon_server.serve_forever, daemon=True)
    daemon_thread.start()
    daemon_port = daemon_server.server_address[1]
    _write_authenticated_daemon_files(guard_home, daemon_port)
    _AuthenticatedDaemonHandler.challenge_mode = "wrong-proof"

    try:
        with pytest.raises(DaemonIdentityError, match="authentication failed"):
            bridge._post_to_loopback_daemon(
                f"http://127.0.0.1:{daemon_port}/v1/hooks/claude-code",
                '{"hook_event_name":"PreToolUse"}',
                state_path=guard_home / "daemon-state.json",
            )
    finally:
        daemon_server.shutdown()
        daemon_thread.join(timeout=5)
        _AuthenticatedDaemonHandler.challenge_mode = "valid"

    assert _AuthenticatedDaemonHandler.captured_challenge_guard_token is None
    assert _AuthenticatedDaemonHandler.captured_guard_token is None


@pytest.mark.parametrize("handler", [_StreamingDaemonHandler, _StreamingErrorDaemonHandler])
def test_post_to_loopback_daemon_enforces_absolute_streaming_deadline(
    tmp_path: Path,
    handler: type[BaseHTTPRequestHandler],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    _write_authenticated_daemon_files(guard_home, server.server_address[1])
    started_at = time.monotonic()

    try:
        with pytest.raises(TimeoutError, match="deadline"):
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
    daemon_server = HTTPServer(("127.0.0.1", 0), _AuthenticatedDaemonHandler)
    daemon_thread = threading.Thread(target=daemon_server.serve_forever, daemon=True)
    daemon_thread.start()
    daemon_port = daemon_server.server_address[1]
    _write_authenticated_daemon_files(guard_home, daemon_port)
    _AuthenticatedDaemonHandler.response_body = b"not-json"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    try:
        exit_code = bridge.main(
            state_path=state_path,
            fallback_daemon_url=f"http://127.0.0.1:{daemon_port}",
            fallback_command=("python3", "-c", "print('{}')"),
            query=f"guard-home={guard_home}",
        )
        assert exit_code == 0
    finally:
        daemon_server.shutdown()
        daemon_thread.join(timeout=5)
        _AuthenticatedDaemonHandler.response_body = b"{}"
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_local_fallback_degrades_invalid_json() -> None:
    response = bridge._run_local_fallback(
        "daemon unavailable",
        json.dumps({"hook_event_name": "PreToolUse"}),
        ("python3", "-c", "print('not-json')"),
    )

    payload = json.loads(response)
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "malformed hook JSON" in payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_degraded_pretool_allows_emergency_safe_read() -> None:
    response = bridge._degraded(
        "daemon unavailable",
        json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/app.ts"},
            }
        ),
    )

    payload = json.loads(response)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_valid_hook_json_degrades_empty_daemon_body() -> None:
    response = bridge._valid_hook_json_or_degraded(
        "",
        reason="daemon returned empty hook JSON",
        data=json.dumps({"hook_event_name": "PreToolUse"}),
    )

    payload = json.loads(response)
    assert payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_daemon_response_body_is_size_bounded() -> None:
    class OversizedResponse:
        def read(self, amt: int = -1) -> bytes:
            assert amt == bridge._MAX_DAEMON_RESPONSE_BYTES + 1
            return b"x" * amt

    with pytest.raises(ValueError, match="safe size limit"):
        bridge._read_bounded_response(OversizedResponse())


def test_oversized_hook_input_fails_safe_without_daemon_contact(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("x" * (bridge._MAX_HOOK_INPUT_BYTES + 1)))

    result = bridge.main(
        state_path="/missing/daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474",
        fallback_command=(sys.executable, "-c", "raise SystemExit(99)"),
        query="guard-home=/missing",
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "exceeded the safe size limit" in payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_oversized_permission_request_uses_nested_deny() -> None:
    payload = json.loads(bridge._limit_denied("hook input", "PermissionRequest"))
    decision = payload["hookSpecificOutput"]["decision"]
    assert payload["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert decision["behavior"] == "deny"
    assert "exceeded the safe size limit" in decision["message"]
    truncated = '{"hook_event_name":"PermissionRequest","tool_name":"Write","prompt":"' + "x" * 80
    assert bridge._event_name(truncated) == "PermissionRequest"
    prompt = json.loads(bridge._limit_denied("hook input", "UserPromptSubmit"))
    assert prompt["decision"] == "block"
    notice = json.loads(bridge._limit_denied("hook input", "Notification"))
    assert notice["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert notice["hookSpecificOutput"]["hookEventName"] == "PreToolUse"


def test_bridge_timeouts_stay_under_harness_budget() -> None:
    assert bridge._HARNESS_TIMEOUT_BUDGET_SECONDS == 10
    assert 0 < bridge._HOOK_DEADLINE_SECONDS < bridge._HARNESS_TIMEOUT_BUDGET_SECONDS
    assert bridge._DAEMON_IO_TIMEOUT_SECONDS <= bridge._HOOK_DEADLINE_SECONDS
    assert bridge._RECOVERY_TIMEOUT_SECONDS <= bridge._HOOK_DEADLINE_SECONDS
    assert bridge._FALLBACK_TIMEOUT_SECONDS <= bridge._HOOK_DEADLINE_SECONDS


def test_main_recovers_missing_daemon_and_retries_hook(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempts = 0
    recovery_commands: list[tuple[str, ...]] = []
    phase_deadlines: list[float] = []

    def fake_post(
        endpoint: str,
        data: str,
        *,
        state_path: str | Path,
        deadline: float | None = None,
    ) -> str:
        assert deadline is not None
        phase_deadlines.append(deadline)
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

    def fake_recover(
        command: tuple[str, ...],
        *,
        deadline: float | None = None,
        failure_kind: str,
    ) -> bool:
        assert deadline is not None
        phase_deadlines.append(deadline)
        assert failure_kind == "transport-failure"
        recovery_commands.append(command)
        return True

    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", fake_post)
    monkeypatch.setattr(bridge, "_run_recovery_command", fake_recover)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    result = bridge.main(
        state_path=tmp_path / "guard-home" / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474",
        fallback_command=("python3", "-c", "raise SystemExit(99)"),
        query=f"guard-home={tmp_path / 'guard-home'}",
    )

    assert result == 0
    assert attempts == 2
    assert len(phase_deadlines) == 3
    assert len(set(phase_deadlines)) == 1
    assert len(recovery_commands) == 1
    assert recovery_commands[0][1:3] == ("-I", "-c")
    assert "schedule_guard_daemon_recovery" in recovery_commands[0][3]
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_authenticated_daemon_failure_denies_without_local_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def reject_request(*args: object, **kwargs: object) -> str:
        raise bridge._DaemonHTTPError(401, "invalid daemon token")

    def reject_fallback(*args: object, **kwargs: object) -> str:
        raise AssertionError("authenticated failures must not use the local fallback")

    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", reject_request)
    monkeypatch.setattr(bridge, "_run_local_fallback", reject_fallback)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    result = bridge.main(
        state_path=tmp_path / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474",
        fallback_command=("python3", "-c", "print('{}')"),
        query=f"guard-home={tmp_path}",
    )

    payload = json.loads(capsys.readouterr().out)
    assert result == 0
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "authentication failed" in payload["hookSpecificOutput"]["permissionDecisionReason"]


def test_authenticated_failure_denies_permission_request_behavior() -> None:
    payload = json.loads(
        bridge._authenticated_control_plane_failure(
            "invalid daemon token",
            json.dumps({"hook_event_name": "PermissionRequest"}),
        )
    )
    assert payload["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    v2 = json.loads(
        bridge._authenticated_control_plane_failure(
            "invalid daemon token",
            json.dumps({"hook_event_name": "PermissionRequestV2"}),
        )
    )
    assert v2["hookSpecificOutput"]["decision"]["behavior"] == "deny"


def test_recovery_only_restarts_for_transport_and_server_failures() -> None:
    assert not bridge._daemon_failure_is_recoverable(ValueError("invalid loopback URL"))
    assert not bridge._daemon_failure_is_recoverable(
        urllib.error.HTTPError("http://127.0.0.1", 400, "Bad Request", {}, None)
    )
    assert not bridge._daemon_failure_is_recoverable(
        urllib.error.HTTPError("http://127.0.0.1", 401, "Unauthorized", {}, None)
    )
    assert bridge._daemon_failure_is_recoverable(
        urllib.error.HTTPError("http://127.0.0.1", 503, "Unavailable", {}, None)
    )
    assert bridge._daemon_failure_is_recoverable(urllib.error.URLError("connection refused"))
    bounded_http_error = bridge._DaemonHTTPError(503, "worker-captured detail")
    assert bridge._daemon_failure_is_recoverable(bounded_http_error)
    assert bridge._daemon_failure_reason(bounded_http_error).endswith("worker-captured detail")
    assert not bridge._daemon_failure_is_recoverable(
        bridge._DaemonHTTPError(429, '{"error":"hook_capacity_exhausted"}')
    )
    assert not bridge._daemon_failure_is_recoverable(bridge._DaemonHTTPError(503, '{"error":"daemon_overloaded"}'))
    assert bridge._daemon_failure_kind(bridge._DaemonHTTPError(429, "busy")) == "overload"
    assert bridge._daemon_failure_kind(TimeoutError("deadline")) == "transport-failure"
    assert bridge._daemon_failure_kind(ValueError("bad state")) == "authenticated-control-plane-failure"


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_fallback_timeout_kills_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "escaped-child.marker"
    child = f"import time;from pathlib import Path;time.sleep(.3);Path({str(marker)!r}).write_text('escaped')"
    parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(10)"
    data = json.dumps({"hook_event_name": "PreToolUse"})

    response = bridge._run_local_fallback(
        "daemon unavailable",
        data,
        (sys.executable, "-c", parent),
        deadline=time.monotonic() + 0.05,
    )
    time.sleep(0.4)

    assert json.loads(response)["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert not marker.exists()


def test_recovery_command_preserves_custom_home_and_guard_home(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard home"
    home_dir = tmp_path / "user home"

    command = bridge._recovery_command(
        guard_home / "daemon-state.json",
        f"guard-home={guard_home.as_posix()}&home={home_dir.as_posix()}",
    )

    assert command[1:3] == ("-I", "-c")
    assert "schedule_guard_daemon_recovery" in command[3]
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
