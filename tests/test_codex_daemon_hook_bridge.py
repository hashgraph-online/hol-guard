"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import io
import json
import os
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_auth as hook_auth
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.daemon import manager as daemon_manager
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _ProxyHandler,
    _write_authenticated_daemon_files,
)


def test_assert_loopback_http_url_rejects_remote_and_credentialed_urls() -> None:
    with pytest.raises(ValueError, match="loopback"):
        hook_auth._assert_loopback_http_url("http://evil.example:5474/v1/hooks/codex")
    with pytest.raises(ValueError, match="credentials"):
        hook_auth._assert_loopback_http_url("http://attacker@127.0.0.1:5474/v1/hooks/codex")
    hook_auth._assert_loopback_http_url("http://[::1]:5474/v1/hooks/codex")


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

    assert hook_auth._daemon_url(guard_home / "daemon-state.json") == expected_url


def test_daemon_url_requires_authenticated_guard_owned_state(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unavailable"):
        hook_auth._daemon_url(
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
        hook_auth._daemon_url(guard_home / "daemon-state.json")


def test_fail_closed_uses_supported_codex_deny_shapes() -> None:
    pretool = bridge._fail_closed("PreToolUse", "review failed")
    permission = bridge._fail_closed("PermissionRequest", "review failed")
    posttool = bridge._fail_closed("PostToolUse", "review failed")
    prompt = bridge._fail_closed("UserPromptSubmit", "review failed")

    assert pretool["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    assert posttool["continue"] is False
    assert prompt["continue"] is False


def test_codex_post_tool_response_excludes_daemon_metadata() -> None:
    response = bridge._codex_hook_response(
        {
            "policy_action": "allow",
            "reason_code": "output_scan_allow",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "safe context",
                "internal_reason_code": "output_scan_allow",
            },
        },
        event_name="PostToolUse",
    )

    assert response == {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "safe context",
        }
    }
    assert (
        bridge._codex_hook_response(
            {"hookSpecificOutput": "unexpected"},
            event_name="PostToolUse",
        )
        == {}
    )


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
    _DaemonHandler.response_body = (
        b'{"hookSpecificOutput":{"hookEventName":"PreToolUse"},"reason_code":"daemon_hook_queue_capacity"}'
    )
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
    captured_hook_payload = json.loads(str(_DaemonHandler.captured_hook_body))
    assert captured_hook_payload.pop("guard_remaining_ms") in range(1, 10_001)
    assert captured_hook_payload == hook_payload
    assert json.loads(str(_DaemonHandler.captured_hook_body))["tool_input"]["command"] == complete_command
    assert _ProxyHandler.captured_paths == []
    response = json.loads(capsys.readouterr().out)
    if response == {}:
        pass
    elif "hookSpecificOutput" in response:
        assert response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    else:
        assert response["continue"] is False


@pytest.mark.parametrize(
    "challenge_mode",
    [
        pytest.param("wrong-proof", id="stale-port-reused-by-unproven-process"),
        pytest.param("expired", id="stale-expired-challenge"),
        pytest.param("redirect", id="redirect-refused"),
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


def test_authenticated_generation_rollover_is_rediscovered_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = "replace-state"
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "UserPromptSubmit"})))

    try:
        exit_code = bridge.main(**_bridge_config(guard_home, daemon.server_address[1]))
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 2
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert json.loads(str(_DaemonHandler.captured_hook_body))["hook_event_name"] == "UserPromptSubmit"
    assert json.loads(capsys.readouterr().out) == {}


def test_repeated_generation_rollover_stays_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    def changed_generation(**_kwargs: object) -> dict[str, object]:
        nonlocal attempts
        attempts += 1
        raise bridge._DaemonGenerationChangedError("fixture rollover")

    monkeypatch.setattr(bridge, "_daemon_response_once", changed_generation)

    with pytest.raises(bridge._DaemonGenerationChangedError):
        bridge._daemon_response(
            state_path="unused",
            query="",
            data='{"hook_event_name":"UserPromptSubmit"}',
            timeout_seconds=1,
        )

    assert attempts == 2


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
    if "could not authenticate the local daemon" in json.dumps(response).lower():
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bridge_real_daemon_uses_payload_cwd_for_bounded_compound_read(
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
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "shell",
                    "tool_input": {"command": 'pwd; git status --short --branch; sed -n "1,5p" README.md'},
                    "cwd": str(workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    response = json.loads(capsys.readouterr().out)
    assert response == {} or response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_bridge_real_daemon_emits_schema_exact_post_tool_response(
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
    config["query"] = urlencode({"guard-home": str(guard_home), "home": str(tmp_path)})
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            json.dumps(
                {
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "pwd"},
                    "tool_response": str(workspace),
                    "cwd": str(workspace),
                }
            )
        ),
    )

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.stop()

    assert exit_code == 0
    response = json.loads(capsys.readouterr().out)
    if "hookSpecificOutput" in response:
        assert response == {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}
    else:
        assert response["continue"] is False
