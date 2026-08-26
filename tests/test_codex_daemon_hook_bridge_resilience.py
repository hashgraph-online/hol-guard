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
from http.server import HTTPServer
from pathlib import Path
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge_flow as bridge_flow
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _write_authenticated_daemon_files,
)


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

    def start_daemon(
        command: tuple[str, ...],
        *,
        timeout_seconds: float,
        failure_kind: str,
    ) -> bool:
        starts.append(tuple(command))
        assert 1.0 < timeout_seconds <= 2
        assert failure_kind == "transport-failure"
        return True

    config = _bridge_config(guard_home, 1)
    monkeypatch.setattr(bridge_flow, "_daemon_response", daemon_response)
    monkeypatch.setattr(bridge_flow, "_run_daemon_start", start_daemon)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    exit_code = bridge.main(**config)

    assert exit_code == 0
    assert len(responses) == 2
    assert starts == [tuple(config["start_command"])]
    assert json.loads(capsys.readouterr().out) == {}

    fallback_calls: list[str] = []
    monkeypatch.setattr(
        bridge_flow,
        "_daemon_response",
        lambda **_kwargs: {
            "continue": False,
            "stopReason": "isolated review failed",
            "systemMessage": "isolated review failed",
            "reason_code": "daemon_hook_process_failed",
        },
    )
    monkeypatch.setattr(
        bridge_flow,
        "_run_local_fallback",
        lambda _command, *, data, timeout_seconds: (
            fallback_calls.append(data) or {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}
        ),
    )
    prompt = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Reassess the current implementation.",
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(prompt)))

    assert bridge.main(**config) == 0
    assert fallback_calls == [json.dumps(prompt)]
    assert json.loads(capsys.readouterr().out) == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}


def test_authenticated_overload_fails_closed_without_fallback_or_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    starts: list[tuple[str, ...]] = []

    def overloaded_daemon(**kwargs: object) -> dict[str, object]:
        del kwargs
        raise bridge_flow._DaemonResponseError(429, '{"error":"hook_capacity_exhausted"}', authenticated=True)

    def start_daemon(
        command: tuple[str, ...],
        *,
        timeout_seconds: float,
        failure_kind: str,
    ) -> bool:
        del timeout_seconds, failure_kind
        starts.append(command)
        return True

    config = _bridge_config(guard_home, 1)
    monkeypatch.setattr(bridge_flow, "_daemon_response", overloaded_daemon)
    monkeypatch.setattr(bridge_flow, "_run_daemon_start", start_daemon)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"hook_event_name": "PreToolUse"})))

    assert bridge.main(**config) == 0
    assert starts == []
    payload = json.loads(capsys.readouterr().out)
    output = payload["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "temporarily saturated" in output["permissionDecisionReason"]


def test_typed_transient_overload_retries_once_when_deadline_fits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    attempts = 0

    def daemon_response(**kwargs: object) -> dict[str, object]:
        del kwargs
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise bridge_flow._DaemonResponseError(
                503,
                '{"reason_code":"transient_overload","retry_after_ms":25,"estimated_service_ms":100}',
                authenticated=True,
            )
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    monkeypatch.setattr(bridge_flow, "_daemon_response", daemon_response)
    monkeypatch.setattr(bridge.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"hook_event_name":"PreToolUse"}'))

    assert bridge.main(**_bridge_config(guard_home, 1)) == 0
    assert attempts == 2
    assert json.loads(capsys.readouterr().out)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_daemon_failure_kind_separates_overload_transport_and_control_plane() -> None:
    assert (
        bridge_flow._daemon_failure_kind(
            bridge_flow._DaemonResponseError(429, '{"error":"hook_capacity_exhausted"}', authenticated=True)
        )
        == "overload"
    )
    assert bridge_flow._daemon_failure_kind(TimeoutError("deadline")) == "transport-failure"
    assert bridge_flow._daemon_failure_kind(ValueError("state authentication failed")) == (
        "authenticated-control-plane-failure"
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group assertion")
def test_untrusted_fallback_timeout_kills_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "escaped-child.marker"
    child = f"import time;from pathlib import Path;time.sleep(.3);Path({str(marker)!r}).write_text('escaped')"
    parent = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(10)"

    response = bridge_flow._run_local_fallback(
        (sys.executable, "-c", parent),
        data="{}",
        timeout_seconds=0.05,
    )
    time.sleep(0.4)

    assert response is None
    assert not marker.exists()


def test_bridge_script_cold_start_stays_below_hook_budget(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread_started = threading.Event()

    def serve_daemon() -> None:
        daemon_thread_started.set()
        daemon.serve_forever()

    daemon_thread = threading.Thread(target=serve_daemon, daemon=True)
    daemon_thread.start()
    assert daemon_thread_started.wait(timeout=1)
    port = daemon.server_address[1]
    _write_authenticated_daemon_files(guard_home, port)
    config = _bridge_config(guard_home, port)
    config["manifest_path"] = str(guard_home / "managed" / "codex" / "hooks-fixture.manifest.json")
    bridge_path = str(Path(bridge.__file__).resolve())
    timing_wrapper = """
import runpy
import sys
import time

bridge_path = sys.argv.pop(1)
started_at = time.perf_counter()
try:
    runpy.run_path(bridge_path, run_name="__main__")
except SystemExit:
    print(f"bridge-elapsed={time.perf_counter() - started_at}", file=sys.stderr)
    raise
"""
    command = [sys.executable, "-I", "-c", timing_wrapper, bridge_path, json.dumps(config)]
    payload = json.dumps({"hook_event_name": "PreToolUse"})

    results: list[subprocess.CompletedProcess[str]] = []
    try:
        for _ in range(3):
            results.append(
                subprocess.run(
                    command,
                    input=payload,
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
            )
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert all(result.returncode == 0 for result in results), [
        (result.returncode, result.stdout, result.stderr) for result in results
    ]
    responses = [json.loads(result.stdout) for result in results]
    assert all(
        response == {} or response.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
        for response in responses
    )
    elapsed_samples = [float(result.stderr.rsplit("bridge-elapsed=", 1)[1]) for result in results]
    # The process timeout enforces the hard two-second wall-clock budget. The
    # in-process sample retains the one-second bridge budget without charging
    # interpreter startup and runner dispatch to bridge execution.
    assert min(elapsed_samples) < 1.5
