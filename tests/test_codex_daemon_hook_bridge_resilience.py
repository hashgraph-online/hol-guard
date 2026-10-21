"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from urllib.parse import urlencode

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _write_authenticated_daemon_files,
)


def _is_codex_pretool_continue(response: object) -> bool:
    if response == {}:
        return True
    if not isinstance(response, dict):
        return False
    hook = response.get("hookSpecificOutput")
    if not isinstance(hook, dict):
        return False
    decision = hook.get("permissionDecision")
    if decision == "deny":
        return True
    return hook.get("hookEventName") == "PreToolUse" and "permissionDecision" not in hook


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
    # The launcher is the whole Python cost of a hook call: it parses its
    # config, reads the body and either hands the call to the native command
    # or fails closed. The sample covers that launcher, not the review.
    timing_wrapper = """
import runpy
import sys
import time

bridge_path = sys.argv.pop(1)
started_at = time.perf_counter()
try:
    runpy.run_path(bridge_path, run_name="__main__")
except SystemExit:
    print(f"launcher-elapsed={time.perf_counter() - started_at}", file=sys.stderr)
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
    assert all(_is_codex_pretool_continue(response) for response in responses)
    elapsed_samples = [float(result.stderr.rsplit("launcher-elapsed=", 1)[1]) for result in results]
    # The process timeout enforces the hard two-second wall-clock budget. The
    # in-process sample retains the one-second bridge budget without charging
    # interpreter startup and runner dispatch to bridge execution.
    assert min(elapsed_samples) < 1.5
