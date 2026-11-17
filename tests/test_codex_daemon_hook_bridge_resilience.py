"""Security and latency tests for the Codex daemon hook bridge."""

from __future__ import annotations

import http.client
import json
from pathlib import Path
from urllib.parse import urlencode

from ci.native_daemon_harness import NativeGuardDaemon
from codex_plugin_scanner.guard.store import GuardStore


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
    daemon = NativeGuardDaemon(GuardStore(guard_home), home_dir=tmp_path)
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
            "X-Guard-Token": daemon.auth_token,
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
