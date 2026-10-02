"""A bridge failure must not authorize an unreviewed tool action."""

import json
import sys
import time

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge


@pytest.mark.parametrize("event", ("PreToolUse", "PermissionRequest", "PermissionDenied"))
@pytest.mark.parametrize("reason", ("daemon unavailable", "fallback timed out", "malformed hook JSON"))
def test_unreviewed_tool_failure_denies(event, reason):
    payload = json.loads(bridge._degraded(reason, json.dumps({"hook_event_name": event})))
    output = payload["hookSpecificOutput"]
    if event.startswith("Permission"):
        assert output["decision"]["behavior"] == "deny"
    else:
        assert output["permissionDecision"] == "deny"
    assert "without native review" not in json.dumps(payload)


def test_fallback_deadline_exhaustion_denies_without_running_command(tmp_path):
    marker = tmp_path / "executed"
    command = (sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()")
    payload = json.loads(
        bridge._run_local_fallback(
            "daemon unavailable",
            json.dumps({"hook_event_name": "PreToolUse"}),
            command,
            deadline=time.monotonic() - 1,
        )
    )
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not marker.exists()
