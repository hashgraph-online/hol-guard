"""Unavailable native authority must still emit the Codex hook protocol."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_authority as cli
from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("failure", ("worker_none", "worker_response", "worker_raise"))
@pytest.mark.parametrize("json_requested", (False, True))
@pytest.mark.parametrize("event", ("PreToolUse", "PermissionRequest"))
def test_native_failure_preserves_codex_wire_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
    json_requested: bool,
    event: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    store = GuardStore(guard_home)
    payload = {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": "printf test > output.txt"}}

    def unavailable(**_kwargs):
        if failure == "worker_raise":
            raise RuntimeError("injected native failure")
        if failure == "worker_response":
            return availability_harness_response(
                harness="codex",
                event_name=event,
                reason_code="native_hook_worker_exception",
                reason="Native review is unavailable.",
            )
        return None

    monkeypatch.setattr(cli, "try_native_hook_authority", unavailable)
    result = cli.route_native_hook(
        Mock(harness="codex", json=json_requested),
        config=None,
        context=context,
        payload=payload,
        runtime_workspace=None,
        store=store,
    )
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    # codex denies via the hookSpecificOutput.permissionDecision envelope;
    # rc stays 0 so codex honors the deny rather than treating a nonzero rc
    # as a hook error and permitting the action.
    assert response["hookSpecificOutput"]["hookEventName"] == event
    if event == "PreToolUse":
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result == 0
    else:
        assert response["hookSpecificOutput"]["decision"]["behavior"] == "deny"
        assert "permissionDecision" not in response["hookSpecificOutput"]
        assert result == 0


@pytest.mark.parametrize("failure", ("worker_none", "worker_raise"))
def test_native_failure_keeps_copilot_permission_wire_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=guard_home)
    payload = {"hookName": "permissionRequest", "toolName": "bash", "toolArgs": {"command": "rm -rf build"}}

    def unavailable(**_kwargs):
        if failure == "worker_raise":
            raise RuntimeError("injected native failure")
        return None

    monkeypatch.setattr(cli, "try_native_hook_authority", unavailable)
    result = cli.route_native_hook(
        Mock(harness="copilot", json=False),
        config=None,
        context=context,
        payload=payload,
        runtime_workspace=None,
        store=GuardStore(guard_home),
    )
    response = json.loads(capsys.readouterr().out)
    # Copilot reads a permission answer from these top-level fields; the
    # generic hookSpecificOutput envelope would leave the request undecided.
    assert response["behavior"] == "deny"
    assert response["message"]
    assert "hookSpecificOutput" not in response
    assert result == 0
