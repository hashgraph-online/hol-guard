"""Unavailable native authority must still emit the Codex hook protocol."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_authority as cli
from codex_plugin_scanner.guard.cli import commands_hook_native_pipeline as pipeline
from codex_plugin_scanner.guard.daemon.hook_availability_policy import availability_harness_response
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("failure", ("worker_none", "worker_response", "worker_raise", "disabled"))
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
    monkeypatch.setattr(cli, "_native_mode_requires_rust", lambda: failure != "disabled")

    def unavailable(**_kwargs):
        if failure == "worker_raise":
            raise RuntimeError("injected native failure")
        if failure == "worker_response":
            return availability_harness_response(
                payload,
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
        assert response["continue"] is True
        assert "permissionDecision" not in response["hookSpecificOutput"]
        assert "decision" not in response["hookSpecificOutput"]
        assert result == 0


@pytest.mark.parametrize("event", ("PreToolUse", "PermissionRequest"))
@pytest.mark.parametrize("json_requested", (False, True))
def test_pipeline_unavailable_preserves_codex_wire_response(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], event: str, json_requested: bool
) -> None:
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    payload = {"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": "printf test > output.txt"}}
    result = pipeline._emit_native_unavailable(
        Mock(harness="codex", json=json_requested),
        payload=payload,
        workspace=None,
        context=context,
        event_name=event,
        reason_code="native_hook_event_unavailable",
        worker=HookWorker(
            store=GuardStore(context.guard_home), wait_for_native_policy=False, publish_native_policy=False
        ),
    )
    response = json.loads(capsys.readouterr().out)
    # codex deny rides the permissionDecision envelope; rc stays 0.
    assert response["hookSpecificOutput"]["hookEventName"] == event
    if event == "PreToolUse":
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result == 0
    else:
        assert response["continue"] is True
        assert "permissionDecision" not in response["hookSpecificOutput"]
        assert "decision" not in response["hookSpecificOutput"]
        assert result == 0
