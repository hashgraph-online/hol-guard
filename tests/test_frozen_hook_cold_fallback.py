"""A frozen Guard never starts a cold `hol-guard hook` evaluator from a hook bridge."""

from __future__ import annotations

import json
import sys
import time

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge, codex_daemon_hook_bridge_flow

_PRE_TOOL_USE = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})


def _forbidden(*args: object, **kwargs: object) -> object:
    del args, kwargs
    raise AssertionError("a frozen Guard must not start a cold evaluator")


class _ForbiddenLaunch:
    def run_fallback(self, *args: object, **kwargs: object) -> object:
        return _forbidden(*args, **kwargs)


def test_frozen_claude_bridge_denies_without_a_daemon_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(claude_daemon_hook_bridge, "run_isolated_hook_process", _forbidden)

    output = claude_daemon_hook_bridge._run_local_fallback(
        "daemon unavailable",
        _PRE_TOOL_USE,
        ("/app/hol-guard", "hook", "--harness", "claude"),
        deadline=time.monotonic() + 10,
    )

    decision = json.loads(output)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "no daemon answered" in decision["permissionDecisionReason"]


def test_frozen_codex_bridge_has_no_fallback_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(codex_daemon_hook_bridge_flow, "_run_local_fallback", _forbidden)

    response = codex_daemon_hook_bridge_flow._fallback_response(
        trusted_launch=_ForbiddenLaunch(),  # type: ignore[arg-type]
        launch_integrity_failed=False,
        fallback_command=("/app/hol-guard", "hook", "--harness", "codex"),
        data=_PRE_TOOL_USE,
        deadline=time.monotonic() + 10,
    )

    assert response is None
