"""A frozen Guard never starts a cold `hol-guard hook` evaluator from a hook bridge.

The Claude bridge has no local evaluator left to forbid: its launcher runs the
native command or denies, so `tests/test_claude_daemon_hook_bridge.py` covers
it from the other side.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import frozen_codex_runtime
from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as codex_bridge

_PRE_TOOL_USE = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})
_FALLBACK_COMMAND = ["/app/hol-guard", "hook", "--harness", "codex"]
_NATIVE = Path("/app/guard-home/native/hol-guard-runtime")
# The argument the frozen launch contract authenticated, carried verbatim.
_BRIDGE_CONFIG = json.dumps(
    {
        "state_path": "/app/guard-home/daemon-state.json",
        "manifest_path": "/app/guard-home/managed/codex/hooks.manifest.json",
        "fallback_command": _FALLBACK_COMMAND,
        "start_command": ["/app/hol-guard", "--hol-guard-frozen-daemon-recover", "{}"],
        "query": "",
        "hook_timeouts": {"PreToolUse": 10},
    },
    separators=(",", ":"),
)


def test_frozen_codex_bridge_has_no_fallback_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    children: list[tuple[str, ...]] = []

    def record(argv, **kwargs):
        del kwargs
        children.append(tuple(str(part) for part in argv))
        return subprocess.CompletedProcess(list(argv), 0)

    authenticated: list[str] = []

    def authenticate(*, config_json, **_kwargs):
        authenticated.append(config_json)

    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr(codex_bridge, "trusted_hook_launch", authenticate)
    monkeypatch.setattr(codex_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: _NATIVE)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PRE_TOOL_USE))

    argv = ("hol-guard", frozen_codex_runtime._FROZEN_BRIDGE_ARG, _BRIDGE_CONFIG)
    assert frozen_codex_runtime.run_frozen_internal_command(argv) == 0

    # The registration this hook call carries is authenticated before the
    # runtime reviews anything, and the runtime then carries that same
    # argument.
    assert authenticated == [_BRIDGE_CONFIG]
    assert children == [(str(_NATIVE), "codex-hook-bridge", _BRIDGE_CONFIG)]
    capsys.readouterr()

    monkeypatch.setattr(codex_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PRE_TOOL_USE))
    children.clear()

    assert frozen_codex_runtime.run_frozen_internal_command(argv) == 0

    assert children == []
    decision = json.loads(capsys.readouterr().out)["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert decision["permissionDecisionReason"] == codex_bridge._NATIVE_RUNTIME_UNAVAILABLE
