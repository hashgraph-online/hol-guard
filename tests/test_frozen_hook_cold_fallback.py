"""A frozen Guard never starts a cold `hol-guard hook` evaluator from a hook bridge.

Neither harness has a Python launcher left: Guard installs the native command
for both. A hook still registered with the old frozen bridge argument starts
no child and tells the user to run repair.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from codex_plugin_scanner.guard import frozen_codex_runtime

_PRE_TOOL_USE = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})


def test_stale_frozen_codex_bridge_starts_nothing_and_asks_for_repair(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    children: list[object] = []

    def record(argv, **_kwargs):
        children.append(argv)
        return subprocess.CompletedProcess(list(argv), 0)

    monkeypatch.setattr(subprocess, "run", record)
    monkeypatch.setattr(subprocess, "Popen", record)
    monkeypatch.setattr("sys.stdin", io.StringIO(_PRE_TOOL_USE))

    argv = ("hol-guard", frozen_codex_runtime._FROZEN_BRIDGE_ARG, "{}")
    assert frozen_codex_runtime.run_frozen_internal_command(argv) == 2

    assert children == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hol-guard repair" in captured.err
