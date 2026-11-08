"""Revoked compatibility hooks must stop before native capability discovery."""

from __future__ import annotations

import io
import json
import subprocess
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError


def _configure(monkeypatch, tmp_path: Path, *, desktop: bool) -> dict[str, object]:
    data = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash"})
    monkeypatch.setattr(bridge, "_desktop_probe_lane", lambda: desktop)
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO(data))
    monkeypatch.setattr(bridge, "_desktop_transition_probe_command", lambda **_kwargs: None)
    monkeypatch.setattr(
        bridge, "_bound_hook_input", lambda _timeouts: ("PreToolUse", data, 10.0, time.monotonic(), data)
    )
    guard_home = tmp_path / "guard-home"
    return {
        "state_path": guard_home / "daemon-state.json",
        "fallback_command": ("fallback",),
        "start_command": ("start",),
        "query": "",
        "hook_timeouts": {"PreToolUse": 10},
        "manifest_path": guard_home / "managed" / "codex" / "hooks-fixture.manifest.json",
        "config_json": "{}",
    }


@pytest.mark.parametrize("desktop", [False, True])
def test_missing_registration_never_discovers_native_capabilities(tmp_path, monkeypatch, capsys, desktop):
    config = _configure(monkeypatch, tmp_path, desktop=desktop)
    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda *_: pytest.fail("capabilities were probed"))
    monkeypatch.setattr(bridge.subprocess, "run", lambda *a, **kw: pytest.fail("a process was launched"))

    assert bridge.main(**config) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(captured.err)["causes"] == [{"reason_code": "codex_hook_manifest_missing"}]


@pytest.mark.parametrize("desktop", [False, True])
def test_invalid_registration_never_discovers_native_capabilities(tmp_path, monkeypatch, capsys, desktop):
    config = _configure(monkeypatch, tmp_path, desktop=desktop)

    def reject(**_kwargs):
        raise CodexHookIntegrityError("codex_hook_manifest_authentication_invalid", "changed registration")

    monkeypatch.setattr(bridge, "trusted_hook_launch", reject)
    monkeypatch.setattr(bridge, "_native_bridge_executable", lambda *_: pytest.fail("capabilities were probed"))
    monkeypatch.setattr(bridge.subprocess, "run", lambda *a, **kw: pytest.fail("a process was launched"))

    assert bridge.main(**config) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert json.loads(captured.err)["causes"] == [{"reason_code": "codex_hook_manifest_authentication_invalid"}]


@pytest.mark.parametrize("desktop", [False, True])
def test_authenticated_registration_discovers_then_launches_native_runtime(tmp_path, monkeypatch, desktop):
    config = _configure(monkeypatch, tmp_path, desktop=desktop)
    events = []

    def authenticate(**_kwargs):
        events.append("authenticate")

    def discover(_home):
        events.append("discover")
        return tmp_path / "runtime"

    def launch(argv, **_kwargs):
        events.append("launch")
        assert argv[0] == str(tmp_path / "runtime")
        return subprocess.CompletedProcess(argv, 0, b"{}", b"")

    monkeypatch.setattr(bridge, "trusted_hook_launch", authenticate)
    monkeypatch.setattr(bridge, "_native_bridge_executable", discover)
    monkeypatch.setattr(bridge.subprocess, "run", launch)

    assert bridge.main(**config) == 0
    assert events == ["authenticate", "discover", "launch"]
