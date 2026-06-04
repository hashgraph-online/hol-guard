"""Tests for runtime harness attribution (Cursor vs Claude Code hooks)."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime.harness_attribution import (
    cursor_hook_query_extras,
    cursor_runtime_detected,
    resolve_runtime_hook_harness,
)


def test_cursor_runtime_detected_from_cursor_env() -> None:
    assert cursor_runtime_detected({"CURSOR_VERSION": "2.0.0"}) is True
    assert cursor_runtime_detected({}) is False


def test_resolve_runtime_hook_harness_maps_claude_to_cursor_in_cursor() -> None:
    env = {"CURSOR_VERSION": "2.0.0", "CURSOR_PROJECT_DIR": "/tmp/project"}
    assert resolve_runtime_hook_harness("claude-code", env=env) == "cursor"
    assert resolve_runtime_hook_harness("opencode", env=env) == "opencode"


def test_cursor_hook_query_extras_includes_runtime_harness_and_workspace() -> None:
    extras = cursor_hook_query_extras(
        {"CURSOR_VERSION": "1.2.3", "CURSOR_PROJECT_DIR": "/Users/me/repo"},
    )
    assert extras == {"runtime-harness": "cursor", "workspace": "/Users/me/repo"}


def test_claude_hook_http_url_includes_cursor_runtime_harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CURSOR_VERSION", "9.9.9")
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(tmp_path / "workspace"))
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "ignored",
        guard_home=tmp_path / "guard",
    )
    url = ClaudeCodeHarnessAdapter._hook_http_url(context)
    assert "runtime-harness=cursor" in url
    assert f"workspace={tmp_path / 'workspace'}" in url.replace("%2F", "/")


def test_guard_hook_records_cursor_harness_for_cursor_env(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.test_guard_runtime import _build_guard_fixture, _run_guard_hook

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    monkeypatch.setenv("CURSOR_VERSION", "2.0.0")
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(workspace_dir))
    monkeypatch.setattr(guard_commands_module, "ensure_guard_daemon", lambda _guard_home: "http://127.0.0.1:4455")

    rc, payload = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="claude-code",
        event={
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {"command": "rm -rf /tmp/hol-guard-cursor-attribution-test"},
            "source_scope": "project",
        },
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert rc == 1
    assert isinstance(payload, dict)
    assert payload["harness"] == "cursor"
