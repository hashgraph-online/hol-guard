"""Regression tests for Cursor native hook installation and payload mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    _MANAGED_HOOK_EVENTS,
    _MANAGED_HOOK_TIMEOUT_SECONDS,
    _strip_managed_hook_entries,
    install_cursor_hooks,
    prepare_cursor_hook_payload,
)


def test_managed_hook_events_exclude_pretooluse() -> None:
    assert "preToolUse" not in _MANAGED_HOOK_EVENTS
    assert _MANAGED_HOOK_EVENTS == (
        "beforeShellExecution",
        "beforeMCPExecution",
        "beforeReadFile",
    )


def test_prepare_cursor_hook_payload_maps_before_read_file() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/secrets.env",
        }
    )
    assert payload["hook_event_name"] == "PreToolUse"
    assert payload["tool_name"] == "Read"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["file_path"] == "/tmp/secrets.env"
    assert tool_input["path"] == "/tmp/secrets.env"


def test_prepare_cursor_hook_payload_infers_shell_without_event_name() -> None:
    payload = prepare_cursor_hook_payload({"command": "echo hello", "cwd": "/tmp"})
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_prepare_cursor_hook_payload_infers_read_without_event_name() -> None:
    payload = prepare_cursor_hook_payload({"file_path": "/tmp/secrets.env"})
    assert payload["tool_name"] == "Read"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["file_path"] == "/tmp/secrets.env"


def test_prepare_cursor_hook_payload_maps_before_shell_execution() -> None:
    payload = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "echo hello",
            "cwd": "/tmp",
        }
    )
    assert payload["tool_name"] == "Shell"
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    assert tool_input["command"] == "echo hello"
    assert tool_input["working_directory"] == "/tmp"


def test_cursor_hook_script_source_skips_missing_workspace(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.cursor_hooks import cursor_hook_script_source

    context = HarnessContext(home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=tmp_path)
    source = cursor_hook_script_source(context)
    assert "Path(candidate).is_dir()" in source


def test_strip_managed_hook_entries_removes_hol_guard_pretooluse(tmp_path: Path) -> None:
    script_path = tmp_path / "hol-guard-cursor-hook.py"
    script_path.write_text("# Managed by HOL Guard\n", encoding="utf-8")
    entries = [
        {"command": "lean-ctx hook rewrite", "matcher": "Shell"},
        {
            "command": str(script_path.resolve()),
            "failClosed": True,
            "matcher": "Shell|MCP|mcp__.*|Bash|Read",
            "timeout": 35,
        },
    ]
    stripped = _strip_managed_hook_entries(entries, script_path=script_path)
    assert stripped == [{"command": "lean-ctx hook rewrite", "matcher": "Shell"}]


def test_install_cursor_hooks_strips_legacy_pretooluse_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    guard_home = tmp_path / "guard"
    workspace = tmp_path / "workspace"
    home.mkdir()
    guard_home.mkdir()
    workspace.mkdir()
    cursor_dir = home / ".cursor"
    cursor_dir.mkdir()
    script_path = cursor_dir / "hooks" / "hol-guard-cursor-hook.py"
    hooks_path = cursor_dir / "hooks.json"
    hooks_path.write_text(
        json.dumps(
            {
                "version": 1,
                "hooks": {
                    "preToolUse": [
                        {"command": "lean-ctx hook rewrite", "matcher": "Shell"},
                        {
                            "command": str(script_path),
                            "failClosed": True,
                            "matcher": "Shell|Read",
                            "timeout": 35,
                        },
                    ]
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.cursor_hooks._resolve_guard_cli_command",
        lambda: ["hol-guard"],
    )
    context = HarnessContext(home_dir=home, guard_home=guard_home, workspace_dir=workspace)
    result = install_cursor_hooks(context)
    installed = json.loads(hooks_path.read_text(encoding="utf-8"))
    pre_tool_use = installed["hooks"].get("preToolUse")
    if pre_tool_use is not None:
        assert all("hol-guard-cursor-hook.py" not in str(entry.get("command", "")) for entry in pre_tool_use)
    assert "beforeShellExecution" in installed["hooks"]
    assert result["managed_hook_events"] == list(_MANAGED_HOOK_EVENTS)
    for event_name in _MANAGED_HOOK_EVENTS:
        entry = installed["hooks"][event_name][-1]
        assert entry["timeout"] == _MANAGED_HOOK_TIMEOUT_SECONDS
