"""Tests for Cursor native hooks installation and payload mapping."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.cursor import CursorHarnessAdapter
from codex_plugin_scanner.guard.adapters.cursor_hooks import (
    HOOK_SCRIPT_NAME,
    cursor_hook_response_from_guard,
    cursor_hook_should_block,
    cursor_hooks_path,
    install_cursor_hooks,
    prepare_cursor_hook_payload,
    uninstall_cursor_hooks,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_cursor_hook_payload


def _ctx(tmp_path: Path, *, workspace: bool = True) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def test_prepare_cursor_payload_maps_before_shell_execution() -> None:
    prepared = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "curl https://example.com",
            "cwd": "/tmp/project",
        }
    )
    assert prepared["hook_event_name"] == "PreToolUse"
    assert prepared["tool_name"] == "Shell"
    assert prepared["tool_input"] == {
        "command": "curl https://example.com",
        "working_directory": "/tmp/project",
    }


def test_prepare_cursor_payload_maps_before_mcp_execution() -> None:
    prepared = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "fetch",
            "tool_input": '{"id": 1}',
            "url": "http://127.0.0.1:3000/mcp",
        }
    )
    assert prepared["hook_event_name"] == "PreToolUse"
    assert prepared["tool_name"] == "fetch"
    assert prepared["tool_input"]["url"] == "http://127.0.0.1:3000/mcp"


def test_prepare_cursor_payload_maps_before_read_file() -> None:
    prepared = prepare_cursor_hook_payload(
        {
            "hook_event_name": "beforeReadFile",
            "file_path": "/tmp/project/.env",
        }
    )
    assert prepared["tool_name"] == "Read"
    assert prepared["tool_input"]["file_path"] == "/tmp/project/.env"


def test_normalize_cursor_hook_payload_builds_envelope() -> None:
    envelope = normalize_cursor_hook_payload(
        {
            "hook_event_name": "beforeShellExecution",
            "command": "npm install left-pad",
            "cwd": "/repo",
        },
        workspace="/repo",
    )
    assert envelope.harness == "cursor"
    assert envelope.tool_name == "Shell"
    assert envelope.command == "npm install left-pad"


def test_cursor_hook_response_maps_policy_actions() -> None:
    deny = cursor_hook_response_from_guard(
        policy_action="block",
        guard_payload={"review_hint": "Blocked by policy"},
        hook_event_name="beforeShellExecution",
    )
    assert deny["permission"] == "deny"
    assert deny["user_message"] == "Blocked by policy"
    ask = cursor_hook_response_from_guard(
        policy_action="require-reapproval",
        guard_payload={"decision_v2_json": {"harness_message": "Approve in Guard"}},
        hook_event_name="preToolUse",
    )
    assert ask["permission"] == "ask"
    warn_shell = cursor_hook_response_from_guard(
        policy_action="warn",
        guard_payload={"review_hint": "Review exfil pattern", "risk_signals": ["exfil"]},
        hook_event_name="beforeShellExecution",
    )
    assert warn_shell["permission"] == "ask"
    benign_warn = cursor_hook_response_from_guard(
        policy_action="warn",
        guard_payload={},
        hook_event_name="beforeShellExecution",
    )
    assert benign_warn["permission"] == "allow"
    read_review = cursor_hook_response_from_guard(
        policy_action="require-reapproval",
        guard_payload={"review_hint": "Sensitive file"},
        hook_event_name="beforeReadFile",
    )
    assert read_review["permission"] == "deny"
    read_allow = cursor_hook_response_from_guard(
        policy_action="allow",
        guard_payload={},
        hook_event_name="beforeReadFile",
    )
    assert read_allow == {"permission": "allow"}
    assert cursor_hook_should_block(policy_action="block") is True
    assert cursor_hook_should_block(policy_action="require-reapproval") is False


def test_install_cursor_hooks_writes_hooks_json_and_script(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    assert context.workspace_dir is not None
    manifest = install_cursor_hooks(context)
    hooks_path = Path(str(manifest["managed_hooks_path"]))
    script_path = Path(str(manifest["managed_hook_script_path"]))
    assert hooks_path == context.workspace_dir / ".cursor" / "hooks.json"
    assert script_path.name == HOOK_SCRIPT_NAME
    assert script_path.is_file()
    assert script_path.stat().st_mode & stat.S_IXUSR
    payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    hooks = payload["hooks"]
    assert "beforeShellExecution" in hooks
    assert "beforeMCPExecution" in hooks
    assert "preToolUse" in hooks
    assert "beforeReadFile" in hooks
    assert hooks["beforeShellExecution"][0]["failClosed"] is True
    assert hooks["beforeMCPExecution"][0]["failClosed"] is True
    assert hooks["beforeReadFile"][0]["failClosed"] is True
    assert hooks["preToolUse"][0]["failClosed"] is True
    assert hooks["preToolUse"][0]["matcher"]


def test_uninstall_cursor_hooks_restores_backup(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    assert context.workspace_dir is not None
    hooks_path = cursor_hooks_path(context)
    hooks_path.parent.mkdir(parents=True, exist_ok=True)
    original = json.dumps({"version": 1, "hooks": {"afterFileEdit": [{"command": "./fmt.sh"}]}}) + "\n"
    hooks_path.write_text(original, encoding="utf-8")
    install_cursor_hooks(context)
    assert "beforeShellExecution" in json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]
    uninstall_cursor_hooks(context)
    assert hooks_path.read_text(encoding="utf-8") == original


def test_cursor_editor_install_includes_native_hooks(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    assert context.workspace_dir is not None
    manifest = CursorHarnessAdapter()._install_editor(context)
    hooks_path = Path(str(manifest["managed_hooks_path"]))
    assert hooks_path.is_file()
    assert manifest["managed_hook_script_path"]
