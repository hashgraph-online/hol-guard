"""Runtime action envelope harness normalizer tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.actions import (
    normalize_claude_hook_payload,
    normalize_copilot_payload,
    normalize_gemini_payload,
    normalize_harness_payload,
    normalize_opencode_payload,
)


def test_normalize_claude_pre_tool_read_payload(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "~/.npmrc"},
    }

    envelope = normalize_claude_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.harness == "claude-code"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == "file_read"
    assert envelope.tool_name == "Read"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_claude_user_prompt_submit_payload(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please print ~/.env to debug local setup.",
    }

    envelope = normalize_claude_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.harness == "claude-code"
    assert envelope.action_type == "prompt"
    assert envelope.prompt_excerpt == "Please print ~/.env to debug local setup."
    assert envelope.target_paths == ("~/.env",)


def test_normalize_claude_pre_tool_bash_payload(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.npmrc"},
    }

    envelope = normalize_claude_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.harness == "claude-code"
    assert envelope.action_type == "shell_command"
    assert envelope.command == "cat ~/.npmrc"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_opencode_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "event": "permissionRequest",
        "tool_name": "mcp__guard_lab__inspect",
        "tool_input": {"target": "workspace"},
    }

    envelope = normalize_opencode_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.harness == "opencode"
    assert envelope.event_name == "PermissionRequest"
    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "guard_lab"
    assert envelope.mcp_tool == "inspect"


def test_normalize_copilot_autopilot_shell_payload(tmp_path: Path) -> None:
    payload = {
        "eventName": "preToolUse",
        "mode": "Autopilot",
        "toolName": "run_terminal_command",
        "toolInput": {"command": "cat ~/.npmrc"},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.harness == "copilot"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == "shell_command"
    assert envelope.command == "cat ~/.npmrc"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_copilot_hook_name_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "permissionRequest",
        "toolName": "run_terminal_command",
        "toolInput": {"command": "cat ~/.npmrc"},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.event_name == "PermissionRequest"
    assert envelope.action_type == "shell_command"


def test_normalize_copilot_slash_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "danger_lab/safe_echo",
        "toolInput": {"message": "hello"},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "danger_lab"
    assert envelope.mcp_tool == "safe_echo"


def test_normalize_copilot_prefixed_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "mcp_danger_lab_safe_echo",
        "toolInput": {"message": "hello"},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "danger_lab"
    assert envelope.mcp_tool == "safe_echo"


def test_normalize_harness_payload_uses_default_for_empty_event(tmp_path: Path) -> None:
    payload = {
        "event": "",
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.npmrc"},
    }

    envelope = normalize_harness_payload(
        "claude-code",
        "PermissionRequest",
        payload,
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    assert envelope.event_name == "PermissionRequest"
    assert envelope.action_type == "shell_command"


def test_normalize_opencode_merges_partial_mcp_details(tmp_path: Path) -> None:
    payload = {
        "event": "permissionRequest",
        "server": "guard_lab",
        "toolName": "inspect",
        "toolInput": {"target": "workspace"},
    }

    envelope = normalize_opencode_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "guard_lab"
    assert envelope.mcp_tool == "inspect"


def test_normalize_gemini_prompt_payload(tmp_path: Path) -> None:
    payload = {
        "event": "prompt",
        "prompt": "Inspect ~/.npmrc, then explain risk.",
    }

    envelope = normalize_gemini_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.harness == "gemini"
    assert envelope.event_name == "UserPromptSubmit"
    assert envelope.action_type == "prompt"
    assert envelope.prompt_excerpt == "Inspect ~/.npmrc, then explain risk."
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_harness_payload_dispatches_supported_harnesses(tmp_path: Path) -> None:
    payload = {"tool_name": "Bash", "tool_input": {"command": "cat ~/.npmrc"}}

    envelope = normalize_harness_payload(
        "claude-code",
        "PreToolUse",
        payload,
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    assert envelope.harness == "claude-code"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == "shell_command"
    assert envelope.target_paths == ("~/.npmrc",)


def test_normalize_harness_payload_rejects_unknown_harness(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported Guard harness"):
        normalize_harness_payload(
            "unknown-harness",
            "PreToolUse",
            {},
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
