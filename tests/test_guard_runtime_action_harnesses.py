"""Runtime action envelope harness normalizer tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.actions import (
    action_envelope_harnesses,
    normalize_claude_hook_payload,
    normalize_copilot_payload,
    normalize_gemini_payload,
    normalize_harness_payload,
    normalize_kimi_payload,
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
        "mcpServers": {"danger_lab": {}},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "danger_lab"
    assert envelope.mcp_tool == "safe_echo"


def test_normalize_copilot_three_part_prefixed_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "mcp_guard_lab_inspect",
        "toolInput": {"target": "workspace"},
        "mcpServers": {"guard_lab": {}},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "guard_lab"
    assert envelope.mcp_tool == "inspect"


def test_normalize_copilot_long_server_prefixed_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "mcp_my_server_name_my_tool",
        "toolInput": {"target": "workspace"},
        "mcpServers": {"my_server_name": {}},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "my_server_name"
    assert envelope.mcp_tool == "my_tool"


def test_normalize_copilot_single_token_tool_prefixed_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "mcp_guard_team_lab_ping",
        "toolInput": {"target": "workspace"},
        "mcpServers": {"guard_team_lab": {}},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "guard_team_lab"
    assert envelope.mcp_tool == "ping"


def test_normalize_copilot_unknown_prefixed_mcp_payload_stays_untyped(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "mcp_guard_team_lab_ping",
        "toolInput": {"target": "workspace"},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "config_change"
    assert envelope.mcp_server is None
    assert envelope.mcp_tool is None


def test_normalize_copilot_tokenized_server_prefixed_mcp_payload(tmp_path: Path) -> None:
    payload = {
        "hookName": "preToolUse",
        "toolName": "mcp_shared_tools_ping",
        "toolInput": {"target": "workspace"},
        "mcpServers": {"shared-tools": {}},
    }

    envelope = normalize_copilot_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "shared-tools"
    assert envelope.mcp_tool == "ping"


def test_normalize_generic_tool_alias_does_not_set_mcp_tool(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool": "Read",
        "tool_input": {"path": "~/.npmrc"},
    }

    envelope = normalize_claude_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "file_read"
    assert envelope.tool_name == "Read"
    assert envelope.mcp_server is None
    assert envelope.mcp_tool is None


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


def test_normalize_opencode_merges_snake_case_partial_mcp_details(tmp_path: Path) -> None:
    payload = {
        "event": "permissionRequest",
        "server": "guard_lab",
        "tool_name": "inspect",
        "tool_input": {"target": "workspace"},
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


def test_normalize_kimi_prompt_payload_flattens_content_parts(tmp_path: Path) -> None:
    envelope = normalize_kimi_payload(
        {
            "event": "UserPromptSubmit",
            "prompt": [{"text": "Inspect ~/.npmrc"}, {"text": "then explain the risk."}],
        },
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    assert envelope.harness == "kimi"
    assert envelope.event_name == "UserPromptSubmit"
    assert envelope.action_type == "prompt"
    assert envelope.prompt_excerpt == "Inspect ~/.npmrc then explain the risk."
    assert envelope.target_paths == ("~/.npmrc",)


def test_shared_action_envelope_contract_covers_every_registered_harness(tmp_path: Path) -> None:
    """Every registered native-hook harness preserves the safe common shell shape."""

    payload = {"tool_name": "Bash", "tool_input": {"command": "cat ~/.npmrc"}}
    expected_harnesses = {"claude": "claude-code", "zai": "zcode"}
    for harness in action_envelope_harnesses():
        envelope = normalize_harness_payload(
            harness,
            "PreToolUse",
            payload,
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        case_id = f"ADAPTER-ENVELOPE-001:{harness}"
        expected = {
            "harness": expected_harnesses.get(harness, harness),
            "event_name": "PreToolUse",
            "action_type": "shell_command",
            "target_paths": ("~/.npmrc",),
        }
        actual = {
            "harness": envelope.harness,
            "event_name": envelope.event_name,
            "action_type": envelope.action_type,
            "target_paths": envelope.target_paths,
        }
        assert actual == expected, f"{case_id}: input={payload!r} expected={expected!r} actual={actual!r}"


def test_hook_runtime_helpers_survive_action_normalizer_first_import(tmp_path: Path) -> None:
    """A native hook cannot lose runtime helpers because another hook loads first."""

    script = "\n".join(
        (
            "from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload",
            "normalize_harness_payload('kimi', 'PreToolUse', "
            "{'tool_name': 'Bash', 'tool_input': {'command': 'printf safe'}})",
            "from codex_plugin_scanner.guard.cli.commands_hook_generic import _artifact_id_from_event",
            "from codex_plugin_scanner.guard.cli.commands_support_codex_paths import _collect_codex_tool_response_text",
            "assert _artifact_id_from_event('pi', {'tool_name': 'Bash'}).endswith(':Bash')",
            "assert _collect_codex_tool_response_text({'stdout': 'safe'}) == 'safe'",
        )
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_normalize_harness_payload_dispatches_grok(tmp_path: Path) -> None:
    envelope = normalize_harness_payload(
        "grok",
        "PreToolUse",
        {
            "hookEventName": "pre_tool_use",
            "toolName": "grep",
            "toolInput": {"pattern": "TODO", "path": "src"},
        },
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )
    assert envelope.harness == "grok"
    assert envelope.event_name == "PreToolUse"


def test_normalize_harness_payload_rejects_unknown_harness(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported Guard harness"):
        normalize_harness_payload(
            "unknown-harness",
            "PreToolUse",
            {},
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
