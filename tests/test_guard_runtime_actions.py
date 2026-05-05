"""Runtime action envelope tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.actions import (
    GuardActionEnvelope,
    normalize_codex_hook_payload,
    redacted_workspace_label,
    stable_action_hash,
)


def test_guard_action_envelope_round_trips_to_dict() -> None:
    envelope = GuardActionEnvelope(
        schema_version=1,
        action_id="action-123",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace="/workspace/demo",
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        target_paths=("package.json",),
        network_hosts=("example.com",),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={"tool_name": "Bash"},
    )

    payload = envelope.to_dict()
    restored = GuardActionEnvelope.from_dict(payload)

    assert payload == {
        "schema_version": 1,
        "action_id": "action-123",
        "harness": "codex",
        "event_name": "PreToolUse",
        "action_type": "shell_command",
        "workspace": "/workspace/demo",
        "workspace_hash": "workspace-hash",
        "tool_name": "Bash",
        "command": "printf ok",
        "prompt_excerpt": None,
        "target_paths": ["package.json"],
        "network_hosts": ["example.com"],
        "mcp_server": None,
        "mcp_tool": None,
        "package_manager": None,
        "package_name": None,
        "script_name": None,
        "raw_payload_redacted": {"tool_name": "Bash"},
    }
    assert restored == envelope


def test_guard_action_envelope_from_dict_requires_schema_version() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        GuardActionEnvelope.from_dict({"harness": "codex"})


def test_stable_action_hash_trims_outer_command_whitespace_only() -> None:
    base = GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="Bash",
        command="printf ok",
        prompt_excerpt=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    padded = GuardActionEnvelope.from_dict({**base.to_dict(), "command": "  printf ok  "})
    internally_changed = GuardActionEnvelope.from_dict({**base.to_dict(), "command": "printf  ok"})

    assert stable_action_hash(base) == stable_action_hash(padded)
    assert stable_action_hash(base) != stable_action_hash(internally_changed)


def test_redacted_workspace_label_hides_home_directory(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace = home_dir / "projects" / "demo"

    label = redacted_workspace_label(workspace, home_dir=home_dir)

    assert label == "~/projects/demo"
    assert str(home_dir) not in label


def test_normalize_codex_pre_tool_bash_payload(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf ok"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=workspace, home_dir=tmp_path)

    assert envelope.harness == "codex"
    assert envelope.event_name == "PreToolUse"
    assert envelope.action_type == "shell_command"
    assert envelope.tool_name == "Bash"
    assert envelope.command == "printf ok"
    assert envelope.workspace == str(workspace)
    assert envelope.workspace_hash is not None
    assert envelope.raw_payload_redacted["tool_input"] == {"command": "printf ok"}


def test_normalize_codex_prompt_payload_extracts_prompt_excerpt(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "UserPromptSubmit",
        "prompt": "Please inspect ~/.npmrc and summarize the token setup.",
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "prompt"
    assert envelope.prompt_excerpt == "Please inspect ~/.npmrc and summarize the token setup."
    assert envelope.target_paths == ("~/.npmrc",)
    assert "prompt" in envelope.raw_payload_redacted


def test_normalize_codex_mcp_payload_extracts_server_and_tool(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__danger_lab__dangerous_delete",
        "tool_input": {"target": "workspace"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "mcp_tool"
    assert envelope.mcp_server == "danger_lab"
    assert envelope.mcp_tool == "dangerous_delete"
    assert envelope.tool_name == "mcp__danger_lab__dangerous_delete"


def test_normalize_codex_post_tool_redacts_raw_output(tmp_path: Path) -> None:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat fixture.txt"},
        "tool_response": {"content": "secret output should not persist"},
    }

    envelope = normalize_codex_hook_payload(payload, workspace=tmp_path / "workspace", home_dir=tmp_path)

    assert envelope.action_type == "shell_command"
    assert envelope.command == "cat fixture.txt"
    assert envelope.raw_payload_redacted["tool_response"] == "[redacted]"
    assert "secret output" not in str(envelope.raw_payload_redacted)
