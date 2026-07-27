"""Tests for AdaL hook payload and response helpers."""

from __future__ import annotations

import io
import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.adal_hooks import (
    adal_hook_event_is_observation_only,
    adal_hook_response_from_guard,
    adal_hook_should_block,
    emit_adal_hook_response,
    prepare_adal_hook_payload,
)
from codex_plugin_scanner.guard.runtime.actions import (
    normalize_adal_hook_payload,
    normalize_harness_payload,
)


class TestAdaLHookPayload:
    def test_prepare_payload_maps_bash(self) -> None:
        normalized = prepare_adal_hook_payload(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": "git status"},
                "session_id": "session-1",
                "cwd": "/workspace",
            }
        )
        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "Bash"
        assert normalized["workspace_root"] == "/workspace"

    def test_prepare_payload_maps_all_adal_file_tools(self) -> None:
        expected = {
            "read_file": "Read",
            "read_image": "Read",
            "write_file": "Write",
            "create_file": "Write",
            "rewrite_file": "Write",
            "replace_by_string": "Edit",
            "delete_lines": "Edit",
        }
        for raw_name, canonical_name in expected.items():
            normalized = prepare_adal_hook_payload(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": raw_name,
                    "tool_input": {"file_path": "demo.txt"},
                }
            )
            assert normalized["tool_name"] == canonical_name

    def test_prepare_payload_maps_new_string_to_write_content(self) -> None:
        normalized = prepare_adal_hook_payload(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "create_file",
                "tool_input": {"file_path": "demo.txt", "new_string": "hello"},
            }
        )
        assert normalized["tool_input"]["content"] == "hello"

    def test_prepare_payload_preserves_mcp_tool_name(self) -> None:
        normalized = prepare_adal_hook_payload(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__github__create_issue",
                "tool_input": {"title": "demo"},
            }
        )
        assert normalized["tool_name"] == "mcp__github__create_issue"

    def test_normalize_adal_payload_builds_shell_envelope(self, tmp_path: Path) -> None:
        envelope = normalize_adal_hook_payload(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": "git status"},
            },
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "adal"
        assert envelope.action_type == "shell_command"
        assert envelope.tool_name == "Bash"

    def test_normalize_harness_payload_accepts_alias(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "adal-cli",
            "UserPromptSubmit",
            {"prompt": "inspect this repository"},
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "adal"
        assert envelope.action_type == "prompt"


class TestAdaLHookResponses:
    def test_allow_pretool_response_uses_protocol_envelope(self) -> None:
        assert adal_hook_response_from_guard(
            policy_action="allow",
            reason="",
            event_name="PreToolUse",
        ) == {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}

    def test_block_pretool_response_uses_deny(self) -> None:
        response = adal_hook_response_from_guard(
            policy_action="review",
            reason="Approval required.",
            event_name="PreToolUse",
        )
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert response["hookSpecificOutput"]["permissionDecisionReason"] == "Approval required."

    def test_block_prompt_response_uses_top_level_block(self) -> None:
        response = adal_hook_response_from_guard(
            policy_action="block",
            reason="Prompt denied.",
            event_name="UserPromptSubmit",
        )
        assert response["decision"] == "block"
        assert response["reason"] == "Prompt denied."

    def test_observer_event_never_claims_to_block(self) -> None:
        for event_name in ("PostToolUse", "PostToolUseFailure", "PermissionRequest", "Stop"):
            response = adal_hook_response_from_guard(
                policy_action="block",
                reason="Finding recorded.",
                event_name=event_name,
            )
            assert response == {"hookSpecificOutput": {"hookEventName": event_name}}
            assert not adal_hook_should_block(
                policy_action="block",
                event_name=event_name,
            )

    def test_emit_writes_one_json_line(self) -> None:
        stream = io.StringIO()
        emit_adal_hook_response(
            policy_action="allow",
            reason="",
            event_name="Stop",
            output_stream=stream,
        )
        assert stream.getvalue().endswith("\n")
        assert json.loads(stream.getvalue()) == {"hookSpecificOutput": {"hookEventName": "Stop"}}


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "adal" / name).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


class TestAdaLHookFixtures:
    """Recorded AdaL stdin payloads normalize into Guard's shared hook shape."""

    def test_pretooluse_bash_fixture_normalizes_shell_action(self) -> None:
        normalized = prepare_adal_hook_payload(_fixture("pretooluse_bash.json"))

        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "Bash"
        assert normalized["tool_input"] == {"command": "npm install left-pad"}
        assert normalized["session_id"] == "session-redacted-001"

    def test_pretooluse_mcp_fixture_preserves_mcp_tool_identity(self) -> None:
        normalized = prepare_adal_hook_payload(_fixture("pretooluse_mcp.json"))

        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "mcp__my-server__exec"
        assert adal_hook_should_block(policy_action="block", event_name="PreToolUse") is True

    def test_user_prompt_submit_fixture_is_an_enforcement_event(self) -> None:
        normalized = prepare_adal_hook_payload(_fixture("user_prompt_submit.json"))

        assert normalized["hook_event_name"] == "UserPromptSubmit"
        assert adal_hook_event_is_observation_only(str(normalized["hook_event_name"])) is False

    def test_posttooluse_fixture_is_observation_only(self) -> None:
        normalized = prepare_adal_hook_payload(_fixture("posttooluse_observation.json"))

        assert normalized["hook_event_name"] == "PostToolUse"
        assert normalized["tool_name"] == "Read"
        assert adal_hook_event_is_observation_only(str(normalized["hook_event_name"])) is True
        assert adal_hook_should_block(policy_action="block", event_name="PostToolUse") is False
