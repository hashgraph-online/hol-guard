"""Tests for the z.ai ZCode hook payload and response helpers."""

from __future__ import annotations

import io
import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.zcode_hooks import (
    emit_zcode_hook_response,
    prepare_zcode_hook_payload,
    zcode_hook_response_from_guard,
    zcode_hook_should_block,
)
from codex_plugin_scanner.guard.runtime.actions import (
    normalize_harness_payload,
    normalize_zcode_hook_payload,
)


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "zcode" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class TestZCodeHookPayload:
    def test_prepare_payload_maps_bash_fixture(self) -> None:
        normalized = prepare_zcode_hook_payload(_fixture("pretooluse_bash.json"))
        assert normalized["hook_event_name"] == "PreToolUse"
        assert normalized["tool_name"] == "Bash"
        assert normalized["session_id"] == "session-redacted-001"
        assert normalized["workspace_root"] == "<workspace>"

    def test_prepare_payload_maps_mcp_fixture(self) -> None:
        normalized = prepare_zcode_hook_payload(_fixture("pretooluse_mcp.json"))
        assert normalized["tool_name"] == "mcp__lean-ctx__ctx_call"
        assert normalized["tool_input"]["name"] == "ctx_call"

    def test_prepare_payload_maps_prompt_fixture(self) -> None:
        normalized = prepare_zcode_hook_payload(_fixture("user_prompt_submit.json"))
        assert normalized["hook_event_name"] == "UserPromptSubmit"
        assert normalized["prompt"] == "show me how to read a secret file"

    def test_prepare_payload_camelcase_keys(self) -> None:
        normalized = prepare_zcode_hook_payload(
            {"hookEventName": "PostToolUse", "toolName": "Read", "toolInput": {"path": "x"}, "sessionId": "s"}
        )
        assert normalized["hook_event_name"] == "PostToolUse"
        assert normalized["tool_name"] == "Read"
        assert normalized["session_id"] == "s"

    def test_prepare_payload_malformed_is_safe(self) -> None:
        assert prepare_zcode_hook_payload({}) == {}

    def test_normalize_zcode_hook_payload_builds_shell_envelope(self, tmp_path: Path) -> None:
        envelope = normalize_zcode_hook_payload(
            _fixture("pretooluse_bash.json"),
            workspace=tmp_path / "workspace",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"
        assert envelope.action_type == "shell_command"
        assert envelope.event_name == "PreToolUse"

    def test_normalize_harness_payload_accepts_zcode(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zcode",
            "PreToolUse",
            _fixture("pretooluse_mcp.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"

    def test_normalize_harness_payload_accepts_zai_alias(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "zai",
            "UserPromptSubmit",
            _fixture("user_prompt_submit.json"),
            workspace=tmp_path / "ws",
            home_dir=tmp_path,
        )
        assert envelope.harness == "zcode"


class TestZCodeHookResponses:
    def test_allow_pretool_response(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="allow", reason="")
        assert payload == {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}

    def test_block_pretool_response(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="block", reason="Blocked by HOL Guard.")
        assert payload == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Blocked by HOL Guard.",
            }
        }

    def test_block_uses_default_reason_when_empty(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="block", reason="")
        reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
        assert reason == "Blocked by HOL Guard."

    def test_block_userprompt_response(self) -> None:
        payload = zcode_hook_response_from_guard(
            policy_action="require-reapproval", reason="needs approval", event_name="UserPromptSubmit"
        )
        assert payload["decision"] == "block"
        assert payload["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"

    def test_should_block_flags_blocking_actions(self) -> None:
        assert zcode_hook_should_block(policy_action="block")
        assert zcode_hook_should_block(policy_action="sandbox-required")
        assert zcode_hook_should_block(policy_action="require-reapproval")
        assert not zcode_hook_should_block(policy_action="allow")

    def test_emit_writes_json_line(self) -> None:
        stream = io.StringIO()
        emit_zcode_hook_response(policy_action="allow", reason="", output_stream=stream)
        assert json.loads(stream.getvalue())["hookSpecificOutput"]["permissionDecision"] == "allow"
