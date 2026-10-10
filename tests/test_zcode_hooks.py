"""Tests for the z.ai ZCode hook payload and response helpers."""

from __future__ import annotations

import io
import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters.zcode_hooks import (
    emit_zcode_hook_response,
    prepare_zcode_hook_payload,
    zcode_authority_block_reason,
    zcode_hook_process_exit,
    zcode_hook_response_from_guard,
    zcode_hook_should_block,
)
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _native_hook_permission_decision
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

    def test_prepare_payload_maps_post_tool_use_failure_event(self) -> None:
        normalized = prepare_zcode_hook_payload(
            {"hookEventName": "PostToolUseFailure", "toolName": "Bash", "toolInput": {"command": "ls"}}
        )
        assert normalized["hook_event_name"] == "PostToolUseFailure"

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

    def test_sandbox_required_pretool_response_is_deny(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="sandbox-required", reason="sandbox needed")
        assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_review_pretool_response_asks_through_native_prompt(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="review", reason="Approval required.")
        assert payload == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "Approval required.",
            }
        }

    def test_require_reapproval_pretool_response_asks(self) -> None:
        payload = zcode_hook_response_from_guard(policy_action="require-reapproval", reason="re-approve")
        assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"

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

    def test_authority_block_reason_appends_remediation(self) -> None:
        reason = "HOL Guard requires the native command extension policy before this action can execute."
        enriched = zcode_authority_block_reason(reason)
        assert enriched.startswith(reason)
        assert "hol-guard command controls recover-authority" in enriched
        assert "acknowledge-degraded" not in enriched

    def test_authority_block_reason_is_idempotent(self) -> None:
        once = zcode_authority_block_reason(
            "HOL Guard requires the native command extension policy before this action can execute."
        )
        assert zcode_authority_block_reason(once) == once

    def test_authority_block_reason_leaves_other_reasons_alone(self) -> None:
        assert zcode_authority_block_reason("Blocked by policy.") == "Blocked by policy."

    def test_authority_block_reason_surfaces_in_deny_envelope(self) -> None:
        payload = zcode_hook_response_from_guard(
            policy_action="block",
            reason="HOL Guard requires the native command extension policy before this action can execute.",
        )
        assert (
            "hol-guard command controls recover-authority" in payload["hookSpecificOutput"]["permissionDecisionReason"]
        )

    def test_should_block_flags_blocking_actions(self) -> None:
        assert zcode_hook_should_block(policy_action="review")
        assert zcode_hook_should_block(policy_action="block")
        assert zcode_hook_should_block(policy_action="sandbox-required")
        assert zcode_hook_should_block(policy_action="require-reapproval")
        assert not zcode_hook_should_block(policy_action="allow")

    def test_process_exit_review_pretool_exits_zero_so_ask_json_is_parsed(self) -> None:
        # ZCode only parses stdout JSON for successful hook processes; exit 2
        # would discard the ask envelope and deny the call outright.
        assert zcode_hook_process_exit(policy_action="review", event_name="PreToolUse") == 0
        assert zcode_hook_process_exit(policy_action="require-reapproval", event_name="PreToolUse") == 0

    def test_process_exit_hard_denials_keep_blocking_exit(self) -> None:
        assert zcode_hook_process_exit(policy_action="block", event_name="PreToolUse") == 2
        assert zcode_hook_process_exit(policy_action="sandbox-required", event_name="PreToolUse") == 2

    def test_process_exit_prompt_blocks_keep_blocking_exit(self) -> None:
        assert zcode_hook_process_exit(policy_action="review", event_name="UserPromptSubmit") == 2
        assert zcode_hook_process_exit(policy_action="block", event_name="UserPromptSubmit") == 2

    def test_process_exit_allows_exit_zero(self) -> None:
        assert zcode_hook_process_exit(policy_action="allow", event_name="PreToolUse") == 0

    def test_emit_writes_json_line(self) -> None:
        stream = io.StringIO()
        emit_zcode_hook_response(policy_action="allow", reason="", output_stream=stream)
        assert json.loads(stream.getvalue())["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_emit_review_writes_ask_envelope(self) -> None:
        stream = io.StringIO()
        emit_zcode_hook_response(policy_action="review", reason="Approval required.", output_stream=stream)
        payload = json.loads(stream.getvalue())
        assert payload["hookSpecificOutput"]["permissionDecision"] == "ask"


class TestZCodePermissionDecisionGates:
    def test_review_tier_asks_for_zcode(self) -> None:
        assert _native_hook_permission_decision("review", harness="zcode") == "ask"
        assert _native_hook_permission_decision("require-reapproval", harness="zcode") == "ask"

    def test_hard_denials_stay_deny_for_zcode(self) -> None:
        assert _native_hook_permission_decision("block", harness="zcode") == "deny"
        assert _native_hook_permission_decision("sandbox-required", harness="zcode") == "deny"

    def test_allow_stays_allow_for_zcode(self) -> None:
        assert _native_hook_permission_decision("allow", harness="zcode") == "allow"
