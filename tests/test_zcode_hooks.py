"""Tests for the z.ai ZCode hook payload and response helpers."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.guard.adapters._modules.zcode.zcode_hooks import (
    zcode_authority_block_reason,
    zcode_hook_process_exit,
)
from codex_plugin_scanner.guard.runtime.actions import (
    normalize_harness_payload,
    normalize_zcode_hook_payload,
)


def _fixture(name: str) -> dict[str, object]:
    payload = json.loads((Path(__file__).parent / "fixtures" / "zcode" / name).read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else {}


class TestZCodeHookPayload:
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
