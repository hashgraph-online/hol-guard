"""Policy-only activity remains correlated when native rule evidence is unavailable."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_support_command_activity as activity_support
from codex_plugin_scanner.guard.native_command_control_authority_io import NativeCommandControlMutationRequiredError
from codex_plugin_scanner.guard.runtime.command_activity_api_contract import CommandActivityListQuery
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    CommandExecutionStatus,
)
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from codex_plugin_scanner.guard.store import GuardStore


def test_missing_native_review_records_policy_only_command_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(activity_support, "_evaluate_payload_command", lambda *_args, **_kwargs: None)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    assert not activity_support.record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload={"tool_name": "Read", "tool_input": {"path": "note.txt"}},
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )

    payload = {
        "tool_name": "Shell",
        "tool_input": {"command": "git diff --stat # guard-private-command-sentinel"},
        "tool_call_id": "toolcall_abcdef1234567890",
    }
    assert activity_support.record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action="allow",
        receipt_id=None,
        prompted=False,
        approval_reuse_status=ActivityApprovalReuseStatus.ACCEPTED,
        workflow_authorization_claimed=True,
    )
    assert activity_support.record_post_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PostToolUse",
        payload=payload,
        succeeded=True,
    )
    key = load_or_create_installation_correlation_key(guard_home)
    correlation = derive_proven_request_correlation(harness="codex", event="PostToolUse", payload=payload, key=key)
    assert correlation is not None
    activity = store.get_command_activity_by_request_correlation(correlation)
    assert activity is not None
    assert activity.execution_status is CommandExecutionStatus.CONFIRMED_SUCCESS
    assert activity.decision_reason_code is ActivityDecisionReason.CAPABILITY
    assert activity.match_count == 0
    assert store.count_command_activity_rule_hits() == 0
    page = store.list_command_activity_page(CommandActivityListQuery())
    assert "guard-private-command-sentinel" not in str(page)


def test_native_authority_error_does_not_claim_policy_only_activity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def mutation_required(*_args: object, **_kwargs: object) -> None:
        raise NativeCommandControlMutationRequiredError()

    monkeypatch.setattr(activity_support, "_evaluate_payload_command", mutation_required)
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    assert not activity_support.record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload={"tool_name": "Shell", "tool_input": {"command": "git diff --stat"}},
        policy_action="allow",
        receipt_id=None,
        prompted=False,
    )
    assert store.count_command_activities() == 0
    assert store.get_command_activity_persistence_health().last_error_code == "pre_native_control_unavailable"
