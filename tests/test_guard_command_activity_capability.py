"""Trusted workflow-capability command activity integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_command_activity import (
    record_pre_hook_command_activity_best_effort,
)
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_activity_contract import ActivityDecisionReason
from codex_plugin_scanner.guard.runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_or_create_installation_correlation_key,
)
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize(
    "command,action,expected_reason",
    [
        ("git diff --stat", "allow", ActivityDecisionReason.CAPABILITY),
        ("rm -rf ./generated-output", "review", ActivityDecisionReason.EXTENSION_MATCH),
    ],
)
def test_only_claimed_final_allow_records_capability(
    tmp_path: Path,
    command: str,
    action: GuardAction,
    expected_reason: ActivityDecisionReason,
) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home, prime_policy_integrity=False)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": command},
        "tool_call_id": f"codex_{action}_abcdef1234567890",
    }

    assert record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=guard_home,
        harness="codex",
        event="PreToolUse",
        payload=payload,
        policy_action=action,
        receipt_id=f"receipt:workflow-{action}",
        prompted=action == "review",
        workflow_authorization_claimed=True,
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    correlation = derive_proven_request_correlation(
        harness="codex",
        event="PreToolUse",
        payload=payload,
        key=load_or_create_installation_correlation_key(guard_home),
    )
    assert correlation is not None
    activity = store.get_command_activity_by_request_correlation(correlation)
    assert activity is not None
    assert activity.decision_reason_code is expected_reason
    if action == "allow":
        assert activity.match_count == 0
    else:
        assert activity.match_count > 0
