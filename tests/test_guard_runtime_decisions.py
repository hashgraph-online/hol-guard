"""Behavior tests for typed Guard runtime decisions."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.decisions import (
    GuardDecisionV2,
    decision_from_legacy_policy_action,
)
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2


def _signal() -> RiskSignalV2:
    return RiskSignalV2(
        signal_id="secret:env-read",
        category="secret",
        severity="high",
        confidence="strong",
        detector="guard-risk-v2",
        title="Can read local environment secrets",
        plain_reason="can read local environment secrets",
        technical_detail=None,
        evidence_ref="artifact",
        redaction_level="summary",
        false_positive_hint="Review whether this is read-only source search.",
        advisory_id=None,
    )


def _weak_signal() -> RiskSignalV2:
    return RiskSignalV2(
        signal_id="network:traffic",
        category="network",
        severity="medium",
        confidence="weak",
        detector="guard-risk-v2",
        title="Can send network traffic",
        plain_reason="can send or receive network traffic",
        technical_detail=None,
        evidence_ref="artifact",
        redaction_level="summary",
        false_positive_hint=None,
        advisory_id=None,
    )


def test_guard_decision_v2_round_trips_to_dict_payload() -> None:
    decision = GuardDecisionV2(
        action="ask",
        reason="require-reapproval",
        user_title="Review this changed action",
        user_body="HOL Guard needs a fresh decision before this can run.",
        harness_message="HOL Guard paused this changed action.",
        dashboard_primary_detail="Changed shell command reads local secrets.",
        approval_scopes=("artifact", "workspace"),
        retry_instruction="Choose an approval scope, then retry in the harness.",
        signals=(_signal(),),
        confidence="strong",
    )

    payload = decision.to_dict()

    assert payload == {
        "action": "ask",
        "reason": "require-reapproval",
        "user_title": "Review this changed action",
        "user_body": "HOL Guard needs a fresh decision before this can run.",
        "harness_message": "HOL Guard paused this changed action.",
        "dashboard_primary_detail": "Changed shell command reads local secrets.",
        "approval_scopes": ["artifact", "workspace"],
        "retry_instruction": "Choose an approval scope, then retry in the harness.",
        "signals": [_signal().to_dict()],
        "confidence": "strong",
    }
    assert GuardDecisionV2.from_dict(payload) == decision


def test_guard_decision_v2_rejects_non_object_signal_entries() -> None:
    payload = GuardDecisionV2(
        action="ask",
        reason="require-reapproval",
        user_title="Review this changed action",
        user_body="HOL Guard needs a fresh decision before this can run.",
        harness_message="HOL Guard paused this changed action.",
        dashboard_primary_detail="Changed shell command reads local secrets.",
        approval_scopes=("artifact", "workspace"),
        retry_instruction="Choose an approval scope, then retry in the harness.",
        signals=(_signal(),),
        confidence="strong",
    ).to_dict()
    payload["signals"] = [_signal().to_dict(), "not-a-signal"]

    with pytest.raises(ValueError, match="signal item must be an object"):
        GuardDecisionV2.from_dict(payload)


def test_decision_from_legacy_policy_action_maps_all_actions() -> None:
    cases = {
        "allow": ("allow", "Policy allows this action."),
        "warn": ("warn", "HOL Guard noticed risk signals, but policy allows the harness to continue."),
        "review": ("ask", "HOL Guard needs your approval before this action can run."),
        "sandbox-required": ("ask", "HOL Guard wants this action reviewed and run in a sandboxed path."),
        "require-reapproval": ("ask", "HOL Guard needs a fresh approval because this action changed."),
        "block": ("block", "HOL Guard blocked this action."),
    }

    for legacy_action, expected in cases.items():
        decision = decision_from_legacy_policy_action(
            legacy_action,
            reason="test-reason",
            signals=(_signal(),),
        )

        assert (decision.action, decision.harness_message) == expected
        assert decision.reason == "test-reason"
        assert decision.confidence == "strong"
        assert decision.signals == (_signal(),)


def test_decision_from_legacy_policy_action_uses_highest_confidence_signal() -> None:
    decision = decision_from_legacy_policy_action(
        "review",
        reason="mixed-signals",
        signals=(_weak_signal(), _signal()),
    )

    assert decision.confidence == "strong"
    assert decision.dashboard_primary_detail == "can read local environment secrets"
