"""Behavior tests for typed Guard runtime decisions."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.decisions import (
    GuardDecisionV2,
    build_authoritative_decision,
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


def _data_flow_signal() -> RiskSignalV2:
    return RiskSignalV2(
        signal_id="data-flow:secret-pipe-http",
        category="network",
        severity="critical",
        confidence="strong",
        detector="data_flow.exfiltration",
        title="Shell pipeline sends a local secret to a network host",
        plain_reason="This command sends local secret to network host.",
        technical_detail="source and sink were detected without retaining secret contents",
        evidence_ref="command",
        redaction_level="summary",
        false_positive_hint="Allow only when the command intentionally moves non-sensitive data.",
        advisory_id=None,
    )


def _clipboard_data_flow_signal() -> RiskSignalV2:
    return RiskSignalV2(
        signal_id="data-flow:clipboard-secret",
        category="secret",
        severity="critical",
        confidence="strong",
        detector="data_flow.exfiltration",
        title="Clipboard receives a local secret",
        plain_reason="This command copies local secret contents into the clipboard.",
        technical_detail="clipboard command receives sensitive source through a pipe",
        evidence_ref="command",
        redaction_level="summary",
        false_positive_hint="Allow only when the clipboard target is intentional.",
        advisory_id=None,
    )


def test_guard_decision_v2_round_trips_to_dict_payload() -> None:
    decision = GuardDecisionV2(
        guard_action="require-reapproval",
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
        "guard_action": "require-reapproval",
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
        guard_action="require-reapproval",
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


@pytest.mark.parametrize(
    ("guard_action", "product_action"),
    [
        ("allow", "allow"),
        ("warn", "warn"),
        ("review", "ask"),
        ("require-reapproval", "ask"),
        ("sandbox-required", "ask"),
        ("block", "block"),
    ],
)
def test_guard_decision_v2_requires_the_exact_product_projection(
    guard_action: str,
    product_action: str,
) -> None:
    payload = decision_from_legacy_policy_action(
        guard_action,  # type: ignore[arg-type]
        reason="projection-test",
    ).to_dict()
    payload["action"] = product_action

    assert GuardDecisionV2.from_dict(payload).guard_action == guard_action

    payload["action"] = "block" if product_action != "block" else "allow"
    with pytest.raises(ValueError, match="must match guard_action"):
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

        assert decision.guard_action == legacy_action
        assert (decision.action, decision.harness_message) == expected
        assert decision.reason == "test-reason"
        assert decision.confidence == "strong"
        assert decision.signals == (_signal(),)


def test_sandbox_required_copy_never_advertises_an_approval_bypass() -> None:
    decision = build_authoritative_decision(
        "sandbox-required",
        reason="sandbox-policy",
        composition_trace={"final_action": "sandbox-required"},
        authority_finalized=True,
    )

    assert decision.enforcement.sandbox_required is True
    assert decision.enforcement.prompt_required is False
    assert decision.enforcement.launch_permitted is False
    assert decision.decision_v2.approval_scopes == ()
    assert decision.decision_v2.retry_instruction == "Run this action in an approved sandbox, then retry."
    assert "approval" not in decision.decision_v2.retry_instruction.lower()


def test_decision_from_legacy_policy_action_uses_highest_confidence_signal() -> None:
    decision = decision_from_legacy_policy_action(
        "review",
        reason="mixed-signals",
        signals=(_weak_signal(), _signal()),
    )

    assert decision.confidence == "strong"
    assert decision.dashboard_primary_detail == "can read local environment secrets"


def test_decision_from_legacy_policy_action_explains_data_flow_exfiltration() -> None:
    decision = decision_from_legacy_policy_action(
        "require-reapproval",
        reason="data-flow-exfiltration",
        signals=(_data_flow_signal(),),
    )

    assert "sends local secret to network host" in decision.harness_message
    assert "Source-to-sink" in decision.dashboard_primary_detail


@pytest.mark.parametrize(
    ("policy_action", "required_copy", "forbidden_copy"),
    [
        ("allow", "allowed this action", "paused"),
        ("warn", "allowed this action with a warning", "paused"),
        ("review", "paused this action", "allowed this action"),
        ("require-reapproval", "paused this action", "allowed this action"),
        ("sandbox-required", "requires a sandbox", "paused"),
        ("block", "blocked this action", "paused"),
    ],
)
def test_data_flow_harness_copy_uses_the_authoritative_action(
    policy_action: GuardAction,
    required_copy: str,
    forbidden_copy: str,
) -> None:
    decision = decision_from_legacy_policy_action(
        policy_action,
        reason="data-flow-exfiltration",
        signals=(_data_flow_signal(),),
    )

    assert required_copy in decision.harness_message
    assert forbidden_copy not in decision.harness_message


def test_decision_from_legacy_policy_action_names_non_network_data_flow_sink() -> None:
    decision = decision_from_legacy_policy_action(
        "require-reapproval",
        reason="data-flow-exfiltration",
        signals=(_clipboard_data_flow_signal(),),
    )

    assert "clipboard" in decision.harness_message
    assert "network host" not in decision.harness_message
    assert "local secret -> clipboard" in decision.dashboard_primary_detail
