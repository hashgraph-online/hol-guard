"""Decision-v2 regressions for local package-protect approvals."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.protect_approvals import _protect_approval_item
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.decisions import GuardDecisionV2


def _artifact(workspace: Path) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="npm:project:package-request",
        name="left-pad",
        harness="npm",
        artifact_type="package_request",
        source_scope="project",
        config_path=str(workspace / "hol-guard.toml"),
    )


def _response(
    *,
    verdict_action: str,
    supply_action: str = "review",
    reason: str | None = "Package provenance requires review.",
) -> dict[str, object]:
    return {
        "verdict": {
            "action": verdict_action,
            "reason": reason,
            "risk_signals": ["package source changed"],
        },
        "receipt": {
            "artifact_id": "npm:project:package-request",
            "artifact_name": "left-pad",
            "artifact_hash": "sha256:package-request",
            "source_scope": "project",
        },
        "request": {
            "targets": [{"package_name": "left-pad"}],
            "package_execution_context": {"schema_version": 1, "digest": "context-v1"},
        },
        "supply_chain_evaluation": {
            "policy_action": supply_action,
            "risk_summary": reason,
            "user_copy": {
                "title": "Hand-built title must not define the decision schema",
                "summary": reason,
                "harness_message": "Hand-built message",
            },
        },
    }


@pytest.mark.parametrize(
    (
        "verdict_action",
        "supply_action",
        "expected_policy_action",
        "expected_decision_action",
        "expected_title",
        "expect_contract_evidence",
    ),
    [
        ("review", "review", "review", "ask", "Approval required", False),
        (
            "require-reapproval",
            "require-reapproval",
            "require-reapproval",
            "ask",
            "Fresh approval required",
            False,
        ),
        ("review", "require-reapproval", "require-reapproval", "ask", "Fresh approval required", True),
        ("block", "review", "block", "block", "Blocked by policy", True),
        ("review", "block", "block", "block", "Blocked by policy", True),
    ],
)
def test_protect_approval_uses_complete_canonical_decision_v2(
    tmp_path: Path,
    verdict_action: str,
    supply_action: str,
    expected_policy_action: str,
    expected_decision_action: str,
    expected_title: str,
    expect_contract_evidence: bool,
) -> None:
    item = _protect_approval_item(
        _response(verdict_action=verdict_action, supply_action=supply_action),
        workspace=tmp_path,
        artifact=_artifact(tmp_path),
    )

    assert item is not None
    assert item["policy_action"] == expected_policy_action
    decision_payload = item["decision_v2_json"]
    assert isinstance(decision_payload, dict)
    decision = GuardDecisionV2.from_dict(decision_payload)
    assert decision.action == expected_decision_action
    assert decision.guard_action == expected_policy_action
    assert decision.user_title == expected_title
    assert decision.reason == "Package provenance requires review."
    assert decision.signals == ()
    assert decision.confidence == "likely"
    assert set(decision_payload) == {
        "guard_action",
        "action",
        "reason",
        "user_title",
        "user_body",
        "harness_message",
        "dashboard_primary_detail",
        "approval_scopes",
        "retry_instruction",
        "signals",
        "confidence",
    }
    scanner_evidence = item["scanner_evidence"]
    assert isinstance(scanner_evidence, list)
    contract_evidence = [
        evidence
        for evidence in scanner_evidence
        if isinstance(evidence, dict) and evidence.get("source") == "decision_contract"
    ]
    assert bool(contract_evidence) is expect_contract_evidence
    if expect_contract_evidence:
        assert contract_evidence[0]["reason_code"] == "authoritative_decision_inconsistent"
        assert contract_evidence[0]["final_action"] == expected_policy_action


def test_protect_approval_supplies_nonempty_reason_when_scanners_have_no_copy(tmp_path: Path) -> None:
    response = _response(verdict_action="review", reason=None)
    item = _protect_approval_item(response, workspace=tmp_path, artifact=_artifact(tmp_path))

    assert item is not None
    decision_payload = item["decision_v2_json"]
    assert isinstance(decision_payload, dict)
    decision = GuardDecisionV2.from_dict(decision_payload)
    assert decision.reason == "package_supply_chain_review"


def test_strict_decision_parser_still_rejects_the_old_partial_protect_shape() -> None:
    old_partial_payload = {
        "action": "require-reapproval",
        "user_title": "Review required",
        "summary": "Review the package request.",
        "harness_message": "Review required.",
    }

    with pytest.raises(ValueError, match="action must be a known Guard action"):
        GuardDecisionV2.from_dict(old_partial_payload)
