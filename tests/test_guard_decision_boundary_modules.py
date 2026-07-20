"""Regression coverage for the decision-boundary module split."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.decision_boundaries import (
    CanonicalApprovalDecision,
    canonical_approval_decision,
)
from codex_plugin_scanner.guard.decision_projection_boundaries import (
    CanonicalApprovalDecision as ProjectionCanonicalApprovalDecision,
)
from codex_plugin_scanner.guard.decision_projection_boundaries import (
    canonical_approval_decision as projection_canonical_approval_decision,
)
from codex_plugin_scanner.guard.runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT


def test_decision_boundary_facade_preserves_approval_projection_exports() -> None:
    assert CanonicalApprovalDecision is ProjectionCanonicalApprovalDecision
    assert canonical_approval_decision is projection_canonical_approval_decision

    decision = canonical_approval_decision(
        "review",
        None,
        reject_contradiction=False,
    )

    assert decision.policy_action == "review"
    assert decision.decision_v2_json["action"] == "ask"
    assert decision.decision_v2_json["guard_action"] == "review"


def test_split_projection_boundary_still_rejects_hidden_action_fields() -> None:
    with pytest.raises(ValueError, match=AUTHORITATIVE_DECISION_INCONSISTENT):
        canonical_approval_decision(
            "allow",
            {"action": "allow", "final_action": "block"},
            reject_contradiction=True,
        )
