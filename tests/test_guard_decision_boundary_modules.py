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

pytestmark = pytest.mark.usefixtures("native_prompt_runtime")


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


def test_projection_preserves_valid_package_cloud_reason_code() -> None:
    source = canonical_approval_decision("review", None, reject_contradiction=False).decision_v2_json
    source["package_review_cloud_reason_code"] = "cloud_validation_error"

    decision = canonical_approval_decision("review", source, reject_contradiction=True)

    assert decision.decision_v2_json["package_review_cloud_reason_code"] == "cloud_validation_error"


def test_projection_drops_unknown_package_cloud_reason_code() -> None:
    source = canonical_approval_decision("review", None, reject_contradiction=False).decision_v2_json
    source["package_review_cloud_reason_code"] = "unexpected"

    decision = canonical_approval_decision("review", source, reject_contradiction=True)

    assert "package_review_cloud_reason_code" not in decision.decision_v2_json


@pytest.mark.parametrize("malformed_code", ([], {}))
def test_projection_drops_non_string_package_cloud_reason_code(malformed_code: object) -> None:
    source = canonical_approval_decision("review", None, reject_contradiction=False).decision_v2_json
    source["package_review_cloud_reason_code"] = malformed_code

    decision = canonical_approval_decision("review", source, reject_contradiction=True)

    assert "package_review_cloud_reason_code" not in decision.decision_v2_json
