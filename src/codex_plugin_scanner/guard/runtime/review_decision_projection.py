"""Project review provenance and package availability without changing authority."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from ..models import GuardAction
from ..policy.engine import build_decision_v2
from .approval_reuse import ApprovalReuseDecision
from .signals import RiskSignalV2

if TYPE_CHECKING:
    from .supply_chain_package_eval import PackageRequestEvaluation


def runtime_review_decision_payload(
    policy_action: GuardAction,
    *,
    decision_signals: Sequence[RiskSignalV2],
    approval_reuse: ApprovalReuseDecision | None,
    trusted_request_override: bool,
    package_evaluation: PackageRequestEvaluation | None,
) -> dict[str, object]:

    decision_v2 = build_decision_v2(policy_action, reason=policy_action, signals=decision_signals)
    decision_v2_payload = decision_v2.to_dict()
    if approval_reuse is not None:
        decision_v2_payload.update(
            approval_reuse.policy_rule_evidence(policy_action, overridden=trusted_request_override)
        )
    if package_evaluation is not None:
        cloud_reason_codes = {
            str(reason.get("code") or "") for reason in package_evaluation.reasons if isinstance(reason, Mapping)
        }
        if (
            package_evaluation.policy_rule_identity is not None
            and package_evaluation.policy_action == policy_action
            and not trusted_request_override
            and "policyId" not in decision_v2_payload
        ):
            decision_v2_payload.update(package_evaluation.policy_rule_identity.to_dict())
        for cloud_reason_code in (
            "cloud_auth_error",
            "cloud_validation_error",
            "cloud_http_error",
            "cloud_timeout",
        ):
            if cloud_reason_code in cloud_reason_codes:
                decision_v2_payload["package_review_cloud_reason_code"] = cloud_reason_code
                break
    return decision_v2_payload
