"""Cloud fallback routing through the live evaluator."""

from __future__ import annotations


def _cloud_result_should_defer_to_bundle(
    evaluation: _eval.PackageRequestEvaluation,
    *,
    bundle_evaluation: _eval._EvaluationDraft | None,
) -> bool:
    if bundle_evaluation is None:
        return False
    if not (bundle_evaluation.decision == "block" or not bundle_evaluation.refresh_required):
        return False
    reason_codes = {str(reason.get("code") or "") for reason in evaluation.reasons if isinstance(reason, dict)}
    if evaluation.decision == "block" and evaluation.policy_action == "block":
        return False
    defer_codes = {"cloud_auth_error", "cloud_http_error", "cloud_timeout"}
    if not any(code in defer_codes for code in reason_codes):
        return False
    return _eval._decision_rank(bundle_evaluation.decision) > _eval._decision_rank(evaluation.decision)


def _cloud_fallback_reason(*, code: str, message: str) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "severity": "unknown",
        "source": "guard-cloud",
    }


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
