use super::*;

/// Convert a finalized `PackageEvalResult` back to the `EvaluationDraft` fields
/// used by `cloud_result_should_defer_to_bundle` (which operates on drafts).
#[allow(dead_code)]
pub(super) fn evaluation_to_draft(evaluation: &PackageEvalResult) -> EvaluationDraft {
    EvaluationDraft {
        decision: evaluation.decision.clone(),
        enforcement: evaluation.enforcement.clone(),
        entitlement_state: evaluation.entitlement_state.clone(),
        cache_status: evaluation.cache_status.clone(),
        packages: evaluation.packages.clone(),
        reasons: evaluation.reasons.clone(),
        matched_rule_id: evaluation.matched_rule_id.clone(),
        exception_id: evaluation.exception_id.clone(),
        refresh_required: evaluation.refresh_required,
        record_monitor_evidence: evaluation.record_monitor_evidence,
        bundle_version: evaluation.bundle_version.clone(),
        policy_version: evaluation.policy_version.clone(),
        ..Default::default()
    }
}
