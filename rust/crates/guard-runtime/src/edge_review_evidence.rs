//! The review evidence of a reviewed `PreToolUse`, settled in the edge answer.
//!
//! The daemon used to ask the resident a second time for a review's
//! `HookReview` answers: whether the receipt's policy binding holds, the
//! retry binding, and the exact-action token or its once-only reason. The
//! edge already holds every input of that query, so it answers the query
//! beside the custom extension rule and the daemon reads both from one
//! answer. The daemon asks for it by sending its extension-control digest
//! with its custom extension rules. A recorded call is never paused, so it
//! carries none.

use std::path::Path;

use guard_contracts::{
    GuardHookEnvelopeV2, GuardHookReviewEvidenceV1, NativeExactActionQueryV1,
    NativeHookDecisionReceiptV1,
};
use serde_json::{Map, Value};

/// The `HookReview` budget the daemon asked with.
const BUDGET_MS: u64 = 4_000;
const REVIEW_ACTIONS: [&str; 2] = ["review", "require-reapproval"];
/// The hook's stamp of the agent's own `PATH`, `HOME` and variable names,
/// which the envelope carries apart from the payload.
const EXECUTION_ENVIRONMENT_KEY: &str = "guard_execution_environment";

/// Run `settle` (the custom extension rule) while the review evidence is
/// derived beside it, so a review waits for the slower of the two.
pub(crate) fn beside<T>(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    result: &Value,
    receipt: &NativeHookDecisionReceiptV1,
    guard_home: Option<&Path>,
    settle: impl FnOnce() -> T,
) -> (T, Option<GuardHookReviewEvidenceV1>) {
    let receipt = match serde_json::to_value(receipt) {
        Ok(Value::Object(receipt)) => Some(receipt),
        _ => None,
    };
    let Some(query) = receipt
        .and_then(|receipt| hook_review_query(envelope, harness, event_name, result, receipt))
    else {
        return (settle(), None);
    };
    std::thread::scope(|scope| {
        let evidence =
            scope.spawn(|| crate::native_exact_action_op::hook_review_evidence(&query, guard_home));
        let settled = settle();
        // A proof that panicked binds nothing, so the review is not offered.
        let evidence = evidence
            .join()
            .unwrap_or_else(|_| crate::native_exact_action_op::unproven_review_evidence(false));
        (settled, Some(evidence))
    })
}

/// The `HookReview` query the daemon would have sent for this review, or
/// `None` when the daemon asked for no evidence or the answer pauses nothing.
fn hook_review_query(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    event_name: &str,
    result: &Value,
    receipt: Map<String, Value>,
) -> Option<NativeExactActionQueryV1> {
    let rules = envelope.local_cli_rules.as_ref()?;
    let digest = rules.exact_action_control_digest.as_ref()?;
    let result = result.as_object()?;
    let action = result.get("minimum_action").and_then(Value::as_str)?;
    if event_name != "PreToolUse" || envelope.recording_only || !REVIEW_ACTIONS.contains(&action) {
        return None;
    }
    let mut payload = envelope.raw_payload.as_object()?.clone();
    if let Some(stamp) = envelope.source.execution_environment.as_ref() {
        payload.insert(
            EXECUTION_ENVIRONMENT_KEY.to_owned(),
            serde_json::to_value(stamp).ok()?,
        );
    }
    Some(NativeExactActionQueryV1::HookReview {
        harness: harness.to_owned(),
        payload,
        result: result.clone(),
        receipt: Some(receipt),
        workspace: envelope.source.cwd.clone(),
        home_dir: Some(envelope.source.home_dir.clone()),
        environment: rules.env.clone(),
        extension_control_digest: digest.clone(),
        budget_ms: BUDGET_MS,
    })
}

#[cfg(test)]
#[path = "edge_review_evidence_tests.rs"]
mod tests;
