//! Review evidence for consent queued by the real execution sink.

use guard_contracts::{GuardHookEnvelopeV2, NativeBashReviewV1};

use crate::native_hook_receipt::{receipt_from_pre_tool, NativeReceiptIdentity};
use crate::policy_enforcement::{ActionFloor, AdmittedPolicySnapshot};

pub(super) fn review(
    assessment: &super::bash_policy::Assessment,
    envelope: &GuardHookEnvelopeV2,
    snapshot: &AdmittedPolicySnapshot,
) -> Result<NativeBashReviewV1, String> {
    // Every member was evaluated by the existing policy lattice. Choose its
    // strongest floor natively; Python must not invent an aggregate verdict.
    let decision = assessment
        .decisions
        .iter()
        .max_by_key(|decision| ActionFloor::parse(&decision.minimum_action))
        .ok_or_else(|| "native_bash_assessment_missing".to_owned())?
        .clone();
    crate::policy_enforcement::validate_pre_tool_result_matrix(&decision)?;
    let (request_id, request_digest) = crate::edge::request_identity(envelope)?;
    let intent_digest = crate::edge::execution_intent_digest(envelope)?;
    let anchor_digest = crate::edge::review_anchor_digest(envelope, Some(snapshot.snapshot()))?;
    let identity = NativeReceiptIdentity {
        request_id: &request_id,
        request_digest: &request_digest,
        execution_intent_digest: Some(&intent_digest),
        review_anchor_digest: Some(&anchor_digest),
    };
    let receipt = receipt_from_pre_tool(
        envelope,
        Some(snapshot.snapshot()),
        &identity,
        &envelope.harness,
        &crate::edge::payload_kind(&envelope.raw_payload)?,
        &decision,
    )?;
    Ok(NativeBashReviewV1 { decision, receipt })
}
