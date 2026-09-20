//! Reconstruct scoped approval context through the same resident evaluator.
use super::{context_from_result, derive_context_with_snapshot, ApprovalContext};
use crate::policy_store::{AdmittedVersionedPolicySnapshot, PolicySnapshotStore};
use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};
use serde_json::Value;

pub(in crate::approval) fn derive_context_with_versioned_snapshot(
    envelope: &GuardHookEnvelopeV2,
    store: &PolicySnapshotStore,
    snapshot: &AdmittedVersionedPolicySnapshot,
) -> Result<ApprovalContext, String> {
    let AdmittedVersionedPolicySnapshot::V4(scoped) = snapshot else {
        return derive_context_with_snapshot(envelope, store, snapshot.as_v3()?);
    };
    crate::edge::validate_envelope_shape(envelope)?;
    let bytes =
        crate::edge_v4::evaluate_admitted(envelope.clone(), scoped, store.resident_generation())?;
    if bytes.len() > guard_contracts::NATIVE_APPROVAL_MAX_BYTES * 2 {
        return Err("native_approval_edge_result_too_large".to_owned());
    }
    let edge = crate::strict_json_value(&bytes)
        .map_err(|_| "native_approval_edge_result_invalid".to_owned())?;
    let harness = crate::edge::canonical_harness(&envelope.harness)?;
    let (request_id, request_digest) = crate::edge::request_identity(envelope)?;
    // These values are produced in-process by the scoped evaluator under the
    // snapshot fence, never supplied by an approval presenter.
    if edge.get("schema").and_then(Value::as_str) != Some("guard-hook-edge-result.v3")
        || edge.get("authority").and_then(Value::as_str) != Some("rust")
        || edge.get("event_name").and_then(Value::as_str) != Some("PreToolUse")
        || edge.get("harness").and_then(Value::as_str) != Some(harness.as_str())
        || edge.get("request_id").and_then(Value::as_str) != Some(request_id.as_str())
    {
        return Err("native_approval_edge_result_invalid".to_owned());
    }
    let result: PreToolResultV1 = serde_json::from_value(edge["result"].clone())
        .map_err(|_| "native_approval_result_invalid".to_owned())?;
    context_from_result(
        envelope,
        store,
        &snapshot.authenticated(),
        request_id,
        request_digest,
        harness,
        result,
    )
}
