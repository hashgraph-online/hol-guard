use guard_contracts::{
    GuardHookEnvelopeV2, GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookDecisionReceiptV1,
    PreToolResultV1, NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES,
};
use guard_policy_snapshot::PolicySnapshotV3;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn optional_snapshot_string(
    snapshot: Option<&PolicySnapshotV3>,
    envelope: &GuardHookEnvelopeV2,
    key: &str,
) -> Option<String> {
    snapshot
        .and_then(|value| match key {
            "policy_digest" => Some(value.policy_digest.clone()),
            "rule_digest" => Some(value.rule_digest.clone()),
            "runtime_identity" => Some(value.runtime_identity.clone()),
            _ => None,
        })
        .or_else(|| {
            envelope
                .policy_snapshot
                .get(key)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}

struct DecisionReceiptInputs<'a> {
    request_id: &'a str,
    request_digest: &'a str,
    harness: &'a str,
    event_name: &'a str,
    payload_kind: &'a GuardHookPayloadKindV2,
    decision: &'a str,
    model_output_action: &'a str,
    policy_action: Option<&'a str>,
    observed_policy_action: Option<&'a str>,
    reason_code: &'a str,
    reviewed_output_sha256: Option<&'a str>,
    observe_mode: bool,
}

fn build_decision_receipt(
    envelope: &GuardHookEnvelopeV2,
    policy_snapshot: Option<&PolicySnapshotV3>,
    inputs: DecisionReceiptInputs<'_>,
) -> Result<NativeHookDecisionReceiptV1, String> {
    let policy_generation = policy_snapshot
        .map(|value| value.generation)
        .unwrap_or(envelope.policy_generation);
    let policy_digest = optional_snapshot_string(policy_snapshot, envelope, "policy_digest");
    let rule_digest = optional_snapshot_string(policy_snapshot, envelope, "rule_digest");
    let runtime_identity = optional_snapshot_string(policy_snapshot, envelope, "runtime_identity");
    let workspace_bound = envelope.source.cwd.is_some();
    let identity = serde_json::json!({
        "schema": "guard-native-hook-decision-identity.v1",
        "version": 1,
        "request_id": inputs.request_id,
        "request_digest": inputs.request_digest,
        "harness": inputs.harness,
        "event_name": inputs.event_name,
        "payload_kind": inputs.payload_kind,
        "policy_generation": policy_generation,
        "policy_digest": policy_digest,
        "rule_digest": rule_digest,
        "runtime_identity": runtime_identity,
        "decision": inputs.decision,
        "model_output_action": inputs.model_output_action,
        "policy_action": inputs.policy_action,
        "observed_policy_action": inputs.observed_policy_action,
        "reason_code": inputs.reason_code,
        "workspace_bound": workspace_bound,
        "source_ref_external_allowed": envelope.source.source_ref_external_allowed,
        "reviewed_output_sha256": inputs.reviewed_output_sha256,
        "observe_mode": inputs.observe_mode,
        "deadline_budget_ms": envelope.deadline_budget_ms,
    });
    let canonical = guard_policy_snapshot::canonical_json_bytes(&identity)
        .map_err(|_| "native_hook_decision_receipt_digest_failed".to_owned())?;
    let decision_id = hex::encode(Sha256::digest(&canonical));
    let receipt = NativeHookDecisionReceiptV1 {
        schema: guard_contracts::NATIVE_HOOK_DECISION_RECEIPT_V1_SCHEMA.to_owned(),
        version: 1,
        authority: "rust".to_owned(),
        decision_id,
        request_id: inputs.request_id.to_owned(),
        request_digest: inputs.request_digest.to_owned(),
        harness: inputs.harness.to_owned(),
        event_name: inputs.event_name.to_owned(),
        payload_kind: inputs.payload_kind.clone(),
        policy_generation,
        policy_digest,
        rule_digest,
        runtime_identity,
        decision: inputs.decision.to_owned(),
        model_output_action: inputs.model_output_action.to_owned(),
        policy_action: inputs.policy_action.map(ToOwned::to_owned),
        observed_policy_action: inputs.observed_policy_action.map(ToOwned::to_owned),
        reason_code: inputs.reason_code.to_owned(),
        workspace_bound,
        source_ref_external_allowed: envelope.source.source_ref_external_allowed,
        reviewed_output_sha256: inputs.reviewed_output_sha256.map(ToOwned::to_owned),
        observe_mode: inputs.observe_mode,
        deadline_budget_ms: envelope.deadline_budget_ms,
    };
    let encoded = serde_json::to_vec(&receipt)
        .map_err(|_| "native_hook_decision_receipt_encode_failed".to_owned())?;
    if encoded.len() > NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES {
        return Err("native_hook_decision_receipt_too_large".to_owned());
    }
    Ok(receipt)
}

pub(crate) fn receipt_from_pre_tool(
    envelope: &GuardHookEnvelopeV2,
    snapshot: Option<&PolicySnapshotV3>,
    request_id: &str,
    request_digest: &str,
    harness: &str,
    payload_kind: &GuardHookPayloadKindV2,
    result: &PreToolResultV1,
) -> Result<NativeHookDecisionReceiptV1, String> {
    build_decision_receipt(
        envelope,
        snapshot,
        DecisionReceiptInputs {
            request_id,
            request_digest,
            harness,
            event_name: "PreToolUse",
            payload_kind,
            decision: &result.decision,
            model_output_action: "not_applicable",
            policy_action: Some(&result.policy_action),
            observed_policy_action: None,
            reason_code: &result.reason_code,
            reviewed_output_sha256: None,
            observe_mode: false,
        },
    )
}

pub(crate) fn receipt_from_post_tool(
    envelope: &GuardHookEnvelopeV2,
    snapshot: Option<&PolicySnapshotV3>,
    request_id: &str,
    request_digest: &str,
    harness: &str,
    payload_kind: &GuardHookPayloadKindV2,
    result: &HookReviewResponseV1,
) -> Result<NativeHookDecisionReceiptV1, String> {
    build_decision_receipt(
        envelope,
        snapshot,
        DecisionReceiptInputs {
            request_id,
            request_digest,
            harness,
            event_name: "PostToolUse",
            payload_kind,
            decision: &result.decision,
            model_output_action: &result.model_output_action,
            policy_action: result.policy_action.as_deref(),
            observed_policy_action: result.observed_policy_action.as_deref(),
            reason_code: &result.reason_code,
            reviewed_output_sha256: result.reviewed_output_sha256.as_deref(),
            observe_mode: result.observe_mode,
        },
    )
}
