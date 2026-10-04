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
    execution_intent_digest: Option<&'a str>,
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
    command_extensions: Option<&'a guard_contracts::NativeCommandReceiptBindingV1>,
    prompt_risk_classes: &'a [guard_contracts::NativePromptRiskClassV1],
}

pub(crate) struct NativeReceiptIdentity<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) request_digest: &'a str,
    pub(crate) execution_intent_digest: Option<&'a str>,
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
    let mut identity = serde_json::json!({
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
    if let Some(binding) = inputs.command_extensions {
        identity["command_extensions"] = serde_json::to_value(binding)
            .map_err(|_| "native_hook_decision_receipt_digest_failed".to_owned())?;
    }
    if !inputs.prompt_risk_classes.is_empty() {
        identity["prompt_risk_classes"] = serde_json::to_value(inputs.prompt_risk_classes)
            .map_err(|_| "native_hook_decision_receipt_digest_failed".to_owned())?;
    }
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
        execution_intent_digest: inputs.execution_intent_digest.map(ToOwned::to_owned),
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
        command_extensions: inputs.command_extensions.cloned(),
        origin_authentication: None,
        prompt_risk_classes: inputs.prompt_risk_classes.to_vec(),
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
    identity: &NativeReceiptIdentity<'_>,
    harness: &str,
    payload_kind: &GuardHookPayloadKindV2,
    result: &PreToolResultV1,
) -> Result<NativeHookDecisionReceiptV1, String> {
    build_decision_receipt(
        envelope,
        snapshot,
        DecisionReceiptInputs {
            request_id: identity.request_id,
            request_digest: identity.request_digest,
            execution_intent_digest: identity.execution_intent_digest,
            harness,
            event_name: &result.action.event,
            payload_kind,
            decision: &result.decision,
            model_output_action: "not_applicable",
            policy_action: Some(&result.policy_action),
            observed_policy_action: None,
            reason_code: &result.reason_code,
            reviewed_output_sha256: None,
            observe_mode: false,
            command_extensions: result
                .command_extensions
                .as_ref()
                .map(|value| &value.binding),
            prompt_risk_classes: &result.prompt_risk_classes,
        },
    )
}

pub(crate) fn receipt_from_post_tool(
    envelope: &GuardHookEnvelopeV2,
    snapshot: Option<&PolicySnapshotV3>,
    identity: &NativeReceiptIdentity<'_>,
    harness: &str,
    payload_kind: &GuardHookPayloadKindV2,
    result: &HookReviewResponseV1,
) -> Result<NativeHookDecisionReceiptV1, String> {
    build_decision_receipt(
        envelope,
        snapshot,
        DecisionReceiptInputs {
            request_id: identity.request_id,
            request_digest: identity.request_digest,
            execution_intent_digest: identity.execution_intent_digest,
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
            command_extensions: None,
            prompt_risk_classes: &[],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_contracts::GuardHookSourceMetadataV2;

    fn envelope() -> GuardHookEnvelopeV2 {
        GuardHookEnvelopeV2 {
            schema: guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA.to_owned(),
            request_id: Some("receipt-test".to_owned()),
            harness: "codex".to_owned(),
            event: "PreToolUse".to_owned(),
            raw_payload: serde_json::json!({"tool_input": {"command": "pwd"}}),
            deadline_budget_ms: Some(100),
            policy_generation: 1,
            policy_snapshot: serde_json::json!({}),
            source: GuardHookSourceMetadataV2 {
                cwd: Some("/workspace".to_owned()),
                home_dir: "/home/test".to_owned(),
                guard_home: "/guard".to_owned(),
                source_ref_external_allowed: false,
                execution_environment: None,
            },
        }
    }

    fn receipt(identity: &NativeReceiptIdentity<'_>) -> NativeHookDecisionReceiptV1 {
        build_decision_receipt(
            &envelope(),
            None,
            DecisionReceiptInputs {
                request_id: identity.request_id,
                request_digest: identity.request_digest,
                execution_intent_digest: identity.execution_intent_digest,
                harness: "codex",
                event_name: "PreToolUse",
                payload_kind: &GuardHookPayloadKindV2::Inline,
                decision: "allow",
                model_output_action: "not_applicable",
                policy_action: Some("allow"),
                observed_policy_action: None,
                reason_code: "test",
                reviewed_output_sha256: None,
                observe_mode: false,
                command_extensions: None,
                prompt_risk_classes: &[],
            },
        )
        .unwrap()
    }

    #[test]
    fn execution_intent_evidence_is_not_decision_identity() {
        let legacy = receipt(&NativeReceiptIdentity {
            request_id: "request",
            request_digest: &"a".repeat(64),
            execution_intent_digest: None,
        });
        let evidenced = receipt(&NativeReceiptIdentity {
            request_id: "request",
            request_digest: &"a".repeat(64),
            execution_intent_digest: Some(&"b".repeat(64)),
        });
        assert_eq!(legacy.decision_id, evidenced.decision_id);
        assert_eq!(legacy.execution_intent_digest, None);
        assert_eq!(evidenced.execution_intent_digest, Some("b".repeat(64)));
    }
}
