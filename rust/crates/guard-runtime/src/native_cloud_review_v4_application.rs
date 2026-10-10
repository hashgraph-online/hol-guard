use super::super::{native_review_origin, now_ms};
use super::*;

/// Called only after the real native edge has completed its fresh baseline evaluation.
/// Context derivation uses evaluate_envelope_with_snapshot, which never calls this hook.
pub(crate) fn apply_hook(
    envelope: GuardHookEnvelopeV2,
    store: &PolicySnapshotStore,
    baseline: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut edge: Value = serde_json::from_slice(&baseline)
        .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
    if !matches!(
        edge.get("event_name").and_then(Value::as_str),
        Some("PreToolUse" | "UserPromptSubmit")
    ) || edge.pointer("/result/decision").and_then(Value::as_str) != Some("deny")
        || !matches!(
            edge.pointer("/result/minimum_action")
                .and_then(Value::as_str),
            Some("review" | "require-reapproval" | "sandbox-required")
        )
    {
        return Ok(baseline);
    }
    // A review deny is already fail-closed. Missing, locked, or unusable consent
    // must keep that decision instead of turning the hook into an outage.
    let Ok(_consent) = consent::CONSENT_LOCK.lock() else {
        return Ok(baseline);
    };
    let Ok(_transaction) = consent::transaction(store.state_base()) else {
        return Ok(baseline);
    };
    let Ok(now) = now_ms() else {
        return Ok(baseline);
    };
    let Ok(permission) = consent::require_enabled(store.state_base(), now) else {
        return Ok(baseline);
    };
    let mut request_id = edge
        .pointer("/receipt/request_id")
        .and_then(Value::as_str)
        .ok_or("native_cloud_review_v4_origin_invalid")?
        .to_owned();
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let mut journal = load(store.state_base())?;
    if journal
        .records
        .get(&request_id)
        .is_some_and(|record| record.positive.is_some() || record.blocked.is_some())
    {
        return Ok(baseline);
    }
    let intent = edge
        .pointer("/receipt/execution_intent_digest")
        .and_then(Value::as_str)
        .ok_or("native_cloud_review_v4_origin_invalid")?;
    let mut matching_renewal: Option<&str> = None;
    for (original_id, record) in &journal.records {
        if record.positive.is_none()
            && record.consumption_started.is_some()
            && record.envelope.source == envelope.source
            && record.execution_intent_digest.as_deref() == Some(intent)
        {
            return Err("native_cloud_review_v4_consumption_recovery_required".into());
        }
        if record.positive.is_some()
            || record.blocked.is_some()
            || record.renewal.is_none()
            || record.envelope.source != envelope.source
            || record.execution_intent_digest.as_deref() != Some(intent)
            || !record.installed.as_ref().is_some_and(|installed| {
                installed.artifact.nonce == record.active_challenge().nonce
            })
        {
            continue;
        }
        if matching_renewal.is_some()
            || (original_id != &request_id
                && journal
                    .records
                    .get(&request_id)
                    .is_some_and(|record| record.installed.is_some()))
        {
            return Err("native_cloud_review_v4_renewal_ambiguous".into());
        }
        matching_renewal = Some(original_id);
    }
    if let Some(original_id) = matching_renewal {
        request_id = original_id.to_owned();
    }
    if !journal.records.contains_key(&request_id) {
        if journal.records.len() >= MAX_RECORDS {
            // Evict blocked records before refusing a new origin — a blocked
            // decision is terminal for that request_id and cannot admit new
            // work, so it is safe to drop when the journal is otherwise full.
            // ``positive`` records are kept because they are the replay/
            // idempotency witness for the matching request_id.
            journal.records.retain(|_, record| record.blocked.is_none());
        }
        if journal.records.len() >= MAX_RECORDS {
            // Keep the computed native denial visible without dropping protected
            // consumption/replay evidence or manufacturing a new executable origin.
            return Ok(baseline);
        }
        let challenge =
            crate::approval::approval_v4::create_cloud_review_challenge(&envelope, store, None)?;
        let authority_fingerprint = store.approval_v4_authority()?.fingerprint.clone();
        let execution_intent_digest = intent.to_owned();
        journal.records.insert(
            request_id.clone(),
            Origin {
                envelope,
                challenge,
                consent_revision: permission.revision,
                revocation_epoch: permission.revocation_epoch,
                authority_fingerprint: Some(authority_fingerprint),
                execution_intent_digest: Some(execution_intent_digest),
                renewal: None,
                consumption_started: None,
                installed: None,
                positive: None,
                blocked: None,
            },
        );
        persist(store.state_base(), &journal)?;
        return Ok(baseline);
    }
    let record = journal
        .records
        .get(&request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    if record.positive.is_some() || record.blocked.is_some() {
        return Ok(baseline);
    }
    current(record, store)?;
    let Some(installed) = &record.installed else {
        return Ok(baseline);
    };
    if installed.artifact.nonce != record.active_challenge().nonce {
        return Ok(baseline);
    }
    let artifact = installed.artifact.clone();
    let durable = durable_token(record)?;
    // Reconstruct and verify the current action, not a caller-supplied stored metadata copy.
    let mut envelope = envelope;
    // Only an unambiguous, protected original with the identical live purpose/action/source
    // can replace a retry's transient harness ID. Consumed/blocked entries never match.
    envelope.request_id = Some(request_id.clone());
    crate::approval::approval_v4::consume_approval_with_emit(
        ApprovalConsumeRequestV4 {
            schema: "guard-native-approval-consume-request.v4".into(),
            version: 4,
            envelope,
            artifact,
        },
        store,
        Some(&durable),
        |commit| {
            use crate::approval::approval_v4::ApprovalConsumptionCommit;
            match commit {
                ApprovalConsumptionCommit::Prepared {
                    nonce_digest,
                    consumed_at_ms,
                } => {
                    let record = journal
                        .records
                        .get_mut(&request_id)
                        .ok_or("native_cloud_review_v4_origin_missing")?;
                    record.consumption_started = Some(ConsumptionStarted {
                        nonce_digest: nonce_digest.to_owned(),
                        started_at_ms: consumed_at_ms,
                    });
                }
                ApprovalConsumptionCommit::Consumed {
                    receipt: bytes,
                    consumed_at_ms,
                } => {
                    let receipt: ApprovalResultV4 = serde_json::from_slice(bytes)
                        .map_err(|_| "native_cloud_review_v4_positive_invalid".to_owned())?;
                    if receipt.receipt.phase != "consumed" {
                        return Err("native_cloud_review_v4_positive_invalid".into());
                    }
                    let record = journal
                        .records
                        .get_mut(&request_id)
                        .ok_or("native_cloud_review_v4_origin_missing")?;
                    record.positive = Some(Positive {
                        consumed_at_ms,
                        receipt,
                    });
                    record.consumption_started = None;
                }
            }
            persist(store.state_base(), &journal)
        },
    )?;
    let native = &journal
        .records
        .get(&request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?
        .positive
        .as_ref()
        .ok_or("native_cloud_review_v4_positive_invalid")?
        .receipt;
    let mut hook_receipt: guard_contracts::NativeHookDecisionReceiptV1 = serde_json::from_value(
        edge.get("receipt")
            .ok_or("native_hook_edge_response_invalid")?
            .clone(),
    )
    .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
    hook_receipt.request_id = request_id.clone();
    edge["request_id"] = json!(request_id);
    crate::native_hook_receipt::authorize_consumed_receipt(&mut hook_receipt, native)?;
    native_review_origin::authenticate(store, &mut hook_receipt)?;
    edge["receipt"] = serde_json::to_value(hook_receipt)
        .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
    let approved = edge
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .ok_or("native_hook_edge_response_invalid")?;
    approved.insert("decision".into(), json!("allow"));
    approved.insert("policy_action".into(), json!("allow"));
    approved.insert("minimum_action".into(), json!("allow"));
    approved.insert("explicitly_benign".into(), json!(false));
    approved.insert("reason_code".into(), json!("native_approval_v4_consumed"));
    approved.insert(
        "reason".into(),
        json!("Exact native WebAuthn approval consumed for this action."),
    );
    approved.insert(
        "native_approval_consumption".into(),
        serde_json::to_value(native)
            .map_err(|_| "native_cloud_review_v4_positive_invalid".to_owned())?,
    );
    edge.as_object_mut()
        .ok_or("native_hook_edge_response_invalid")?
        .insert(
            "native_application_v4".into(),
            serde_json::from_slice(&result(&request_id, &journal.records[&request_id])?)
                .map_err(|_| "native_cloud_review_v4_positive_invalid".to_owned())?,
        );
    crate::encode_response(&edge)
}
