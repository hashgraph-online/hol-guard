use super::super::now_ms;
use super::*;
use crate::policy_store::approval_v4_authority::{
    challenge_matches_authority, with_verified_authority,
};
use sha2::{Digest, Sha256};

pub(super) fn checked_request(request: &DeliveryRequest, schema: &str) -> Result<(), String> {
    if request.schema != schema
        || request.version != 4
        || request.request_id.is_empty()
        || request.request_id.len() > 256
    {
        return Err("native_cloud_review_v4_request_invalid".into());
    }
    Ok(())
}
pub(super) fn exact_bindings(request: &DeliveryRequest) -> Result<(&str, &str), String> {
    let decision = request
        .decision_receipt_id
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or("native_cloud_review_v4_decision_binding_invalid")?;
    let source = request
        .source_claim_hash
        .as_deref()
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or("native_cloud_review_v4_source_binding_invalid")?;
    Ok((decision, source))
}
fn checked_renewal_request<'a>(
    request: &'a RenewalRequest,
    schema: &str,
) -> Result<(&'a str, &'a str), String> {
    if request.schema != schema
        || request.version != 4
        || request.request_id.is_empty()
        || request.request_id.len() > 256
    {
        return Err("native_cloud_review_v4_request_invalid".into());
    }
    if request.decision_receipt_id.is_empty() || request.decision_receipt_id.len() > 256 {
        return Err("native_cloud_review_v4_decision_binding_invalid".into());
    }
    if request.source_claim_hash.len() != 64
        || !request
            .source_claim_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("native_cloud_review_v4_source_binding_invalid".into());
    }
    if request.original_nonce_digest.len() != 64
        || !request
            .original_nonce_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("native_cloud_review_v4_original_challenge_mismatch".into());
    }
    Ok((&request.decision_receipt_id, &request.source_claim_hash))
}
pub(super) fn current(origin: &Origin, store: &PolicySnapshotStore) -> Result<(), String> {
    if origin.consumption_started.is_some() {
        return Err("native_cloud_review_v4_consumption_recovery_required".into());
    }
    let state = consent::require_enabled(store.state_base(), now_ms()?)?;
    let revision = origin
        .renewal
        .as_ref()
        .map_or(origin.consent_revision, |renewal| renewal.consent_revision);
    if state.revision != revision || state.revocation_epoch != origin.revocation_epoch {
        return Err("native_cloud_review_v4_permission_revoked".into());
    }
    if origin.active_challenge().expires_at_ms <= now_ms()? {
        return Err("native_approval_receipt_expired".into());
    }
    Ok(())
}
pub(super) fn nonce_digest(challenge: &ApprovalChallengeV4) -> Result<String, String> {
    let nonce = hex::decode(&challenge.nonce)
        .map_err(|_| "native_cloud_review_v4_state_invalid".to_owned())?;
    if nonce.len() != 32 {
        return Err("native_cloud_review_v4_state_invalid".into());
    }
    Ok(guard_policy_snapshot::digest_bytes(&nonce))
}

/// Fresh credentials and policy snapshots may change; the approved business action may not.
pub(crate) fn same_business_identity(
    original: &ApprovalChallengeV4,
    fresh: &ApprovalChallengeV4,
) -> bool {
    original.schema == fresh.schema
        && original.version == fresh.version
        && original.request_id == fresh.request_id
        && original.action_digest == fresh.action_digest
        && original.action_type == fresh.action_type
        && original.operation == fresh.operation
        && original.intrinsic_action == fresh.intrinsic_action
        && original.minimum_action == fresh.minimum_action
        && original.floor_class == fresh.floor_class
        && original.approval_eligible == fresh.approval_eligible
        && fresh.policy_generation >= original.policy_generation
        && fresh.issued_at_ms >= original.expires_at_ms
        && original.rule_digest == fresh.rule_digest
        && original.runtime_identity == fresh.runtime_identity
        && original.runtime_protocol_version == fresh.runtime_protocol_version
        && original.runtime_package == fresh.runtime_package
        && original.runtime_version == fresh.runtime_version
        && original.runtime_binary_identity == fresh.runtime_binary_identity
        && original.harness == fresh.harness
        && original.workspace_binding == fresh.workspace_binding
        && original.device_binding == fresh.device_binding
        && original.installation_binding == fresh.installation_binding
        && original.publisher_binding == fresh.publisher_binding
        && original.artifact_binding == fresh.artifact_binding
        && original.scope_contract_version == fresh.scope_contract_version
        && original.scope_contract_digest == fresh.scope_contract_digest
        && original.scope_binding == fresh.scope_binding
        && original.requested_action == fresh.requested_action
        && original.webauthn.rp_id == fresh.webauthn.rp_id
        && original.webauthn.origin == fresh.webauthn.origin
        && (original.signing_key_id != fresh.signing_key_id
            || (original.webauthn.credential_id == fresh.webauthn.credential_id
                && original.webauthn.algorithm == fresh.webauthn.algorithm))
        && original.webauthn.user_verification == fresh.webauthn.user_verification
}

pub(crate) fn renew(
    request: RenewalRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let (decision, source) =
        checked_renewal_request(&request, "guard-native-cloud-review-renewal-request.v4")?;
    let _consent = consent::CONSENT_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_consent_unavailable".to_owned())?;
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    // The protected journal is queried before creating any second challenge. An unreadable
    // journal is an unknown outcome, never evidence that the original was not consumed.
    let mut journal = load(store.state_base())?;
    let record = journal
        .records
        .get(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    if nonce_digest(&record.challenge)? != request.original_nonce_digest {
        return Err("native_cloud_review_v4_original_challenge_mismatch".into());
    }
    if record.installed.is_some() || record.renewal.is_some() || record.blocked.is_some() {
        let (bound_decision, bound_source) = bindings(record)?;
        if bound_decision != decision || bound_source != source {
            return Err("native_cloud_review_v4_immutable_binding_conflict".into());
        }
    }
    if record.positive.is_some() {
        return Err("native_cloud_review_v4_already_consumed".into());
    }
    if record.blocked.is_some() {
        return Err("native_cloud_review_v4_immutable_binding_conflict".into());
    }
    if record.consumption_started.is_some() {
        return Err("native_cloud_review_v4_consumption_recovery_required".into());
    }
    let now = now_ms()?;
    let permission = consent::require_enabled(store.state_base(), now)?;
    if permission.revocation_epoch != record.revocation_epoch {
        return Err("native_cloud_review_v4_permission_revoked".into());
    }
    let authority = store.approval_v4_authority()?;
    let original_authority = record
        .authority_fingerprint
        .as_deref()
        .filter(|_| record.execution_intent_digest.is_some())
        .ok_or("native_cloud_review_v4_original_authority_unavailable")?;
    let active = record.active_challenge();
    if active.expires_at_ms > now {
        if record.renewal.is_none() {
            return Err("native_cloud_review_v4_renewal_not_required".into());
        }
        let installed_active = record
            .installed
            .as_ref()
            .is_some_and(|installed| installed.artifact.nonce == active.nonce);
        if crate::policy_store::approval_v4_authority::challenge_matches_authority(
            active, authority,
        ) && (installed_active || active.resident_epoch == store.approval_resident_epoch())
        {
            current(record, store)?;
            return crate::policy_store::approval_v4_authority::with_verified_authority(
                authority,
                || {
                    crate::policy_store::approval_v4_authority::verify_renewal_authority(
                        authority,
                        &record.challenge,
                        original_authority,
                    )?;
                    renewal_result(&request.request_id, record)
                },
            );
        }
        // A changed credential or replay epoch requires another fresh UP+UV assertion.
    }
    let snapshot = store.current_snapshot()?;
    // Copy only protected action/source input, never the superseded policy payload.
    let envelope = GuardHookEnvelopeV2 {
        schema: record.envelope.schema.clone(),
        request_id: Some(request.request_id.clone()),
        harness: record.envelope.harness.clone(),
        event: record.envelope.event.clone(),
        raw_payload: record.envelope.raw_payload.clone(),
        deadline_budget_ms: record.envelope.deadline_budget_ms,
        policy_generation: snapshot.generation,
        policy_snapshot: serde_json::to_value(snapshot)
            .map_err(|_| "native_cloud_review_v4_state_invalid".to_owned())?,
        source: record.envelope.source.clone(),
    };
    let challenge = crate::approval::approval_v4::create_cloud_review_challenge(
        &envelope,
        store,
        Some((&record.challenge, original_authority)),
    )?;
    let original_nonce_digest = nonce_digest(&record.challenge)?;
    journal
        .records
        .get_mut(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?
        .renewal = Some(Renewal {
        decision_receipt_id: decision.into(),
        source_claim_hash: source.into(),
        original_nonce_digest,
        envelope,
        challenge,
        consent_revision: permission.revision,
        revocation_epoch: permission.revocation_epoch,
    });
    persist(store.state_base(), &journal)?;
    renewal_result(&request.request_id, &journal.records[&request.request_id])
}
pub(crate) fn query_renewal(
    request: RenewalRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let (decision, source) =
        checked_renewal_request(&request, "guard-native-cloud-review-renewal-query.v4")?;
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let journal = load(store.state_base())?;
    let record = journal
        .records
        .get(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    if nonce_digest(&record.challenge)? != request.original_nonce_digest {
        return Err("native_cloud_review_v4_original_challenge_mismatch".into());
    }
    let renewal = record
        .renewal
        .as_ref()
        .ok_or("native_cloud_review_v4_renewal_missing")?;
    if renewal.decision_receipt_id != decision || renewal.source_claim_hash != source {
        return Err("native_cloud_review_v4_immutable_binding_conflict".into());
    }
    // Historical correlation is readable after expiry/revocation, never executable authority.
    renewal_result(&request.request_id, record)
}
fn renewal_result(request_id: &str, record: &Origin) -> Result<Vec<u8>, String> {
    let renewal = record
        .renewal
        .as_ref()
        .ok_or("native_cloud_review_v4_renewal_missing")?;
    crate::encode_response(
        &json!({"schema":"guard-native-cloud-review-renewal-result.v4", "version":4,
        "request_id":request_id, "decision_receipt_id":renewal.decision_receipt_id, "source_claim_hash":renewal.source_claim_hash,
        "original_nonce_digest":renewal.original_nonce_digest, "challenge":renewal.challenge,
        "consent_revision":renewal.consent_revision, "revocation_epoch":renewal.revocation_epoch}),
    )
}
pub(crate) fn origin(
    request: DeliveryRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    checked_request(&request, "guard-native-cloud-review-origin-request.v4")?;
    if request.proof.is_some()
        || request.decision_receipt_id.is_some()
        || request.source_claim_hash.is_some()
    {
        return Err("native_cloud_review_v4_request_invalid".into());
    }
    let _consent = consent::CONSENT_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_consent_unavailable".to_owned())?;
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let journal = load(store.state_base())?;
    let record = journal
        .records
        .get(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    current(record, store)?;
    let mut result = json!({
        "schema":"guard-native-cloud-review-origin-result.v4", "version":4,
        "request_id":request.request_id, "challenge":record.challenge,
        "consent_revision":record.consent_revision, "revocation_epoch":record.revocation_epoch
    });
    // A source commitment never changes a frozen challenge or returns raw
    // bytes. Old origins still execute, but cannot disclose reusable source
    // unless the protected journal belongs to the current enrolled authority.
    if let Ok(authority) = store.approval_v4_authority() {
        if challenge_matches_authority(&record.challenge, authority) {
            let command_digest = with_verified_authority(authority, || {
                let source = guard_command::pretool::generic::extract_untrusted_command_context(
                    &record.envelope.raw_payload,
                )?;
                Ok(source
                    .command
                    .map(|command| hex::encode(Sha256::digest(command.as_bytes()))))
            })
            .ok()
            .flatten();
            if let Some(command_digest) = command_digest {
                result["command_sha256"] = json!(command_digest);
            }
        }
    }
    crate::encode_response(&result)
}
pub(crate) fn query(
    request: DeliveryRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    checked_request(&request, "guard-native-cloud-review-consumption-query.v4")?;
    if request.proof.is_some() {
        return Err("native_cloud_review_v4_request_invalid".into());
    }
    let (decision, source) = exact_bindings(&request)?;
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let journal = load(store.state_base())?;
    let record = journal
        .records
        .get(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    let (bound_decision, bound_source) = bindings(record)?;
    if bound_decision != decision || bound_source != source {
        return Err("native_cloud_review_v4_immutable_binding_conflict".into());
    }
    // Historical consumed evidence survives revocation; this read never grants action authority.
    result(&request.request_id, record)
}
pub(super) fn result(request_id: &str, record: &Origin) -> Result<Vec<u8>, String> {
    let (decision, source) = bindings(record)?;
    crate::encode_response(
        &json!({"schema":"guard-native-cloud-review-application-result.v4", "version":4,
        "request_id":request_id, "decision_receipt_id":decision,
        "source_claim_hash":source,
        "phase": if record.positive.is_some() { "consumed" } else if record.blocked.is_some() { "blocked" }
            else if record.consumption_started.is_some() { "recovery_required" }
            else if record.installed.as_ref().is_some_and(|installed| installed.artifact.nonce == record.active_challenge().nonce) { "waiting_for_hook" }
            else { "waiting_for_authorization" },
        "consumed_at_ms":record.positive.as_ref().map(|p| p.consumed_at_ms),
        "receipt":record.positive.as_ref().map(|p| &p.receipt.receipt)}),
    )
}

pub(super) fn bindings(record: &Origin) -> Result<(&str, &str), String> {
    if let Some(blocked) = &record.blocked {
        return Ok((&blocked.decision_receipt_id, &blocked.source_claim_hash));
    }
    if let Some(renewal) = &record.renewal {
        return Ok((&renewal.decision_receipt_id, &renewal.source_claim_hash));
    }
    let installed = record
        .installed
        .as_ref()
        .ok_or("native_cloud_review_v4_not_installed")?;
    Ok((&installed.decision_receipt_id, &installed.source_claim_hash))
}

pub(crate) fn block(
    request: DeliveryRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    checked_request(&request, "guard-native-cloud-review-block-request.v4")?;
    if request.proof.is_some() {
        return Err("native_cloud_review_v4_request_invalid".into());
    }
    let (decision, source) = exact_bindings(&request)?;
    let _consent = consent::CONSENT_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_consent_unavailable".to_owned())?;
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let mut journal = load(store.state_base())?;
    let record = journal
        .records
        .get_mut(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    current(record, store)?;
    // Never overwrite or convert an installed positive decision into another decision.
    if record.installed.is_some() || record.positive.is_some() || record.renewal.is_some() {
        return Err("native_cloud_review_v4_immutable_binding_conflict".into());
    }
    if let Some(blocked) = &record.blocked {
        if blocked.decision_receipt_id != decision || blocked.source_claim_hash != source {
            return Err("native_cloud_review_v4_immutable_binding_conflict".into());
        }
    } else {
        record.blocked = Some(Blocked {
            decision_receipt_id: decision.into(),
            source_claim_hash: source.into(),
        });
        persist(store.state_base(), &journal)?;
    }
    result(&request.request_id, &journal.records[&request.request_id])
}
