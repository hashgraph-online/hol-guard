//! Envelope verification, durable-claim gating, and read-only consumption
//! queries. Extracted so the claim semantics and authority screens keep one
//! narrow provenance boundary; nothing here mutates claim state outside the
//! single `consume_or_replay_claim` path.

use ring::signature;

use super::super::workspace_review_authority::read_installed_record;
use super::super::workspace_review_secure_state::WorkspaceReviewClaimV1;
use super::*;

pub(super) fn validate_context(context: &WorkspaceReviewDecisionContext<'_>) -> Result<(), String> {
    if [
        context.workspace_binding,
        context.device_binding,
        context.installation_binding,
        context.scope_binding,
        context.request_binding,
        context.action_binding,
        context.intent_binding,
        context.revision_binding,
        context.policy_binding,
        context.retry_scope_binding,
    ]
    .iter()
    .all(|value| valid_lower_hex(value))
        && context.device_binding != context.installation_binding
        && retry_scope_binding(
            context.action_binding,
            context.intent_binding,
            context.revision_binding,
            context.policy_binding,
        )
        .is_ok_and(|binding| binding == context.retry_scope_binding)
    {
        Ok(())
    } else {
        Err("native_workspace_review_decision_binding_invalid".to_owned())
    }
}

#[cfg(test)]
pub(super) fn verify_envelope(
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    authority: &VerifiedWorkspaceReviewAuthority,
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
) -> Result<(VerifiedWorkspaceReviewDecision, Vec<u8>), String> {
    verify_envelope_mode(
        envelope,
        authority,
        context,
        now_ms,
        NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY,
    )
}

pub(super) fn verify_envelope_mode(
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    authority: &VerifiedWorkspaceReviewAuthority,
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
    delivery_mode: &str,
) -> Result<(VerifiedWorkspaceReviewDecision, Vec<u8>), String> {
    validate_context(context)?;
    if envelope.schema != NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA
        || envelope.version != NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION
        || envelope.purpose != NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE
        || envelope.authority_generation == 0
        || !valid_lower_hex(&envelope.authority_key_id)
        || !valid_lower_hex(&envelope.authority_record_digest)
        || !valid_lower_hex(&envelope.workspace_binding)
        || !valid_lower_hex(&envelope.device_binding)
        || !valid_lower_hex(&envelope.installation_binding)
        || !valid_lower_hex(&envelope.scope_binding)
        || !valid_lower_hex(&envelope.request_binding)
        || !valid_lower_hex(&envelope.action_binding)
        || !valid_lower_hex(&envelope.intent_binding)
        || !valid_lower_hex(&envelope.revision_binding)
        || !valid_lower_hex(&envelope.policy_binding)
        || !valid_lower_hex(&envelope.retry_scope_binding)
        || !valid_lower_hex(&envelope.claim_id)
        || envelope.delivery_mode != delivery_mode
        || !matches!(envelope.decision.as_str(), "allow" | "deny")
        || envelope.issued_at_ms == 0
        || envelope.expires_at_ms <= envelope.issued_at_ms
        || envelope.expires_at_ms - envelope.issued_at_ms > NATIVE_WORKSPACE_REVIEW_MAX_TTL_MS
        || now_ms < envelope.issued_at_ms
        || now_ms >= envelope.expires_at_ms
        || envelope.decision_signature.len() != ED25519_SIGNATURE_HEX_BYTES
        || !envelope
            .decision_signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        if now_ms >= envelope.expires_at_ms && envelope.expires_at_ms > envelope.issued_at_ms {
            return Err("native_workspace_review_decision_expired".to_owned());
        }
        if now_ms < envelope.issued_at_ms && envelope.expires_at_ms > envelope.issued_at_ms {
            return Err("native_workspace_review_decision_not_yet_valid".to_owned());
        }
        return Err("native_workspace_review_decision_invalid".to_owned());
    }
    if envelope.authority_generation != authority.enrollment_generation
        || envelope.authority_key_id != authority.key_id
        || envelope.authority_record_digest != authority.record_digest
    {
        return Err("native_workspace_review_decision_authority_mismatch".to_owned());
    }
    if envelope.workspace_binding != authority.workspace_binding
        || envelope.device_binding != authority.device_binding
        || envelope.installation_binding != authority.installation_binding
        || envelope.scope_binding != authority.scope_binding
        || envelope.workspace_binding != context.workspace_binding
        || envelope.device_binding != context.device_binding
        || envelope.installation_binding != context.installation_binding
        || envelope.scope_binding != context.scope_binding
        || envelope.request_binding != context.request_binding
    {
        return Err("native_workspace_review_decision_provenance_mismatch".to_owned());
    }
    if envelope.action_binding != context.action_binding
        || envelope.intent_binding != context.intent_binding
        || envelope.revision_binding != context.revision_binding
        || envelope.policy_binding != context.policy_binding
        || envelope.retry_scope_binding != context.retry_scope_binding
    {
        return Err("native_workspace_review_decision_binding_mismatch".to_owned());
    }
    let signature_bytes = hex::decode(&envelope.decision_signature)
        .map_err(|_| "native_workspace_review_decision_signature_invalid".to_owned())?;
    let signing = signing_bytes(envelope)?;
    let mut message =
        Vec::with_capacity(NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN.len() + signing.len());
    message.extend_from_slice(NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN);
    message.extend_from_slice(&signing);
    signature::UnparsedPublicKey::new(&signature::ED25519, authority.public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| "native_workspace_review_decision_signature_invalid".to_owned())?;
    let canonical = canonical_envelope_bytes(envelope)?;
    let verified = VerifiedWorkspaceReviewDecision {
        decision: envelope.decision.clone(),
        claim_id: envelope.claim_id.clone(),
        authority_record_digest: envelope.authority_record_digest.clone(),
        workspace_binding: envelope.workspace_binding.clone(),
        device_binding: envelope.device_binding.clone(),
        installation_binding: envelope.installation_binding.clone(),
        scope_binding: envelope.scope_binding.clone(),
        request_binding: envelope.request_binding.clone(),
        action_binding: envelope.action_binding.clone(),
        intent_binding: envelope.intent_binding.clone(),
        revision_binding: envelope.revision_binding.clone(),
        policy_binding: envelope.policy_binding.clone(),
        retry_scope_binding: envelope.retry_scope_binding.clone(),
        request_snapshot_digest: None,
        envelope_digest: digest_bytes(&canonical),
        observed_at_ms: now_ms,
        replayed: false,
    };
    Ok((verified, canonical))
}

pub(super) fn verify_and_claim_at(
    state_base: &Path,
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    verify_and_claim_at_mode(
        state_base,
        envelope,
        context,
        now_ms,
        NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY,
    )
}

pub(super) fn verify_and_claim_at_mode(
    state_base: &Path,
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
    delivery_mode: &str,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let mut state = super::super::workspace_review_secure_state::load(state_base)?
        .ok_or_else(|| "native_workspace_review_secure_state_unavailable".to_owned())?;
    let mut floor_changed = false;
    if state.last_observed_time_ms == 0 {
        // A v1 state created before the floor existed still carries expiry
        // timestamps. Seed the observation floor from the latest consumed
        // expiry so a v1 history cannot replay under a rolled-back clock.
        // Cap the migrated floor at the current wall clock: a floor above
        // `now_ms` would reject every subsequent decision as clock_rollback
        // until that expiry elapsed, permanently locking out an honest
        // upgraded install whose latest claim is still in the future. The
        // rollback guard only needs to prevent *backward* movement from the
        // real wall clock, and replay is independently blocked by claim
        // tombstones and the envelope expiry check, so capping preserves
        // the security property without the false-positive wedge.
        let migrated_floor = state
            .consumed_claims
            .iter()
            .filter_map(|claim| claim.expires_at_ms)
            .max()
            .unwrap_or(0)
            .min(now_ms);
        if migrated_floor != 0 {
            state.last_observed_time_ms = migrated_floor;
            floor_changed = true;
        }
    }
    if now_ms < state.last_observed_time_ms {
        return Err("native_workspace_review_clock_rollback".to_owned());
    }
    if now_ms > state.last_observed_time_ms {
        state.last_observed_time_ms = now_ms;
        floor_changed = true;
    }
    if floor_changed {
        state.validate()?;
        // Persist the floor before validating the authority or candidate.
        // Invalid, expired, and not-yet-valid requests must still advance the
        // durable observation floor.
        super::super::workspace_review_secure_state::store(state_base, &state)?;
    }
    let authority = read_installed_record(state_base, now_ms)?
        .ok_or_else(|| "native_workspace_review_authority_missing".to_owned())?;
    if authority.status != "active" {
        return Err("native_workspace_review_authority_revoked".to_owned());
    }
    state = super::super::workspace_review_secure_state::load(state_base)?
        .ok_or_else(|| "native_workspace_review_secure_state_unavailable".to_owned())?;
    if !state.matches_authority(&authority) {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    let (verified, _) = verify_envelope_mode(envelope, &authority, context, now_ms, delivery_mode)?;
    let semantic_digest = semantic_decision_digest(envelope)?;
    if consume_or_replay_claim(state_base, &mut state, &verified, &semantic_digest)? {
        if delivery_mode == NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH {
            return Err("native_workspace_review_business_dispatch_replay".to_owned());
        }
        let mut resumed = verified;
        resumed.replayed = true;
        return Ok(resumed);
    }
    super::super::workspace_review_secure_state::record_claim(
        state_base,
        &mut state,
        WorkspaceReviewClaimV1 {
            claim_id: verified.claim_id.clone(),
            envelope_digest: verified.envelope_digest.clone(),
            semantic_decision_digest: Some(semantic_digest),
            legacy_semantic_recovered: false,
            expires_at_ms: Some(envelope.expires_at_ms),
        },
    )?;
    Ok(verified)
}

pub(super) fn read_query_authority(
    state_base: &Path,
    time: u64,
) -> Result<
    (
        VerifiedWorkspaceReviewAuthority,
        super::super::workspace_review_secure_state::WorkspaceReviewSecureStateV1,
    ),
    String,
> {
    let state = super::super::workspace_review_secure_state::load(state_base)?
        .ok_or_else(|| "native_workspace_review_secure_state_unavailable".to_owned())?;
    if time < state.last_observed_time_ms {
        return Err("native_workspace_review_clock_rollback".to_owned());
    }
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let (value, bytes) = super::super::policy_store_persistence::read_private_json(
        &state_base.join(super::super::workspace_review_authority::AUTHORITY_FILE_NAME),
        guard_contracts::NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES as u64,
        "workspace_review_authority",
        &private_root,
    )
    .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?
    .ok_or_else(|| "native_workspace_review_authority_missing".to_owned())?;
    if canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?
        != bytes
    {
        return Err("native_workspace_review_authority_noncanonical".to_owned());
    }
    let record = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_authority_invalid".to_owned())?;
    let authority = super::super::workspace_review_authority::verify_record(&record, time)?;
    if !state.matches_authority(&authority) || state.pending_authority_record.is_some() {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    let enrollment = super::super::approval_enrollment::load_unlocked(state_base)?
        .ok_or_else(|| "native_workspace_review_enrollment_required".to_owned())?;
    if enrollment.status == "revoked" || authority.status != "active" {
        return Err("native_workspace_review_authority_revoked".to_owned());
    }
    if enrollment.device_binding != authority.device_binding
        || enrollment.installation_binding != authority.installation_binding
    {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    Ok((authority, state))
}

#[cfg(test)]
pub(super) fn query_consumption_at(
    state_base: &Path,
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    context: &WorkspaceReviewDecisionContext<'_>,
    time: u64,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let (authority, state) = read_query_authority(state_base, time)?;
    query_consumption_verified(state_base, envelope, context, time, &authority, &state)
}

pub(super) fn query_consumption_verified(
    state_base: &Path,
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    context: &WorkspaceReviewDecisionContext<'_>,
    time: u64,
    authority: &VerifiedWorkspaceReviewAuthority,
    state: &super::super::workspace_review_secure_state::WorkspaceReviewSecureStateV1,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let (mut verified, _) = verify_envelope_mode(
        envelope,
        authority,
        context,
        time,
        NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY,
    )?;
    if verified.decision != "allow" {
        return Err("native_workspace_review_decision_declined".to_owned());
    }
    let semantic = semantic_decision_digest(envelope)?;
    if !claim_semantics::query_consumed_claim(state_base, state, &verified, &semantic)? {
        return Err("native_workspace_review_consumption_unconfirmed".to_owned());
    }
    verified.replayed = true;
    Ok(verified)
}

pub(crate) fn current_native_workspace_review_bindings(
    state_base: &Path,
    scope_digest: &str,
) -> Result<(String, String), String> {
    // This native tuple is the enrollment contract; request metadata cannot
    // supply a fallback workspace or scope binding.
    let (guard_home, expected_scope_digest) =
        super::super::policy_store_authority::scope_binding_for_state_base(state_base);
    if scope_digest != expected_scope_digest {
        return Err("native_policy_snapshot_scope_mismatch".to_owned());
    }
    let workspace_binding = crate::approval::binding_digest("workspace", &[guard_home.as_str()])?;
    let scope_binding =
        crate::approval::binding_digest("scope", &[scope_digest, workspace_binding.as_str()])?;
    Ok((workspace_binding, scope_binding))
}

pub(crate) fn ensure_current_native_workspace_review_provenance(
    authority: &VerifiedWorkspaceReviewAuthority,
    workspace_binding: &str,
    scope_binding: &str,
) -> Result<(), String> {
    if authority.workspace_binding != workspace_binding || authority.scope_binding != scope_binding
    {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    Ok(())
}
