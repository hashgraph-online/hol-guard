#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Verification and durable one-shot claiming for workspace-review decisions.
//!
//! The resident dispatch accepts only a Rust contract signed by the installed
//! Ed25519 workspace key; Portal metadata and legacy RSA-PSS artifacts never
//! enter this path.

use guard_contracts::{
    WorkspaceReviewDecisionEnvelopeV1, NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE,
    NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY, NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA, NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES, NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES,
    NATIVE_WORKSPACE_REVIEW_MAX_TTL_MS, NATIVE_WORKSPACE_REVIEW_RETRY_SCOPE_DOMAIN,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use ring::signature;
use serde_json::Value;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::workspace_review_authority::{read_installed_record, VerifiedWorkspaceReviewAuthority};
use super::workspace_review_secure_state::WorkspaceReviewClaimV1;

const DIGEST_HEX_BYTES: usize = 64;
const ED25519_SIGNATURE_HEX_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceReviewDecisionContext<'a> {
    pub(crate) workspace_binding: &'a str,
    pub(crate) device_binding: &'a str,
    pub(crate) installation_binding: &'a str,
    /// Must be derived by the native request path from the installed authority
    /// and current policy scope; callers cannot select a different scope.
    pub(crate) scope_binding: &'a str,
    pub(crate) request_binding: &'a str,
    pub(crate) action_binding: &'a str,
    pub(crate) intent_binding: &'a str,
    pub(crate) revision_binding: &'a str,
    pub(crate) policy_binding: &'a str,
    /// Digest of the fresh retry's stable intent/action/policy scope. The
    /// native retry path must derive it from a newly validated request; this
    /// module has no continuation API for the expired original attempt.
    pub(crate) retry_scope_binding: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedWorkspaceReviewDecision {
    pub(crate) decision: String,
    pub(crate) claim_id: String,
    pub(crate) authority_record_digest: String,
    pub(crate) workspace_binding: String,
    pub(crate) device_binding: String,
    pub(crate) installation_binding: String,
    pub(crate) scope_binding: String,
    pub(crate) request_binding: String,
    pub(crate) action_binding: String,
    pub(crate) intent_binding: String,
    pub(crate) revision_binding: String,
    pub(crate) policy_binding: String,
    pub(crate) retry_scope_binding: String,
    pub(crate) envelope_digest: String,
    /// True only when the same durable claim is being resumed after a lost
    /// response. It is never a second acceptance of the envelope.
    pub(crate) replayed: bool,
}

fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

fn valid_lower_hex(value: &str) -> bool {
    value.len() == DIGEST_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn retry_scope_binding(
    action_binding: &str,
    intent_binding: &str,
    revision_binding: &str,
    policy_binding: &str,
) -> Result<String, String> {
    if ![
        action_binding,
        intent_binding,
        revision_binding,
        policy_binding,
    ]
    .iter()
    .all(|value| valid_lower_hex(value))
    {
        return Err("native_workspace_review_decision_binding_invalid".to_owned());
    }
    let value = serde_json::json!({
        "action_binding": action_binding,
        "intent_binding": intent_binding,
        "revision_binding": revision_binding,
        "policy_binding": policy_binding,
    });
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_decision_binding_invalid".to_owned())?;
    let mut preimage =
        Vec::with_capacity(NATIVE_WORKSPACE_REVIEW_RETRY_SCOPE_DOMAIN.len() + canonical.len());
    preimage.extend_from_slice(NATIVE_WORKSPACE_REVIEW_RETRY_SCOPE_DOMAIN);
    preimage.extend_from_slice(&canonical);
    Ok(digest_bytes(&preimage))
}

fn signing_value(envelope: &WorkspaceReviewDecisionEnvelopeV1) -> Result<Value, String> {
    let mut value = serde_json::to_value(envelope)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    value
        .as_object_mut()
        .ok_or_else(|| "native_workspace_review_decision_invalid".to_owned())?
        .remove("decision_signature");
    Ok(value)
}

pub(crate) fn signing_bytes(
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
) -> Result<Vec<u8>, String> {
    canonical_json_bytes(&signing_value(envelope)?)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())
}

fn canonical_envelope_bytes(
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
) -> Result<Vec<u8>, String> {
    canonical_json_bytes(
        &serde_json::to_value(envelope)
            .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?,
    )
    .map_err(|_| "native_workspace_review_decision_invalid".to_owned())
}

fn validate_context(context: &WorkspaceReviewDecisionContext<'_>) -> Result<(), String> {
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

fn verify_envelope(
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    authority: &VerifiedWorkspaceReviewAuthority,
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
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
        || envelope.delivery_mode != NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY
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
        envelope_digest: digest_bytes(&canonical),
        replayed: false,
    };
    Ok((verified, canonical))
}

pub(crate) fn verify_and_claim(
    state_base: &Path,
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    context: &WorkspaceReviewDecisionContext<'_>,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let now_ms = now_ms()?;
    super::approval_enrollment::with_transition_lock(state_base, || {
        verify_and_claim_at(state_base, envelope, context, now_ms)
    })
}

fn verify_and_claim_at(
    state_base: &Path,
    envelope: &WorkspaceReviewDecisionEnvelopeV1,
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let authority = read_installed_record(state_base, now_ms)?
        .ok_or_else(|| "native_workspace_review_authority_missing".to_owned())?;
    if authority.status != "active" {
        return Err("native_workspace_review_authority_revoked".to_owned());
    }
    let mut state = super::workspace_review_secure_state::load(state_base)?
        .ok_or_else(|| "native_workspace_review_secure_state_unavailable".to_owned())?;
    if !state.matches_authority(&authority) {
        return Err("native_workspace_review_authority_provenance_mismatch".to_owned());
    }
    if state.last_observed_time_ms == 0 {
        // A v1 state created before the floor existed still carries expiry
        // timestamps. Treat the latest one as the conservative migration
        // floor instead of allowing a rollback to replay an old claim.
        state.last_observed_time_ms = state
            .consumed_claims
            .iter()
            .filter_map(|claim| claim.expires_at_ms)
            .max()
            .unwrap_or(0);
    }
    if now_ms < state.last_observed_time_ms {
        return Err("native_workspace_review_clock_rollback".to_owned());
    }
    if now_ms > state.last_observed_time_ms {
        state.last_observed_time_ms = now_ms;
        state.validate()?;
        // Persist the floor before validating the candidate. Invalid or
        // expired requests must still advance the durable observation floor.
        super::workspace_review_secure_state::store(state_base, &state)?;
    }
    let (verified, _) = verify_envelope(envelope, &authority, context, now_ms)?;
    if let Some(claim) = state
        .consumed_claims
        .iter()
        .find(|claim| claim.claim_id == verified.claim_id)
    {
        if claim.envelope_digest != verified.envelope_digest {
            return Err("native_workspace_review_decision_replay".to_owned());
        }
        let mut resumed = verified;
        resumed.replayed = true;
        return Ok(resumed);
    }
    state.consumed_claims.retain(|claim| {
        claim
            .expires_at_ms
            .map(|expires_at_ms| expires_at_ms > now_ms)
            .unwrap_or(true)
    });
    if state.consumed_claims.len() >= NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES {
        return Err("native_workspace_review_decision_replay_full".to_owned());
    }
    state.consumed_claims.push(WorkspaceReviewClaimV1 {
        claim_id: verified.claim_id.clone(),
        envelope_digest: verified.envelope_digest.clone(),
        expires_at_ms: Some(envelope.expires_at_ms),
    });
    state.validate()?;
    super::workspace_review_secure_state::store(state_base, &state)?;
    Ok(verified)
}

pub(crate) fn verify_and_claim_bytes(
    state_base: &Path,
    bytes: &[u8],
    context: &WorkspaceReviewDecisionContext<'_>,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    if bytes.is_empty() || bytes.len() > NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES {
        return Err("native_workspace_review_decision_invalid".to_owned());
    }
    let value: Value = crate::strict_json_value(bytes)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_decision_noncanonical".to_owned());
    }
    let envelope: WorkspaceReviewDecisionEnvelopeV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    verify_and_claim(state_base, &envelope, context)
}

/// Verify one decision against the request snapshot selected by `request_id`.
/// The selector is not a binding input: all request and action material comes
/// from the private snapshot loaded by the resident.
pub(crate) fn verify_and_claim_request(
    state_base: &Path,
    request_id: &str,
    decision: &Value,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let authority = super::workspace_review_authority::load(state_base)?
        .ok_or_else(|| "native_workspace_review_authority_missing".to_owned())?;
    let request = super::workspace_review_request::load(state_base, request_id)?;
    let context = WorkspaceReviewDecisionContext {
        workspace_binding: &authority.workspace_binding,
        device_binding: &authority.device_binding,
        installation_binding: &authority.installation_binding,
        scope_binding: &authority.scope_binding,
        request_binding: &request.request_binding,
        action_binding: &request.action_binding,
        intent_binding: &request.intent_binding,
        revision_binding: &request.revision_binding,
        policy_binding: &request.policy_binding,
        retry_scope_binding: &request.retry_scope_binding,
    };
    let bytes = canonical_json_bytes(decision)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    verify_and_claim_bytes(state_base, &bytes, &context)
}

#[cfg(test)]
pub(crate) fn verify_and_claim_bytes_at(
    state_base: &Path,
    bytes: &[u8],
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    if bytes.is_empty() || bytes.len() > NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES {
        return Err("native_workspace_review_decision_invalid".to_owned());
    }
    let value: Value = crate::strict_json_value(bytes)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_workspace_review_decision_noncanonical".to_owned());
    }
    let envelope: WorkspaceReviewDecisionEnvelopeV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_decision_invalid".to_owned())?;
    verify_and_claim_at(state_base, &envelope, context, now_ms)
}

#[cfg(test)]
#[path = "workspace_review_decision_tests.rs"]
mod tests;
