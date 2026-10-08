#![forbid(unsafe_code)]
//! Verification and durable one-shot claiming for workspace-review decisions.
//!
//! The resident dispatch accepts only a Rust contract signed by the installed
//! Ed25519 workspace key; Portal metadata and legacy RSA-PSS artifacts never
//! enter this path.

use guard_contracts::{
    WorkspaceReviewDecisionEnvelopeV1, NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE,
    NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_OWNED_DISPATCH,
    NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY, NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN,
    NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA, NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION,
    NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES, NATIVE_WORKSPACE_REVIEW_MAX_TTL_MS,
    NATIVE_WORKSPACE_REVIEW_RETRY_SCOPE_DOMAIN, NATIVE_WORKSPACE_REVIEW_SEMANTIC_DECISION_DOMAIN,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde_json::Value;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::workspace_review_authority::VerifiedWorkspaceReviewAuthority;

const DIGEST_HEX_BYTES: usize = 64;
const ED25519_SIGNATURE_HEX_BYTES: usize = 128;

#[path = "workspace_review_decision_claims.rs"]
mod claim_semantics;
use claim_semantics::consume_or_replay_claim;
#[path = "workspace_review_decision_semantics.rs"]
mod semantics;
pub(crate) use semantics::{owned_request_digest, semantic_decision_digest};
#[path = "workspace_review_decision_verification.rs"]
pub(crate) mod verification;
#[cfg(test)]
use verification::{query_consumption_at, verify_envelope};
use verification::{verify_and_claim_at, verify_and_claim_at_mode};

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
    pub(crate) request_snapshot_digest: Option<String>,
    pub(crate) envelope_digest: String,
    pub(crate) observed_at_ms: u64,
    /// True only when the same durable claim is being resumed after a lost
    /// response. It is never a second acceptance of the envelope.
    pub(crate) replayed: bool,
}

pub(super) fn now_ms() -> Result<u64, String> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(value).map_err(|_| "native_resident_clock_invalid".to_owned())
}

pub(super) fn valid_lower_hex(value: &str) -> bool {
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

#[path = "workspace_review_decision_request.rs"]
mod request_claim;
#[cfg(test)]
pub(crate) use request_claim::claim_owned_business_request_at_for_test;
#[cfg(test)]
pub(crate) use request_claim::claim_owned_business_request_with_clock;
pub(crate) use request_claim::query_request_consumption;
pub(crate) use request_claim::verify_and_claim_request;
#[allow(unused_imports)] // Private worker routing is not enabled yet.
pub(crate) use request_claim::{claim_owned_business_request, claim_owned_business_request_with};

pub(crate) fn verify_and_claim_bytes_at(
    state_base: &Path,
    bytes: &[u8],
    context: &WorkspaceReviewDecisionContext<'_>,
    now_ms: u64,
) -> Result<VerifiedWorkspaceReviewDecision, String> {
    let envelope = request_claim::decode_canonical_decision(bytes)?;
    verify_and_claim_at(state_base, &envelope, context, now_ms)
}

#[cfg(test)]
#[path = "workspace_review_decision_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "workspace_review_decision_renewal_tests.rs"]
mod renewal_tests;

#[cfg(test)]
#[path = "workspace_review_decision_legacy_tests.rs"]
mod legacy_tests;
