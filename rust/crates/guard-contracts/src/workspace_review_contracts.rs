use serde::{Deserialize, Serialize};

/// Purpose-specific root-enrolled authority metadata for the native
/// workspace-review delegation path. This is not a Portal decision artifact.
pub const NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_SCHEMA: &str =
    "guard-native-workspace-review-authority.v1";
pub const NATIVE_WORKSPACE_REVIEW_AUTHORITY_V1_VERSION: u16 = 1;
pub const NATIVE_WORKSPACE_REVIEW_AUTHORITY_PURPOSE: &str = "cloud_review_team_delegation";
pub const NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1: &str =
    "guard-native-workspace-review-scope.v1";
pub const NATIVE_WORKSPACE_REVIEW_KEY_ALGORITHM_ED25519: &str = "ed25519";
pub const NATIVE_WORKSPACE_REVIEW_ENROLLMENT_DOMAIN: &[u8] =
    b"guard-native-workspace-review-enrollment-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_DECISION_V1_SCHEMA: &str =
    "guard-native-workspace-review-decision.v1";
pub const NATIVE_WORKSPACE_REVIEW_DECISION_V1_VERSION: u16 = 1;
pub const NATIVE_WORKSPACE_REVIEW_DECISION_DOMAIN: &[u8] =
    b"guard-native-workspace-review-decision-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_DECISION_DELIVERY_RETRY_ONLY: &str = "validated_retry_only";
pub const NATIVE_WORKSPACE_REVIEW_RETRY_SCOPE_DOMAIN: &[u8] =
    b"guard-native-workspace-review-retry-scope-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_REQUEST_BINDING_DOMAIN: &[u8] =
    b"guard-native-workspace-review-request-binding-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_ACTION_BINDING_DOMAIN: &[u8] =
    b"guard-native-workspace-review-action-binding-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_INTENT_BINDING_DOMAIN: &[u8] =
    b"guard-native-workspace-review-intent-binding-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_REVISION_BINDING_DOMAIN: &[u8] =
    b"guard-native-workspace-review-revision-binding-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_POLICY_BINDING_DOMAIN: &[u8] =
    b"guard-native-workspace-review-policy-binding-v1\0";
pub const NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_VERSION_BYTES: usize = 128;
pub const NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_BINDING_BYTES: usize = 64;
pub const NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES: usize = 16 * 1024;
pub const NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES: usize = 16 * 1024;
pub const NATIVE_WORKSPACE_REVIEW_MAX_TTL_MS: u64 = 365 * 24 * 60 * 60 * 1000;
pub const NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES: usize = 1024;

/// The root-signed record binds one workspace-review key to one installation.
/// The current contract intentionally accepts Ed25519 only. Existing Portal
/// RSA-PSS review keys remain legacy until Rust has a bounded verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReviewAuthorityV1 {
    pub schema: String,
    pub version: u16,
    pub purpose: String,
    pub key_algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub workspace_binding: String,
    pub device_binding: String,
    pub installation_binding: String,
    pub enrollment_generation: u64,
    pub previous_key_id: Option<String>,
    pub scope_contract_version: String,
    pub scope_binding: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: String,
    pub enrollment_signature: String,
}

/// A workspace-key decision is separate from the root enrollment record. The
/// installed authority digest and every request/policy binding are repeated so
/// a later native consumer cannot substitute a Portal row or partial context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReviewDecisionEnvelopeV1 {
    pub schema: String,
    pub version: u16,
    pub purpose: String,
    pub authority_generation: u64,
    pub authority_key_id: String,
    pub authority_record_digest: String,
    pub workspace_binding: String,
    pub device_binding: String,
    pub installation_binding: String,
    pub scope_binding: String,
    pub request_binding: String,
    pub action_binding: String,
    pub intent_binding: String,
    pub revision_binding: String,
    pub policy_binding: String,
    pub retry_scope_binding: String,
    pub delivery_mode: String,
    pub decision: String,
    pub claim_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub decision_signature: String,
}
