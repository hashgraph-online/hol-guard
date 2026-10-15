//! `PolicyIntegrityRows` — wire contract for the resident op that verifies
//! and signs local policy rows with the policy-integrity HMAC key.
//!
//! The op answers the batch verify/sign loops the store runs outside the
//! saved-decision lookup: generation advance on policy writes, pending
//! generation reconcile, startup prefetch, migration, and single-row
//! verification for decision payloads. The resident computes every
//! canonical payload, SHA-256 hash and HMAC-SHA256 tag; the caller only
//! ships rows and the resolved key and stores what comes back.
//!
//! The key arrives as base64url without padding, is held zeroized for the
//! duration of the request, and never appears in a result or an error.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA: &str = "guard-policy-integrity-rows-request.v1";
/// Schema discriminator for the result.
pub const POLICY_INTEGRITY_ROWS_RESULT_SCHEMA: &str = "guard-policy-integrity-rows-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const POLICY_INTEGRITY_ROWS_FEATURE: &str = "policy-integrity-rows-v1";

/// Largest canonical request serialization the op will accept.
pub const POLICY_INTEGRITY_ROWS_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most verify plus sign items one request may carry.
pub const POLICY_INTEGRITY_ROWS_MAX_ITEMS: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityRowsRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Resolved policy-integrity HMAC key bytes (base64url, no padding).
    /// Absent means no key: verify items answer `unknown_key` and any sign
    /// item fails the whole request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_b64: Option<String>,
    /// Key id stored on signed rows; must match the row's `integrity_key_id`
    /// for verification and is written onto signed rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_id: Option<String>,
    pub verify: Vec<PolicyIntegrityVerifyItemV1>,
    pub sign: Vec<PolicyIntegritySignItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityVerifyItemV1 {
    /// The stored `policy_decisions` row as a JSON object.
    pub row: Value,
    pub degraded_mode: bool,
    /// Trusted generation for rollback detection on version-2 rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_generation: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegritySignItemV1 {
    /// The `policy_decisions` row to sign, as a JSON object.
    pub row: Value,
    pub generation: i64,
    pub signed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityRowsResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<PolicyIntegrityRowsPayloadV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityRowsPayloadV1 {
    pub verify: Vec<PolicyIntegrityVerifyOutcomeV1>,
    pub sign: Vec<PolicyIntegritySignatureV1>,
}

/// `PolicyIntegrityVerificationResult` fields, one per verify item in order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityVerifyOutcomeV1 {
    pub status: String,
    pub payload_hash: Option<String>,
    pub key_id: Option<String>,
    pub message: Option<String>,
}

/// The six integrity columns, one per sign item in order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegritySignatureV1 {
    pub integrity_version: i64,
    pub integrity_generation: i64,
    pub payload_hash: String,
    pub payload_mac: String,
    pub integrity_key_id: String,
    pub signed_at: String,
}
