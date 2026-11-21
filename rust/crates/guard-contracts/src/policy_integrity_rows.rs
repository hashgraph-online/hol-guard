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
//! The `generation` section decides startup's trusted control state from
//! the store's local rows: it adopts a single newer authenticated generation,
//! completes or abandons a pending generation, and marks cutover complete once
//! no legacy row remains. The `reconcile` section decides only the fate of a
//! pending generation, over rows the caller ships from its own open
//! transaction.
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
/// Capability advertised by the runtime when the request may carry a
/// `generation` section.
pub const POLICY_INTEGRITY_GENERATION_FEATURE: &str = "policy-integrity-generation-v1";
/// Capability advertised by the runtime when the request may carry a
/// `reconcile` section.
pub const POLICY_INTEGRITY_RECONCILE_FEATURE: &str = "policy-integrity-reconcile-v1";

/// Largest canonical request serialization the op will accept.
pub const POLICY_INTEGRITY_ROWS_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most verify plus sign items one request may carry.
pub const POLICY_INTEGRITY_ROWS_MAX_ITEMS: usize = 1024;
/// Most rows one `reconcile` section may carry. The decision runs over every
/// local row, but the rows arrive in chunks that are folded into counters, so
/// this bounds a single request rather than the store. A store of any size can
/// settle its pending generation by sending more chunks.
pub const POLICY_INTEGRITY_RECONCILE_MAX_ROWS: usize = 16_384;

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
    /// Startup generation decision over the store's local rows. Needs the
    /// key; answered in the payload's `generation` section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<PolicyIntegrityGenerationRequestV1>,
    /// Pending-generation reconcile over rows the caller supplies. Needs the
    /// key; answered in the payload's `reconcile` section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile: Option<PolicyIntegrityReconcileRequestV1>,
}

/// Decide the startup policy-integrity control state from the local rows of
/// `store_path`, which must be `guard.db` directly under `guard_home`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityGenerationRequestV1 {
    pub store_path: String,
    pub guard_home: String,
    /// The normalized control state the store currently trusts.
    pub trusted_state: Value,
}

/// Decide what becomes of a pending generation, over rows the caller ships
/// rather than rows read from the store.
///
/// The store is deliberately not read here. This runs while the caller holds
/// an open transaction, whose rows a separate read-only connection would not
/// see, so the caller passes the rows its own connection returned.
///
/// A store larger than one request sends its rows in chunks. Each chunk is
/// folded into [`PolicyIntegrityReconcileTallyV1`] counters and handed back,
/// the caller carries those counters into the next chunk, and the last chunk
/// asks for the decision. The decision itself is taken only here, from the
/// counters; the caller never interprets them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityReconcileRequestV1 {
    /// The normalized control state the store currently trusts.
    pub trusted_state: Value,
    /// This chunk of the store's local `policy_decisions` rows, as JSON
    /// objects. Remote sources are excluded by the caller's own query.
    pub rows: Vec<Value>,
    /// The counters folded from the chunks already sent for this store, or
    /// `None` for the first chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried: Option<PolicyIntegrityReconcileTallyV1>,
    /// `true` decides the pending generation from `carried` plus `rows`;
    /// `false` returns their running counters for the next chunk to carry.
    pub decide: bool,
}

/// What the rows seen so far say about the pending generation.
///
/// Every field counts rows, so chunks add: the decision rule reads the totals
/// exactly as it would read one pass over the whole store.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityReconcileTallyV1 {
    /// Rows folded so far.
    pub rows: u64,
    /// A row carries an integrity version older than the current one.
    pub has_legacy: bool,
    /// Rows at the current integrity version.
    pub pending_candidates: u64,
    /// Rows that verify at the pending generation.
    pub pending_valid: u64,
    /// Rows that do not verify at the pending generation but do verify at the
    /// current one.
    pub current_valid: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityReconcileOutcomeV1 {
    /// The control state the store should trust, present when the request
    /// asked for the decision. Equal to `trusted_state` when the pending
    /// generation is neither completed nor abandoned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_state: Option<Value>,
    /// The running counters, present when the request did not ask for the
    /// decision. The caller carries them into its next chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tally: Option<PolicyIntegrityReconcileTallyV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyIntegrityGenerationOutcomeV1 {
    /// The control state startup should trust after authenticating the rows.
    pub prepared_state: Value,
    /// Every local row verifies at the trusted state's generation.
    pub still_matches: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<PolicyIntegrityGenerationOutcomeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile: Option<PolicyIntegrityReconcileOutcomeV1>,
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
