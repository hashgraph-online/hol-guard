//! `ClaimApprovalReuseDecisions` — wire contract for the resident op that
//! claims a batch of prevalidated policy/local-once reuse decisions under one
//! SQLite `BEGIN IMMEDIATE` transaction.
//!
//! Unlike `ApprovalReuseDecide` (pure lattice), this op performs IO against the
//! guard store and secret store: it opens `store_path`, resolves policy-
//! integrity secret material + integrity state from `guard_home`, then calls
//! `claim_approval_reuse_decisions`. Key bytes never cross the wire; the
//! resident derives them locally.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA: &str = "guard-claim-approval-reuse-request.v1";
/// Schema discriminator for the result.
pub const CLAIM_APPROVAL_REUSE_RESULT_SCHEMA: &str = "guard-claim-approval-reuse-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CLAIM_APPROVAL_REUSE_FEATURE: &str = "claim-approval-reuse-v1";

/// Largest canonical request serialization the op will accept.
pub const CLAIM_APPROVAL_REUSE_MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimApprovalReuseDecisionsRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Absolute path to the guard store SQLite database.
    pub store_path: String,
    /// Absolute path to the resolved guard home (for scoped secret refs).
    pub guard_home: String,
    /// Prevalidated member decisions; each must carry `approval_id` (str) or
    /// `decision_id` (int).
    pub decisions: Vec<Value>,
    /// Claim timestamp (`YYYY-MM-DDTHH:MM:SS+00:00`); batch applies it to every
    /// member and both the revision re-check and each claim's expiry window.
    pub now: String,
    /// Materialized policy-bundle row identities (11-tuples); `None`/missing
    /// means the bundle source is unset → identity compare short-circuits per
    /// member without touching the bundle table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_bundle_decision_identities: Option<Vec<Vec<Value>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimApprovalReuseDecisionsResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_claim_approval_reuse_*` failure codes.
    pub code: String,
    /// `{ "claimed": bool }` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
