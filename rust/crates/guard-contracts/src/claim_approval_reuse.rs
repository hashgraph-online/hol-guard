//! `ClaimApprovalReuseDecisions` — wire contract for the resident op that
//! claims a batch of prevalidated policy/local-once reuse decisions under one
//! SQLite `BEGIN IMMEDIATE` transaction.
//!
//! Unlike `ApprovalReuseDecide` (pure lattice), this op performs IO against the
//! guard store: it opens `store_path` and claims the batch. The OS-keyring
//! facing integrity evidence (refreshed integrity state, HMAC key material,
//! materialized policy-bundle identities) is procured by the Python transport
//! and shipped in the request, exactly as for `PolicyDecisionLookup`. Because
//! that evidence is gathered before the claim's write lock is taken, the
//! request also carries an [`ClaimEvidenceBindingV1`] the resident re-verifies
//! under the lock.

use std::collections::BTreeMap;

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
    /// `_refresh_policy_integrity_state(...)` output captured before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_state: Option<Value>,
    /// Policy-integrity HMAC key bytes (base64url, no padding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity_key_id: Option<String>,
    /// Local-once approval HMAC key bytes (base64url, no padding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_once_integrity_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_once_integrity_key_id: Option<String>,
    /// What the caller read, outside the claim's write lock, to build the
    /// evidence above. The resident re-reads the same sources under the lock
    /// and refuses the whole batch when any of them moved, so evidence gathered
    /// before dispatch can never authorize a claim after its sources changed.
    /// Required whenever a member needs integrity state or bundle identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_binding: Option<ClaimEvidenceBindingV1>,
}

/// The store-resident sources the shipped evidence was derived from.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimEvidenceBindingV1 {
    /// Lowercase SHA-256 of each `sync_state` payload the policy-bundle
    /// identities were derived from; `null` when the row was absent.
    #[serde(default)]
    pub sync_state_sha256: BTreeMap<String, Option<String>>,
    /// Cloud workspace id the bundle was validated against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_workspace_id: Option<String>,
    /// Local device the materialized bundle rows were derived for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<ClaimDeviceBindingV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimDeviceBindingV1 {
    pub installation_id: String,
    pub device_label: String,
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
