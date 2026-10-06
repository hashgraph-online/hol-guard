//! `ApprovalReuseDecide` — wire contract for the resident approval-reuse
//! decision op.
//!
//! `evaluate_approval_reuse` is pure (no IO, no SQLite): the request carries
//! the recomputed action, the optional saved action, and the reuse-eligibility
//! flags; the result carries the `ApprovalReuseDecision.to_evidence()` payload.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_REUSE_REQUEST_SCHEMA: &str = "guard-approval-reuse-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_REUSE_RESULT_SCHEMA: &str = "guard-approval-reuse-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_REUSE_FEATURE: &str = "approval-reuse-v1";

/// Largest canonical request serialization the op will accept.
pub const APPROVAL_REUSE_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReuseRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Recomputed action (untyped wire value; normalized inside the op).
    pub current_action: Value,
    /// Saved action from the persisted row, if a row was found. `None`/`null`
    /// is ambiguous with a malformed stored action unless
    /// `saved_decision_present` is set.
    #[serde(default)]
    pub saved_action: Option<Value>,
    /// Explicit present/absent override for untyped persistence callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_decision_present: Option<bool>,
    /// Reuse-validation failure reason, when the caller rejected the saved row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_reason: Option<String>,
    /// Short-lived, integrity-bound authority from the immediately preceding
    /// review. Persistent policy must never set it.
    #[serde(default)]
    pub fresh_local_approval: bool,
    /// Retained, non-expiring approval-gate allow whose context token and
    /// integrity were verified by the caller.
    #[serde(default)]
    pub durable_exact_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReuseResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_reuse_*` failure codes.
    pub code: String,
    /// The `ApprovalReuseDecision.to_evidence()` payload on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
