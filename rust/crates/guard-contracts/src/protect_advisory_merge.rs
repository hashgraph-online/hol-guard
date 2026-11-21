//! `ProtectAdvisoryMerge` — wire contract for folding locally cached advisory
//! blocks and reviews into a package protect result.
//!
//! The request carries the package protect payload, the cached-advisory
//! verdict for the same command, and the exit code the package path chose.
//! The op decides whether the cached verdict tightens the result and returns
//! the updated payload plus the receipt and event writes the caller persists.
//! A result with no `merged` body leaves the package result unchanged.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const PROTECT_ADVISORY_MERGE_REQUEST_SCHEMA: &str = "guard-protect-advisory-merge-request.v1";
/// Schema discriminator for the result.
pub const PROTECT_ADVISORY_MERGE_RESULT_SCHEMA: &str = "guard-protect-advisory-merge-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const PROTECT_ADVISORY_MERGE_FEATURE: &str = "protect-advisory-merge-v1";

/// Largest canonical request serialization the op will accept. The merged
/// payload is echoed back, so the request is bounded by the response limit.
pub const PROTECT_ADVISORY_MERGE_MAX_REQUEST_BYTES: usize = crate::MAX_NATIVE_RESPONSE_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectAdvisoryMergeRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// The package protect payload, as the package path returned it.
    pub payload: Value,
    /// The cached-advisory verdict for the same command.
    pub cached: ProtectCachedVerdictV1,
    /// Whether the caller asked for a dry run.
    pub requested_dry_run: bool,
    /// The exit code the package path chose.
    pub exit_code: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectCachedVerdictV1 {
    /// `allow`, `review` or `block`.
    pub action: String,
    pub reason: String,
    pub risk_signals: Vec<Value>,
    /// The matched cache rows as the store lists them.
    pub matched_advisories: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectAdvisoryMergeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_protect_advisory_merge_*` failure codes.
    pub code: String,
    /// The tightened result; absent when the cached verdict changes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged: Option<ProtectAdvisoryMergeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectAdvisoryMergeV1 {
    /// The updated top-level payload keys.
    pub payload: Value,
    pub exit_code: i64,
    /// The stored receipt whose policy decision changed, if any.
    pub receipt_policy_update: Option<ProtectReceiptPolicyUpdateV1>,
    /// The install-time event to record, if the action changed.
    pub event: Option<ProtectInstallEventV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectReceiptPolicyUpdateV1 {
    pub receipt_id: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProtectInstallEventV1 {
    pub name: String,
    /// Event payload fields in the order they are recorded.
    pub fields: Vec<(String, Value)>,
}
