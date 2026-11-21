//! `ApprovalBulkEligibility` - wire contract for the resident op that decides
//! whether pending approval requests may be approved once in a bulk action.
//!
//! The op is pure (no store access). The caller ships the stored request
//! fields the decision reads; the resident answers one boolean per request.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_BULK_ELIGIBILITY_REQUEST_SCHEMA: &str =
    "guard-approval-bulk-eligibility-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_BULK_ELIGIBILITY_RESULT_SCHEMA: &str =
    "guard-approval-bulk-eligibility-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_BULK_ELIGIBILITY_FEATURE: &str = "approval-bulk-eligibility-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_BULK_ELIGIBILITY_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most requests one call may judge.
pub const APPROVAL_BULK_ELIGIBILITY_MAX_ITEMS: usize = 1024;

/// One stored approval request, narrowed to the fields the decision reads.
/// Values keep their stored JSON shape so the resident owns every coercion.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBulkEligibilityItemV1 {
    #[serde(default)]
    pub policy_action: Option<Value>,
    #[serde(default)]
    pub status: Option<Value>,
    #[serde(default)]
    pub artifact_name: Option<Value>,
    #[serde(default)]
    pub artifact_type: Option<Value>,
    #[serde(default)]
    pub risk_headline: Option<Value>,
    #[serde(default)]
    pub risk_summary: Option<Value>,
    #[serde(default)]
    pub trigger_summary: Option<Value>,
    #[serde(default)]
    pub launch_summary: Option<Value>,
    #[serde(default)]
    pub why_now: Option<Value>,
    #[serde(default)]
    pub launch_target: Option<Value>,
    #[serde(default)]
    pub raw_command_text: Option<Value>,
    #[serde(default)]
    pub risk_signals: Option<Value>,
    #[serde(default)]
    pub action_envelope_json: Option<Value>,
    #[serde(default)]
    pub decision_v2_json: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBulkEligibilityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The caller's home directory, used to expand `~` in workspace and
    /// target paths exactly as the caller's own environment would.
    #[serde(default)]
    pub home_dir: Option<String>,
    pub items: Vec<ApprovalBulkEligibilityItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBulkEligibilityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_bulk_eligibility_*` failure codes.
    pub code: String,
    /// `{"items": [{"eligible": bool}]}` in request order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
