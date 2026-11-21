//! `ApprovalResolutionEligibility` - wire contract for the resident op that
//! answers whether stored approval rows can accept a user resolution.
//!
//! The rule is the same one the scope sweep applies to the rows it selects:
//! a row whose decision contract could not be read, or whose stored policy
//! action is not a lattice action, is inconsistent, and a terminal action is
//! not something a prompt can lift. Callers resolve rows inside a write
//! transaction, so the op takes the whole batch at once and answers in order
//! rather than making one round trip per row.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_RESOLUTION_ELIGIBILITY_REQUEST_SCHEMA: &str =
    "guard-approval-resolution-eligibility-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_RESOLUTION_ELIGIBILITY_RESULT_SCHEMA: &str =
    "guard-approval-resolution-eligibility-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_RESOLUTION_ELIGIBILITY_FEATURE: &str = "approval-resolution-eligibility-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_RESOLUTION_ELIGIBILITY_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Rows one request may ask about. A sweep that selects more asks again.
pub const APPROVAL_RESOLUTION_ELIGIBILITY_MAX_ITEMS: usize = 1024;

/// One stored row, narrowed to the two surfaces the rule reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionItemV1 {
    /// The row's stored policy action, exactly as it was read.
    #[serde(default)]
    pub policy_action: Value,
    /// The contract error the row's projection carried, or null.
    #[serde(default)]
    pub decision_contract_error: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionEligibilityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The rows to answer for, in the caller's order.
    pub items: Vec<ApprovalResolutionItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionEligibilityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_resolution_eligibility_*` codes.
    pub code: String,
    /// `{"reasons": [null | "<code>", ...]}`, one entry per item in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
