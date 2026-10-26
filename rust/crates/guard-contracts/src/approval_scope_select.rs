//! `ApprovalScopeSelect` - wire contract for the resident op that answers one
//! approval resolution: may this action be recorded at the scope the client
//! chose, must it be narrowed, or is it refused.
//!
//! `ApprovalScope` publishes which scopes a request offers. This op decides
//! what a specific `allow` or `block` at a specific scope actually resolves
//! to, so the honouring, narrowing and refusal of a user's choice has one
//! owner. The op is pure: the caller ships the same narrowed request fields
//! `ApprovalScope` takes plus the contract version and digest the client
//! echoed back, and the resident derives the contract itself rather than
//! trusting a contract the caller claims to hold.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ApprovalScopeItemV1;

/// Schema discriminator for the request.
pub const APPROVAL_SCOPE_SELECT_REQUEST_SCHEMA: &str = "guard-approval-scope-select-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_SCOPE_SELECT_RESULT_SCHEMA: &str = "guard-approval-scope-select-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_SCOPE_SELECT_FEATURE: &str = "approval-scope-select-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_SCOPE_SELECT_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScopeSelectRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The request being resolved, narrowed exactly as `ApprovalScope` takes it.
    pub item: ApprovalScopeItemV1,
    /// `allow` or `block`. Anything else is refused rather than coerced.
    pub action: String,
    /// The scope the client asked for.
    pub requested_scope: String,
    /// The contract version the client echoed back, absent for a legacy client
    /// that never read one.
    #[serde(default)]
    pub contract_version: Option<String>,
    /// The contract digest the client echoed back. Present exactly when
    /// `contract_version` is.
    #[serde(default)]
    pub contract_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScopeSelectResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_scope_select_*` failure codes.
    pub code: String,
    /// `{"outcome": "selected" | "refused", ..., "contract": {...}}`. A
    /// refusal names the condition in `reason`; the contract rides along so
    /// the caller can report what the request actually offers without
    /// deriving it a second time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
