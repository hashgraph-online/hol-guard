//! `ApprovalScope` - wire contract for the resident op that derives the
//! action-aware approval scope contract of one or more pending requests.
//!
//! The op is pure (no IO, no SQLite). The caller ships the narrowed request
//! fields plus the workspace target it already resolved on its own filesystem;
//! the resident returns the scope contract, its digest and the exact-action
//! token bound to the request.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_SCOPE_REQUEST_SCHEMA: &str = "guard-approval-scope-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_SCOPE_RESULT_SCHEMA: &str = "guard-approval-scope-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_SCOPE_FEATURE: &str = "approval-scope-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_SCOPE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most requests one call may derive.
pub const APPROVAL_SCOPE_MAX_ITEMS: usize = 1024;

/// One approval request, narrowed to the fields its scope contract reads.
/// Values keep their stored JSON shape so the resident owns every coercion.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScopeItemV1 {
    #[serde(default)]
    pub artifact_id: Option<Value>,
    #[serde(default)]
    pub artifact_type: Option<Value>,
    #[serde(default)]
    pub artifact_hash: Option<Value>,
    #[serde(default)]
    pub artifact_name: Option<Value>,
    #[serde(default)]
    pub policy_action: Option<Value>,
    #[serde(default)]
    pub harness: Option<Value>,
    #[serde(default)]
    pub publisher: Option<Value>,
    #[serde(default)]
    pub source_scope: Option<Value>,
    #[serde(default)]
    pub config_path: Option<Value>,
    #[serde(default)]
    pub wrapper_chain: Option<Value>,
    #[serde(default)]
    pub action_identity: Option<Value>,
    #[serde(default)]
    pub raw_command_text: Option<Value>,
    #[serde(default)]
    pub action_envelope_json: Option<Value>,
    #[serde(default)]
    pub scanner_evidence: Option<Value>,
    /// The workspace the caller derived from the stored workspace or config
    /// path; resolving it needs the caller's filesystem.
    #[serde(default)]
    pub workspace_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScopeRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub items: Vec<ApprovalScopeItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalScopeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_scope_*` failure codes.
    pub code: String,
    /// `{"items": [{...scope contract..., "exact_context_token"}]}`, in
    /// request order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
