//! `ApprovalResolutionPlan` - wire contract for the resident op that decides
//! what resolving one approval request writes.
//!
//! The op is pure (no IO, no SQLite). The caller ships the narrowed approval
//! request fields and the resolution inputs; the resident returns the policy
//! decision identity, how that decision is persisted, the local-once fallback
//! row, and the selector for sibling requests resolved with it. The caller only
//! executes the plan against the store.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const APPROVAL_RESOLUTION_PLAN_REQUEST_SCHEMA: &str =
    "guard-approval-resolution-plan-request.v1";
/// Schema discriminator for the result.
pub const APPROVAL_RESOLUTION_PLAN_RESULT_SCHEMA: &str = "guard-approval-resolution-plan-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const APPROVAL_RESOLUTION_PLAN_FEATURE: &str = "approval-resolution-plan-v1";
/// Largest canonical request serialization the op will accept.
pub const APPROVAL_RESOLUTION_PLAN_MAX_BYTES: usize = 256 * 1024;

/// Action-envelope fields the plan reads. Present only when the stored
/// envelope is a JSON object; text fields are narrowed to string-or-null and
/// list items that are not strings are carried as `null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionPlanEnvelopeV1 {
    #[serde(default)]
    pub raw_command_text: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub wrapper_chain: Option<Vec<Option<String>>>,
    /// `raw_payload_redacted.permission_mode`.
    #[serde(default)]
    pub permission_mode: Option<String>,
    /// `raw_payload_redacted.permissionMode`.
    #[serde(default)]
    pub permission_mode_camel: Option<String>,
}

/// Browser-intent fields the plan reads. Present only when the stored browser
/// intent is a JSON object.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionPlanBrowserIntentV1 {
    #[serde(default)]
    pub intent: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub target_origin: Option<String>,
    #[serde(default)]
    pub target_path_prefix: Option<String>,
    #[serde(default)]
    pub profile_mode: Option<String>,
    #[serde(default)]
    pub mcp_server_identity_hash: Option<String>,
    #[serde(default)]
    pub mcp_tool_identity_hash: Option<String>,
    #[serde(default)]
    pub mcp_schema_hash: Option<String>,
    /// Present only when the stored flags were a list; every item stringified.
    #[serde(default)]
    pub sensitive_surface_flags: Option<Vec<String>>,
}

/// The stored approval request, narrowed to the fields the plan reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionPlanApprovalV1 {
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub artifact_id: Option<String>,
    #[serde(default)]
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub artifact_type: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    /// Already expanded to the caller's absolute spelling.
    #[serde(default)]
    pub config_path: Option<String>,
    #[serde(default)]
    pub source_scope: Option<String>,
    #[serde(default)]
    pub raw_command_text: Option<String>,
    #[serde(default)]
    pub wrapper_chain: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub envelope: Option<ApprovalResolutionPlanEnvelopeV1>,
    #[serde(default)]
    pub browser_intent: Option<ApprovalResolutionPlanBrowserIntentV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionPlanRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// `allow` or anything else (treated as a block).
    pub action: String,
    /// Applied scope after scope selection.
    pub scope: String,
    #[serde(default)]
    pub persist_policy: Option<bool>,
    pub temporary_mcp: bool,
    pub local_tool: bool,
    pub resolve_scope_matches: bool,
    pub requires_local_once: bool,
    #[serde(default)]
    pub resolved_workspace: Option<String>,
    /// Stable exact-action token of a native review row, when it has one.
    #[serde(default)]
    pub native_exact_token: Option<String>,
    pub resolved_at: String,
    pub approval: ApprovalResolutionPlanApprovalV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolutionPlanResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_approval_resolution_plan_*` failure codes.
    pub code: String,
    /// The plan: `decision`, `persistence`, `once_expires_at`, `local_once`,
    /// `matching` and `exact_context_allow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
