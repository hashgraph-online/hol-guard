//! Request/result contract for the `ToolActionRequestIdentity` resident op.
//!
//! The resident owns the artifact id a sensitive tool-action review is stored
//! under. Python sends the request's identity material and receives the id
//! back, bound to the request by `request_id` plus the canonical
//! `request_sha256`. Python never derives the id itself: a second derivation
//! would re-key approvals the user has already granted.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const TOOL_ACTION_REQUEST_IDENTITY_FEATURE: &str = "tool-action-request-identity-v1";
pub const TOOL_ACTION_REQUEST_IDENTITY_REQUEST_SCHEMA: &str =
    "guard-tool-action-request-identity-request.v1";
pub const TOOL_ACTION_REQUEST_IDENTITY_RESULT_SCHEMA: &str =
    "guard-tool-action-request-identity-result.v1";
/// Largest request the op accepts; longer input fails closed.
pub const TOOL_ACTION_REQUEST_IDENTITY_MAX_REQUEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolActionRequestIdentityRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub harness: String,
    pub source_scope: String,
    /// `ToolActionRequestMatch.normalized_tool_name`, which the fingerprint
    /// payload spells `tool_name`.
    pub normalized_tool_name: String,
    pub command_text: String,
    pub action_class: String,
    pub shell_execution_context_hash: Option<String>,
    /// Already JSON objects on the Python side, so they cross unchanged.
    #[serde(default)]
    pub interpreter_executable_identities: Vec<Value>,
    pub script_read_identity_sha256: Option<String>,
    pub restricted_profile_version: Option<String>,
    pub pytest_config_identity_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ToolActionRequestIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// Hex SHA-256 of the canonical request serialization.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    pub code: String,
    /// `GuardArtifact.artifact_id`; present only when `ok`.
    pub artifact_id: Option<String>,
}
