//! `ComposioRole` — wire contract for the resident Composio routing op.
//!
//! The op is pure (no IO, no SQLite): the request carries one MCP tool name,
//! and the result carries the routing role the native Composio contract reads
//! from it. Roles describe routing, never authority.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the request.
pub const COMPOSIO_ROLE_REQUEST_SCHEMA: &str = "guard-composio-role-request.v1";
/// Schema discriminator for the result.
pub const COMPOSIO_ROLE_RESULT_SCHEMA: &str = "guard-composio-role-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMPOSIO_ROLE_FEATURE: &str = "composio-role-v1";

/// Largest canonical request serialization the op will accept.
pub const COMPOSIO_ROLE_MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComposioRoleRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// The MCP tool name to route, wrapper prefix included.
    pub tool_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComposioRoleResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_composio_role_*` failure codes.
    pub code: String,
    /// `discovery`, `batch`, `workbench`, `connections` or `unknown`; absent
    /// for a tool the Composio contract does not route at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Whether a call to this tool is reviewed as a provider action.
    pub requires_action_review: bool,
}
