//! Local MCP grant decision contract.
//!
//! The resident reads grant rows from `guard.db` and decides whether a live
//! `tools/call` is covered by a this-device allow, block, or review. Callers
//! supply only non-authoritative material: the MCP server identity fields
//! recorded in artifact metadata, the tool name, the tool authority digest,
//! and the connection identity digest. Grant state, the command catalog,
//! per-tool states, catalog authority, observation lookup, and the package
//! launcher equivalence are all read and decided natively.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const LOCAL_MCP_GRANT_REQUEST_SCHEMA: &str = "guard-local-mcp-grant-request.v1";
/// Schema discriminator for the result.
pub const LOCAL_MCP_GRANT_RESULT_SCHEMA: &str = "guard-local-mcp-grant-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const LOCAL_MCP_GRANT_FEATURE: &str = "local-mcp-grant-v1";

/// MCP server identity fields as recorded in artifact metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalMcpServerMaterialV1 {
    /// `identity_hash` as recorded; an absent or malformed value selects the
    /// observed-connector identity derived from `harness` and `tool_name`.
    #[serde(default)]
    pub identity_hash: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args_hash: Option<String>,
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub package_version: Option<String>,
    #[serde(default)]
    pub package_source: Option<String>,
    #[serde(default)]
    pub env_values_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalMcpGrantRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute path of `guard.db`; must sit directly under `guard_home`.
    pub store_path: String,
    /// Absolute path of the guard home that owns the store.
    pub guard_home: String,
    /// Action the grant would refine. Only `allow`, `review`,
    /// `require-reapproval` and `warn` can be refined.
    pub current_action: String,
    /// Harness the call came from; names the observed connector identity.
    pub harness: String,
    /// Tool name of the live call.
    pub tool_name: String,
    pub server: LocalMcpServerMaterialV1,
    /// Digest of the configured host connection. Non-authoritative: it only
    /// selects a stored observation and is ignored for observed connectors.
    #[serde(default)]
    pub connection_identity_hash: Option<String>,
    /// Live tool authority digest compared with the stored catalog digest.
    #[serde(default)]
    pub tool_authority_hash: Option<String>,
    /// `PATH` of the calling process, used only to resolve package launchers.
    #[serde(default)]
    pub launcher_path: Option<String>,
    /// Home directory of the calling process, used to expand `~` launchers.
    #[serde(default)]
    pub launcher_home: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalMcpGrantResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_local_mcp_grant_*` failure code.
    pub code: String,
    /// `{state, cli_id, identity_hash}` on success. `state` is `allowed`,
    /// `blocked`, `review`, or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
