//! Contributed MCP decision contract.
//!
//! The resident decides whether a catalog MCP contribution tightens (block or
//! review) or relaxes (allow) a live `tools/call`. Callers supply only
//! non-authoritative material: the MCP server identity fields recorded in
//! artifact metadata, the tool name, and the extension-control layers the
//! caller verified. The bundled contributions, tool states, launcher and
//! endpoint matching, and the allow binding are all decided natively.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const CONTRIBUTED_MCP_DECISION_REQUEST_SCHEMA: &str =
    "guard-contributed-mcp-decision-request.v1";
/// Schema discriminator for the result.
pub const CONTRIBUTED_MCP_DECISION_RESULT_SCHEMA: &str = "guard-contributed-mcp-decision-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONTRIBUTED_MCP_DECISION_FEATURE: &str = "contributed-mcp-decision-v1";

/// One extension-kind control inside a layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContributedMcpControlV1 {
    pub target_id: String,
    /// `enabled` or `disabled`.
    pub state: String,
}

/// One verified extension-control layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContributedMcpLayerV1 {
    /// `local-admin` or `signed-cloud`.
    pub kind: String,
    pub global_lockdown: bool,
    pub controls: Vec<ContributedMcpControlV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContributedMcpDecisionRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Absolute path of `guard.db`; must sit directly under `guard_home`.
    pub store_path: String,
    /// Absolute path of the guard home that owns the store.
    pub guard_home: String,
    /// Action the contribution would refine.
    pub current_action: String,
    /// `package_name`, `command`, `transport`, `package_source`,
    /// `package_version` and `env_keys` as recorded in artifact metadata.
    /// Values stay raw JSON so type checks match the recorded metadata.
    #[serde(default)]
    pub server_identity: Option<Map<String, Value>>,
    /// Transport of the artifact itself, used when the identity has none.
    #[serde(default)]
    pub artifact_transport: Option<Value>,
    /// `server_name` from artifact metadata.
    #[serde(default)]
    pub server_name: Option<Value>,
    /// `mcp_tool_identity.tool_name` from artifact metadata.
    #[serde(default)]
    pub tool_name: Option<Value>,
    pub layers: Vec<ContributedMcpLayerV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContributedMcpDecisionResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_contributed_mcp_*` failure code.
    pub code: String,
    /// `{state, action, source, reason}` on success. `state` is `decided` or
    /// `none`; the other fields are null for `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
