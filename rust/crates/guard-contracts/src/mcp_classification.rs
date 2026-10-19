//! `McpClassify` - wire contract for the resident op that describes an MCP
//! tool's static evidence: what the declared schema and the provider's own
//! annotations suggest, never what the tool does.
//!
//! The op is pure (no store access) and advisory. A classification is display
//! evidence: it is not an authority, a verified destination or an account
//! binding, and no caller may read it as one.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const MCP_CLASSIFICATION_REQUEST_SCHEMA: &str = "guard-mcp-classification-request.v1";
/// Schema discriminator for the result.
pub const MCP_CLASSIFICATION_RESULT_SCHEMA: &str = "guard-mcp-classification-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const MCP_CLASSIFICATION_FEATURE: &str = "mcp-classification-v1";
/// Schema stamped on every classification the op returns.
pub const MCP_CLASSIFICATION_SCHEMA: &str = "guard.mcp-classification.v1";
/// Largest canonical request serialization the op will accept. It stays below
/// `MAX_NATIVE_REQUEST_BYTES` so the resident envelope around an accepted
/// request still fits one transport frame.
pub const MCP_CLASSIFICATION_MAX_BYTES: usize = 6 * 1024 * 1024 - 64 * 1024;
/// Most tools one call may describe.
pub const MCP_CLASSIFICATION_MAX_ITEMS: usize = 1024;

/// One tool definition to describe. `schema` and `annotations` keep their
/// provider-controlled JSON shape so the resident owns every coercion.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpClassificationItemV1 {
    pub name: String,
    #[serde(default)]
    pub schema: Option<Value>,
    /// The provider whose reviewed mapping may apply, when one is known.
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub annotations: Option<Value>,
    /// False when the caller holds only part of the declared schema.
    #[serde(default = "default_true")]
    pub full_schema: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpClassificationRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub items: Vec<McpClassificationItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpClassificationResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_mcp_classification_*` failure codes.
    pub code: String,
    /// `{"classifications": [...]}` in request order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
