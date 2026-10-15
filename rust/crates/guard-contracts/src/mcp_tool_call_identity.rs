//! `McpToolCallIdentity` - wire contract for the resident op that builds the
//! tool-call artifact and its approval hash for one non-package MCP call.
//!
//! The op is pure (no IO, no SQLite). The caller supplies the static session
//! facts and the dynamic call facts as raw data; the resident composes the
//! artifact identity and metadata (server and tool identity, authority hash,
//! firewall evidence) and the approval digest or context token that binds it.
//! Python never builds identity metadata or hashes locally.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const MCP_TOOL_CALL_IDENTITY_REQUEST_SCHEMA: &str = "guard-mcp-tool-call-identity-request.v1";
/// Schema discriminator for the result.
pub const MCP_TOOL_CALL_IDENTITY_RESULT_SCHEMA: &str = "guard-mcp-tool-call-identity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const MCP_TOOL_CALL_IDENTITY_FEATURE: &str = "mcp-tool-call-identity-v1";
/// Largest canonical request serialization the op will accept. It stays below
/// `MAX_NATIVE_REQUEST_BYTES` so the resident envelope around an accepted
/// request still fits one transport frame.
pub const MCP_TOOL_CALL_IDENTITY_MAX_BYTES: usize = 4 * 1024 * 1024;

fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// The session's stable local MCP server identity fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallServerIdentityV1 {
    pub config_path: String,
    pub command: String,
    pub args_hash: String,
    #[serde(deserialize_with = "required")]
    pub package_name: Option<String>,
    #[serde(deserialize_with = "required")]
    pub package_version: Option<String>,
    pub package_source: String,
    pub transport: String,
    pub env_keys: Vec<String>,
    pub env_values_hash: String,
    pub identity_hash: String,
}

/// Where the tool schema, description and authority binding come from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpToolCallSourceV1 {
    /// The proxy's discovered catalog. `entry` is the raw catalog entry (name
    /// included) or `null` when the tool is not in the catalog. The artifact
    /// metadata carries a null authority hash (the name-matched hash stays out
    /// of the exact saved-block hash) and the full-definition authority hash
    /// goes to `runtime_private_metadata`.
    Catalog {
        #[serde(deserialize_with = "required")]
        entry: Option<Map<String, Value>>,
    },
    /// Caller-supplied schema and description; no authority binding.
    Explicit {
        #[serde(deserialize_with = "required")]
        schema: Option<Value>,
        #[serde(deserialize_with = "required")]
        description: Option<String>,
    },
}

/// Facts needed to build a tool-call artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallBuildV1 {
    pub harness: String,
    pub server_name: String,
    pub tool_name: String,
    pub source_scope: String,
    pub config_path: String,
    pub transport: String,
    #[serde(deserialize_with = "required")]
    pub server_id: Option<String>,
    #[serde(deserialize_with = "required")]
    pub server_fingerprint: Option<Value>,
    #[serde(deserialize_with = "required")]
    pub server_identity: Option<McpToolCallServerIdentityV1>,
    #[serde(deserialize_with = "required")]
    pub provider_catalog_hash: Option<String>,
    pub tool: McpToolCallSourceV1,
}

/// A built tool-call artifact (the fields the approval hash binds).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallArtifactV1 {
    pub artifact_id: String,
    pub name: String,
    pub harness: String,
    pub source_scope: String,
    pub config_path: String,
    #[serde(deserialize_with = "required")]
    pub command: Option<String>,
    #[serde(deserialize_with = "required")]
    pub transport: Option<String>,
    #[serde(deserialize_with = "required")]
    pub publisher: Option<String>,
    pub metadata: Map<String, Value>,
}

/// Inputs of the approval digest row or context token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallHashInputV1 {
    /// The call arguments, as received.
    pub arguments: Value,
    /// Present: build the approval-context token. Absent: the digest row.
    #[serde(deserialize_with = "required")]
    pub config: Option<Map<String, Value>>,
    #[serde(deserialize_with = "required")]
    pub workspace: Option<String>,
    /// Required with `config`.
    #[serde(deserialize_with = "required")]
    pub extension_control_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallIdentityRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Build the artifact from session and call facts...
    #[serde(deserialize_with = "required")]
    pub build: Option<McpToolCallBuildV1>,
    /// ...or hash an artifact built earlier. Exactly one of `build` and
    /// `artifact` is present.
    #[serde(deserialize_with = "required")]
    pub artifact: Option<McpToolCallArtifactV1>,
    /// Absent: only build the artifact (no approval hash).
    #[serde(deserialize_with = "required")]
    pub hash: Option<McpToolCallHashInputV1>,
}

/// `ok` payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallIdentityPayloadV1 {
    pub artifact: McpToolCallArtifactV1,
    /// Local-grant bindings that stay out of the hashed artifact metadata.
    pub runtime_private_metadata: Map<String, Value>,
    /// The approval-context token (config present) or the digest row; absent
    /// when the request carried no hash input.
    pub artifact_hash: Option<String>,
    pub risk_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolCallIdentityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_mcp_tool_call_identity_*` failure code.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
