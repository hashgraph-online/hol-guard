//! `McpToolEvidence` — wire contract for the resident op that owns MCP
//! tool-call risk presentation and the portal firewall projection.
//!
//! Two subops, both pure (no IO, no SQLite):
//!
//! * `risk` extracts the Cloud risk categories for a call (or accepts the
//!   categories a prior policy verdict already produced), then renders the
//!   per-category signal strings and the human summary. Browser scope,
//!   argument and schema checks, and target redaction all run natively.
//! * `firewall` projects an `mcp_server` or `tool_call` artifact into the
//!   portal `mcpSkillFirewall` evidence plus the legacy identity metadata
//!   keys that go with it.
//!
//! Python ships artifact/argument DTOs and renders the result; it never
//! recomputes a signal, summary, or fingerprint. Every field is required on
//! the wire so the canonical request digest Python binds the reply to is
//! exactly the request Rust parsed.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::BrowserMcpArtifactV1;

/// Schema discriminator for the request.
pub const MCP_TOOL_EVIDENCE_REQUEST_SCHEMA: &str = "guard-mcp-tool-evidence-request.v1";
/// Schema discriminator for the result.
pub const MCP_TOOL_EVIDENCE_RESULT_SCHEMA: &str = "guard-mcp-tool-evidence-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const MCP_TOOL_EVIDENCE_FEATURE: &str = "mcp-tool-evidence-v1";
/// Largest canonical request serialization the op will accept.
pub const MCP_TOOL_EVIDENCE_MAX_BYTES: usize = 2 * 1024 * 1024;

/// `Option` field that must be present (possibly `null`) on the wire.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Call arguments in the shape Python received them. A mapping keeps its
/// insertion order (Rust cannot recover it from a sorted JSON object); a
/// string is parsed by Rust; anything else is carried as a value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "format", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpToolArgumentsV1 {
    Mapping { entries: Vec<(String, Value)> },
    Json { text: String },
    Other { value: Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolRiskInputV1 {
    pub artifact: BrowserMcpArtifactV1,
    pub arguments: McpToolArgumentsV1,
    /// Categories a native policy verdict already produced. `null` asks the
    /// resident to extract them from the artifact and arguments.
    #[serde(deserialize_with = "required")]
    pub risk_categories: Option<Vec<String>>,
    /// `no_risk`, `risk`, or `configuration_stricter` from the native policy
    /// verdict. `null` renders the plain risk summary from the signals.
    #[serde(deserialize_with = "required")]
    pub summary_code: Option<String>,
}

/// Artifact fields the firewall projection reads. Metadata keys are lifted
/// into explicit fields so unrelated metadata never reaches the resident.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpFirewallInputV1 {
    /// `mcp_server` or `tool_call`.
    pub artifact_type: String,
    pub name: String,
    #[serde(deserialize_with = "required")]
    pub command: Option<String>,
    pub config_path: String,
    #[serde(deserialize_with = "required")]
    pub transport: Option<String>,
    /// Whether `artifact.url` is set. The URL itself is never shipped.
    pub has_url: bool,
    pub args: Vec<String>,
    #[serde(deserialize_with = "required")]
    pub publisher: Option<String>,
    /// `metadata["server_name"]` when present; `null` means absent.
    #[serde(deserialize_with = "required")]
    pub server_name: Option<String>,
    /// String-only `metadata["env"]` pairs.
    pub env: Vec<(String, String)>,
    #[serde(deserialize_with = "required")]
    pub mcp_server_identity: Option<Map<String, Value>>,
    #[serde(deserialize_with = "required")]
    pub mcp_tool_identity: Option<Map<String, Value>>,
    #[serde(deserialize_with = "required")]
    pub tool_schema: Option<Value>,
    #[serde(deserialize_with = "required")]
    pub tool_description: Option<Value>,
    #[serde(deserialize_with = "required")]
    pub tool_names: Option<Value>,
    #[serde(deserialize_with = "required")]
    pub tool_names_camel: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolEvidenceRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    pub request_id: String,
    /// `risk` or `firewall`.
    pub subop: String,
    /// Resolved guard home the request is scoped to.
    pub guard_home: String,
    #[serde(deserialize_with = "required")]
    pub risk: Option<McpToolRiskInputV1>,
    #[serde(deserialize_with = "required")]
    pub firewall: Option<McpFirewallInputV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolEvidenceResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_mcp_tool_evidence_*` failure codes.
    pub code: String,
    /// `risk`: `{risk_categories, signals, summary}`. `firewall`:
    /// `{metadata_patch}` where `null` leaves the artifact unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
