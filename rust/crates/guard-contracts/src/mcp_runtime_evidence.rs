//! `McpRuntimeEvidence` — wire contract for the resident op that produces the
//! authoritative MCP tool-call receipt evidence: the `runtimeAction` record
//! (`build_runtime_action_record`) and the human-readable command text
//! (`extract_mcp_command_text`).
//!
//! The op is pure (no IO, no SQLite). Python ships artifact/argument/envelope
//! DTOs and renders the result; it never recomputes either value. A resident
//! that cannot answer is an unavailable authority, never an empty record.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const MCP_RUNTIME_EVIDENCE_REQUEST_SCHEMA: &str = "guard-mcp-runtime-evidence-request.v1";
/// Schema discriminator for the result.
pub const MCP_RUNTIME_EVIDENCE_RESULT_SCHEMA: &str = "guard-mcp-runtime-evidence-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const MCP_RUNTIME_EVIDENCE_FEATURE: &str = "mcp-runtime-evidence-v1";

/// Argument keys whose string values `command_text` reads, in priority order.
/// Mirrored by `_COMMAND_ARGUMENT_KEYS` in the Python transport; a test keeps
/// the two in lockstep.
pub const MCP_RUNTIME_EVIDENCE_COMMAND_ARGUMENT_KEYS: &[&str] = &[
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "script",
    "expression",
    "code",
    "query",
];
/// Argument keys `command_text` falls back to for a `"<tool> <path>"` string.
pub const MCP_RUNTIME_EVIDENCE_PATH_ARGUMENT_KEYS: &[&str] = &[
    "path",
    "file_path",
    "filePath",
    "filepath",
    "directory",
    "dir",
    "cwd",
    "working_dir",
    "workingDir",
    "url",
    "uri",
];
/// Lowercased key substrings whose values `runtime_action` records as touched files.
pub const MCP_RUNTIME_EVIDENCE_PATH_TOKENS: &[&str] = &["path", "file", "target", "source"];

/// Largest canonical request serialization the op will accept.
pub const MCP_RUNTIME_EVIDENCE_MAX_BYTES: usize = 256 * 1024;

/// `Option` field that must be present (possibly `null`) on the wire.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Every field is required (no serde defaults) so the canonical request digest
/// Python binds results to is exactly the request Rust parsed.
///
/// Redacted view of the harness action envelope fields that contribute to
/// runtime-action evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpRuntimeEnvelopeV1 {
    pub target_paths: Vec<String>,
    pub network_hosts: Vec<String>,
    #[serde(deserialize_with = "required")]
    pub package_manager: Option<String>,
    #[serde(deserialize_with = "required")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpRuntimeEvidenceRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    pub request_id: String,
    /// `runtime_action`, `command_text`, or `receipt_evidence` (both in one reply:
    /// `command_text` from `arguments`, `runtime_action` from description,
    /// risk categories, and envelope only).
    pub subop: String,
    /// Resolved guard home the request is scoped to.
    pub guard_home: String,
    /// `GuardArtifact.name` (`server:tool`).
    pub artifact_name: String,
    /// `artifact.metadata["tool_description"]` when it is a string.
    #[serde(deserialize_with = "required")]
    pub tool_description: Option<String>,
    /// Call arguments as ordered `[key, value]` entries (keys stringified,
    /// non-string values `null`). `None` means the arguments are not a mapping.
    #[serde(deserialize_with = "required")]
    pub arguments: Option<Vec<(String, Option<String>)>>,
    /// Native risk categories observed for the call, in order.
    pub risk_categories: Vec<String>,
    #[serde(deserialize_with = "required")]
    pub envelope: Option<McpRuntimeEnvelopeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpRuntimeEvidenceResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_mcp_runtime_evidence_*` failure codes.
    pub code: String,
    /// `{"runtime_action": ..}`, `{"command_text": ..}`, or both keys for `receipt_evidence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
