//! `RuntimeDetectorRun` — wire contract for the resident op that runs the
//! default runtime detectors (secret paths, data-flow exfiltration, prompt
//! injection, skill content, supply chain, safe decode, false-positive hints,
//! persistence, Guard bypass and MCP tool risk) for one runtime action.
//!
//! The op is pure (no IO, no SQLite). Python ships the action fields and the
//! registry options and renders the per-detector entries; it never runs these
//! detectors itself. The scanner-backed Cisco preflight detectors are not part
//! of this op. A resident that cannot answer fails the run closed.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const RUNTIME_DETECTOR_RUN_REQUEST_SCHEMA: &str = "guard-runtime-detector-run-request.v1";
/// Schema discriminator for the result.
pub const RUNTIME_DETECTOR_RUN_RESULT_SCHEMA: &str = "guard-runtime-detector-run-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const RUNTIME_DETECTOR_RUN_FEATURE: &str = "runtime-detector-run-v1";

/// Largest canonical request serialization the op will accept.
pub const RUNTIME_DETECTOR_RUN_MAX_BYTES: usize = 4 * 1024 * 1024;

/// `Option` field that must be present (possibly `null`) on the wire.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// The `GuardActionEnvelope` fields the detectors read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDetectorActionV1 {
    pub action_type: String,
    #[serde(deserialize_with = "required")]
    pub command: Option<String>,
    #[serde(deserialize_with = "required")]
    pub prompt_text: Option<String>,
    #[serde(deserialize_with = "required")]
    pub prompt_excerpt: Option<String>,
    #[serde(deserialize_with = "required")]
    pub mcp_tool: Option<String>,
    /// In order.
    pub target_paths: Vec<String>,
}

/// Every field is required (no serde defaults) so the canonical request digest
/// Python binds results to is exactly the request Rust parsed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDetectorRunRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    pub request_id: String,
    /// Resolved guard home the request is scoped to.
    pub guard_home: String,
    /// Workspace the action runs in, used to resolve relative paths.
    #[serde(deserialize_with = "required")]
    pub workspace: Option<String>,
    pub action: RuntimeDetectorActionV1,
    /// A detector slower than this is reported as `timeout` (its signals are
    /// still kept).
    pub timeout_ms: u64,
    /// Detector ids to skip; unknown ids are ignored.
    pub disabled_detector_ids: Vec<String>,
    /// When present, detectors with no category in this list are skipped and
    /// signals outside it are dropped.
    #[serde(deserialize_with = "required")]
    pub enabled_categories: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDetectorRunResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_runtime_detector_run_*` failure codes.
    pub code: String,
    /// `{"detectors": [{detector_id, categories, status, elapsed_ms,
    /// error_type, signals}]}` sorted by detector id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
