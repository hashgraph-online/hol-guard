//! `FalsePositiveRules` — wire contract for the resident op that owns the
//! advisory false-positive signals for a runtime action (read-only source
//! searches, localhost health checks, read-only HTTP probes, version-pin,
//! manifest and docs/example file reads).
//!
//! The op is pure (no IO, no SQLite). Python ships the action type, command
//! and target paths and renders the returned signals; it never classifies a
//! command or path itself. A resident that cannot answer yields no
//! false-positive signal, the conservative outcome for every caller.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const FALSE_POSITIVE_RULES_REQUEST_SCHEMA: &str = "guard-false-positive-rules-request.v1";
/// Schema discriminator for the result.
pub const FALSE_POSITIVE_RULES_RESULT_SCHEMA: &str = "guard-false-positive-rules-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const FALSE_POSITIVE_RULES_FEATURE: &str = "false-positive-rules-v1";

/// Largest canonical request serialization the op will accept.
pub const FALSE_POSITIVE_RULES_MAX_BYTES: usize = 256 * 1024;

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FalsePositiveRulesRequestV1 {
    pub schema: String,
    /// Caller correlation id; echoed back in the result.
    pub request_id: String,
    /// Resolved guard home the request is scoped to.
    pub guard_home: String,
    /// `GuardActionEnvelope.action_type`.
    pub action_type: String,
    /// `GuardActionEnvelope.command`.
    #[serde(deserialize_with = "required")]
    pub command: Option<String>,
    /// `GuardActionEnvelope.target_paths`, in order.
    pub target_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FalsePositiveRulesResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_false_positive_rules_*` failure codes.
    pub code: String,
    /// `{"signals": [RiskSignalV2 dicts]}` in emission order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
