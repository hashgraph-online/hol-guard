//! `HookArtifactFacts` - wire contract for the resident op that derives the
//! per-artifact facts the native configured-policy action reads.
//!
//! The facts themselves are `PolicyArtifactFactsV1`, the struct the compose
//! op already takes. This op exists so the caller stops deriving them: it
//! ships the artifact as it stands and the resident reads the metadata.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA: &str = "guard-hook-artifact-facts-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ARTIFACT_FACTS_RESULT_SCHEMA: &str = "guard-hook-artifact-facts-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ARTIFACT_FACTS_FEATURE: &str = "hook-artifact-facts-v1";
/// Largest canonical request serialization the op will accept.
pub const HOOK_ARTIFACT_FACTS_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most artifacts one request may carry. A hook asks about two; a request
/// above this is refused so the caller asks again with what it holds.
pub const HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS: usize = 64;

/// One artifact the caller asks about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactV1 {
    /// `GuardArtifact.artifact_type`.
    pub artifact_type: String,
    /// `GuardArtifact.metadata`, unchanged.
    #[serde(default)]
    pub metadata: Value,
    /// The artifact, publisher or harness override the config resolved, which
    /// is a settings lookup rather than a reading of the artifact.
    #[serde(default)]
    pub configured_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactFactsRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The artifacts of one evaluation, in the caller's order. A hook reads
    /// facts for its runtime artifact and its approval-context artifact, and
    /// asking for both in one request keeps the evaluation to one round trip
    /// rather than one per artifact.
    pub artifacts: Vec<HookArtifactV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookArtifactFactsResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_hook_artifact_facts_*` codes.
    pub code: String,
    /// `{"facts": [...]}`: one `PolicyArtifactFactsV1` per requested
    /// artifact, in the order the request listed them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
