//! `HookArtifactFacts` - wire contract for the resident op that derives the
//! per-artifact facts the native configured-policy action reads.
//!
//! The facts themselves are `PolicyArtifactFactsV1`, the struct the compose
//! op already takes. This op exists so the caller stops deriving them: it
//! ships the artifact as it stands and the resident reads the metadata.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const HOOK_ARTIFACT_FACTS_REQUEST_SCHEMA: &str = "guard-hook-artifact-facts-request.v1";
/// Schema discriminator for the result.
pub const HOOK_ARTIFACT_FACTS_RESULT_SCHEMA: &str = "guard-hook-artifact-facts-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_ARTIFACT_FACTS_FEATURE: &str = "hook-artifact-facts-v1";
/// Capability advertised when the op also answers `content_sha256`, the digest
/// a saved approval is keyed by. A caller that needs the digest asks under
/// this feature, so a runtime that would silently omit it is unavailable
/// instead; callers that only need the policy facts are unaffected.
pub const HOOK_ARTIFACT_FACTS_CONTENT_HASH_FEATURE: &str = "hook-artifact-facts-content-hash-v1";
/// Largest canonical request serialization the op will accept.
pub const HOOK_ARTIFACT_FACTS_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most artifacts one request may carry. A hook asks about two; a request
/// above this is refused so the caller asks again with what it holds.
pub const HOOK_ARTIFACT_FACTS_MAX_ARTIFACTS: usize = 64;

/// One artifact the caller asks about.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
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
    /// `GuardArtifact.artifact_id`.
    #[serde(default)]
    pub artifact_id: String,
    /// `GuardArtifact.name`.
    #[serde(default)]
    pub name: String,
    /// `GuardArtifact.harness`, the artifact's own harness rather than the
    /// canonical policy harness the caller resolved.
    #[serde(default)]
    pub harness: String,
    /// `GuardArtifact.source_scope`.
    #[serde(default)]
    pub source_scope: String,
    /// `GuardArtifact.config_path`.
    #[serde(default)]
    pub config_path: String,
    /// `GuardArtifact.command`.
    #[serde(default)]
    pub command: Option<String>,
    /// `GuardArtifact.args`, unredacted; the hash redacts them itself.
    #[serde(default)]
    pub args: Vec<String>,
    /// `GuardArtifact.url`, unredacted; the hash redacts it itself.
    #[serde(default)]
    pub url: Option<String>,
    /// `GuardArtifact.transport`.
    #[serde(default)]
    pub transport: Option<String>,
    /// `GuardArtifact.publisher`.
    #[serde(default)]
    pub publisher: Option<String>,
    /// Present when the caller asks for `content_sha256`: what the caller
    /// stamped onto `metadata` after the artifact's approval identity was
    /// fixed.
    ///
    /// A hook fixes that identity before it stamps its runtime posture onto
    /// the same metadata, so the digest a saved approval is keyed by covers
    /// the artifact as it stood *before* the stamp, while the facts above are
    /// read from the stamped metadata. Naming the stamp rather than carrying
    /// a second full copy of the metadata keeps one round trip answering both
    /// questions without the resident guessing which keys the caller added,
    /// and keeps a large metadata from doubling the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_stamp: Option<MetadataStampV1>,
}

/// What a caller added to an artifact's metadata after its identity was fixed.
///
/// Removing `added` from the stamped metadata and putting `replaced` back
/// recovers the metadata the identity was taken over. An empty stamp says the
/// caller stamped nothing, so the identity is the metadata as sent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetadataStampV1 {
    /// Keys the stamp introduced, absent from the metadata the digest covers.
    #[serde(default)]
    pub added: Vec<String>,
    /// Keys the stamp overwrote, holding the value the identity carried.
    #[serde(default)]
    pub replaced: Map<String, Value>,
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
