//! `ArtifactContentHash` - wire contract for the resident op that spells the
//! content hash a saved approval is keyed by.
//!
//! `GuardStore` keys saved decisions by this digest, so the value has to be
//! the one the retired Python helper computed for the same artifact: a
//! different spelling would silently invalidate every approval the user has
//! already granted. That is why the hash is spelled in one place. A caller
//! ships the artifact's own fields, unredacted, and the resident applies the
//! artifact's redaction before hashing.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const ARTIFACT_CONTENT_HASH_REQUEST_SCHEMA: &str = "guard-artifact-content-hash-request.v1";
/// Schema discriminator for the result.
pub const ARTIFACT_CONTENT_HASH_RESULT_SCHEMA: &str = "guard-artifact-content-hash-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const ARTIFACT_CONTENT_HASH_FEATURE: &str = "artifact-content-hash-v1";
/// Largest canonical request serialization the op will accept.
pub const ARTIFACT_CONTENT_HASH_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most artifacts one request may carry. A scan asks about every artifact a
/// harness defines, and a request above this is refused so the caller asks
/// again with the batch it holds rather than growing the request unbounded.
pub const ARTIFACT_CONTENT_HASH_MAX_ARTIFACTS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContentHashRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The artifacts' own fields, in the caller's order, each as the fields
    /// `GuardArtifact` carries. They travel raw: the resident applies the
    /// artifact's own redaction before hashing, and a copy redacted by the
    /// caller would hash differently and miss every saved approval.
    pub artifacts: Vec<Map<String, Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContentHashResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_artifact_content_hash_*` codes.
    pub code: String,
    /// `{"content_hashes": [...]}`: one hash per requested artifact, in the
    /// order the request listed them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
