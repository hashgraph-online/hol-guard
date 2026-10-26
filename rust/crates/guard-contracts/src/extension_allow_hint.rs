//! Wire contract for the resident extension allow-hint op.
//!
//! A reviewed command that only an extension rule paused may be allowed by
//! enabling a configurable permission. The resident answers which permissions
//! would let the command run: it re-evaluates the command with hypothetical
//! enabled permissions and keeps only the ones the allow needs. The hint is
//! advisory and carries catalog identifiers only; enabling a permission still
//! goes through the proof-bound extension-control mutation.
//!
//! The request carries the same inputs a command evaluation does. The resident
//! evaluates them under its own admitted control snapshot, so a caller cannot
//! widen what a hint may name.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const EXTENSION_ALLOW_HINT_REQUEST_SCHEMA: &str = "guard-extension-allow-hint-request.v1";
/// Schema discriminator for the result.
pub const EXTENSION_ALLOW_HINT_RESULT_SCHEMA: &str = "guard-extension-allow-hint-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const EXTENSION_ALLOW_HINT_FEATURE: &str = "extension-allow-hint-v1";
/// The one query kind this operation answers, echoed by the payload.
pub const EXTENSION_ALLOW_HINT_QUERY_KIND: &str = "allow_hint";
/// Schema discriminator of the hint itself, as stored on a queued review.
pub const EXTENSION_ALLOW_HINT_SCHEMA: &str = "guard.extension-allow-hint.v1";

/// Largest canonical request serialization the op will accept.
pub const EXTENSION_ALLOW_HINT_MAX_BYTES: usize = 1024 * 1024;
/// Most permissions one hint may name.
pub const EXTENSION_ALLOW_HINT_MAX_PERMISSIONS: usize = 3;
/// Most already-enabled permissions a hint may report as relied on.
pub const EXTENSION_ALLOW_HINT_MAX_RELIED: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAllowHintQueryV1 {
    /// Always `allow_hint`.
    pub kind: String,
    /// Raw command text under review.
    pub command_text: String,
    /// Canonical command produced by the native command-model op.
    pub canonical_command: Value,
    /// Native command-safety extension evidence the review was decided on.
    pub native_extension_evidence: Value,
    /// Control snapshot binding the evidence is bound to.
    pub control_snapshot: Value,
    /// Current working directory used for workspace-relative proof checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Home directory used for the private-scope fence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    /// Time the optional reduction pass may run, counted from the moment the
    /// resident starts the request. Once it has passed, the already verified
    /// full permission set is answered as it is. Absent means unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduction_budget_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAllowHintRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    pub query: ExtensionAllowHintQueryV1,
}

/// The permissions whose Allow state would let the command run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAllowHintV1 {
    /// `EXTENSION_ALLOW_HINT_SCHEMA`.
    pub schema: String,
    /// Permissions to enable, in rule match order; at most
    /// `EXTENSION_ALLOW_HINT_MAX_PERMISSIONS`.
    pub permission_ids: Vec<String>,
    /// The first matched rule that named each permission, without repeats.
    pub rule_ids: Vec<String>,
    /// Owners of the named permissions, without repeats.
    pub extension_ids: Vec<String>,
    /// Permissions already enabled that the allow also depends on: it holds
    /// only while they stay enabled.
    pub relied_permission_ids: Vec<String>,
    /// Digest of the catalog the permissions are named in.
    pub catalog_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAllowHintPayloadV1 {
    /// Echo of the query kind.
    pub kind: String,
    /// The hint, or null when no permission change would let the command run.
    pub hint: Option<ExtensionAllowHintV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAllowHintResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_extension_allow_hint_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ExtensionAllowHintPayloadV1>,
}
