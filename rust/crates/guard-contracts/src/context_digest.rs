//! Bounded native request-context digest contract.
//!
//! Approval-context tokens and configured environment/header digests are
//! authority-bearing artifacts: a saved approval is reusable only while these
//! digests are unchanged. Computing them is therefore native work — Python
//! callers send the raw components and receive the canonical token/digest
//! back through the resident protocol or `hol-guard-runtime context-digest
//! --stdin`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CONTEXT_DIGEST_REQUEST_SCHEMA: &str = "guard-context-digest-request.v1";
/// Schema discriminator for the result.
pub const CONTEXT_DIGEST_RESULT_SCHEMA: &str = "guard-context-digest-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONTEXT_DIGEST_FEATURE: &str = "context-digest-v1";

/// Opaque approval-context token prefix shared with the persisted contract.
pub const APPROVAL_CONTEXT_TOKEN_PREFIX: &str = "guard-approval-context:v1:";
/// Longest accepted token body.
pub const APPROVAL_CONTEXT_TOKEN_MAX_BYTES: usize = 2_048;
/// Largest canonical component serialization the digest op will hash.
pub const CONTEXT_COMPONENT_MAX_BYTES: usize = 1024 * 1024;

/// First-difference reasons for approval-context validation. These strings
/// are part of the persisted/presentation contract with the Python side.
pub const APPROVAL_CONTEXT_VALIDATION_REASONS: [&str; 5] = [
    "approval_reuse_identity_changed",
    "approval_reuse_content_changed",
    "approval_reuse_capability_changed",
    "approval_reuse_policy_changed",
    "approval_reuse_sandbox_changed",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextDigestComponentsV1 {
    pub identity: Value,
    pub content: Value,
    pub capabilities: Value,
    /// Raw policy component. The runtime wraps it with the caller-supplied
    /// extension-control digest before hashing, matching the historical
    /// construction exactly.
    pub policy: Value,
    pub sandbox: Value,
    /// Digest produced by the extension-control snapshot currently bound to
    /// the request. The caller still owns that snapshot's lifetime; the
    /// worker only binds its value into the policy component hash.
    pub extension_control_digest: String,
}

/// Sub-operation carried by a single context-digest request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextDigestKindV1 {
    /// Build the opaque approval-context token for a full component set.
    BuildApprovalContextToken {
        components: ContextDigestComponentsV1,
    },
    /// Compare two already-built tokens, returning the first changed
    /// dimension or none. Malformed input fails closed as changed content.
    ValidateApprovalContextTokens {
        saved_token: Value,
        current_token: Value,
    },
    /// Build the current token from components and compare it against a
    /// saved token in one round trip.
    ValidateApprovalContext {
        saved_token: Value,
        components: ContextDigestComponentsV1,
    },
    /// Domain-separated digest over a configured environment subset.
    ConfiguredEnvironmentHash {
        values: Option<Value>,
        configured_keys: Option<Vec<String>>,
    },
    /// Domain-separated digest over a configured header subset.
    ConfiguredHeadersHash {
        values: Option<Value>,
        configured_keys: Option<Vec<String>>,
    },
    /// Stable launch-identity digest over the raw argv list.
    LaunchArgvDigest { argv: Vec<String> },
}

// `deny_unknown_fields` cannot combine with `flatten` (serde rejects the
// variant fields outright); strictness is enforced per-variant on the kind
// enum instead.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextDigestRequestV1 {
    pub schema: String,
    pub request_id: String,
    #[serde(flatten)]
    pub kind: ContextDigestKindV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContextDigestResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_context_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_reason: Option<String>,
}
