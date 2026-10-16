//! `PolicyBundleAuthority` — wire contract for the resident op that owns signed
//! Guard Cloud policy-bundle authority: schema validation, canonical hashing,
//! RSA-PSS signature verification, trusted-key resolution, monotonic replay
//! defense, delivery/acknowledgement correlation and rule materialization.
//!
//! One request carries a `kind` plus a JSON `input`. Large untrusted documents
//! (the bundle itself) travel as JSON text chunks so the resident can enforce
//! the policy-bundle resource limits on the decoded document rather than on the
//! transport framing. Rust owns every verdict; callers relay the `result`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA: &str = "guard-policy-bundle-authority-request.v1";
/// Schema discriminator for the result.
pub const POLICY_BUNDLE_AUTHORITY_RESULT_SCHEMA: &str = "guard-policy-bundle-authority-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const POLICY_BUNDLE_AUTHORITY_FEATURE: &str = "policy-bundle-authority-v1";
/// Largest request the op accepts.
pub const POLICY_BUNDLE_AUTHORITY_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleAuthorityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// Operation selector, for example `validate_v1` or `build_decisions`.
    pub kind: String,
    /// Kind-specific input document.
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleAuthorityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or a `native_policy_bundle_authority_*` failure code.
    pub code: String,
    /// Kind-specific verdict document; `null` when `status` is `error`.
    #[serde(default)]
    pub result: Value,
}
