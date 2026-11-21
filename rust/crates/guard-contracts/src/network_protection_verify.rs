//! Network protection bundle verification contract.
//!
//! The resident checks one signed network protection bundle response end to
//! end: the canonical payload hash, the contract version, that the bundle
//! belongs to this workspace, its rules and threat indicators, rollback
//! against the version the caller already holds, freshness, the keyring the
//! signing key must be anchored to, that key's rotation state, and the RSA-PSS
//! signature. The caller sends the response exactly as it fetched it and gets
//! back the form it saves; it never decides whether the bundle holds, and a
//! caller that cannot reach the resident saves nothing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const NETWORK_PROTECTION_VERIFY_REQUEST_SCHEMA: &str =
    "guard-network-protection-verify-request.v1";
/// Schema discriminator for the result.
pub const NETWORK_PROTECTION_VERIFY_RESULT_SCHEMA: &str =
    "guard-network-protection-verify-result.v1";
/// Capability advertised by the runtime when `network_protection_verify` is available.
pub const NETWORK_PROTECTION_VERIFY_FEATURE: &str = "network-protection-verify-v1";
/// Capability advertised when the request may carry the response as
/// `response_json` text instead of a JSON value.
pub const NETWORK_PROTECTION_VERIFY_RESPONSE_JSON_FEATURE: &str =
    "network-protection-verify-response-json-v1";
/// Capability advertised when the request may name a file holding the
/// response, by `response_path` plus `response_sha256`.
pub const NETWORK_PROTECTION_VERIFY_RESPONSE_FILE_FEATURE: &str =
    "network-protection-verify-response-file-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkProtectionVerifyRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The bundle response as fetched, unaltered: the resident recomputes the
    /// canonical payload over it rather than trusting a hash the caller
    /// derived. Null when `response_json` carries it instead.
    #[serde(default)]
    pub response: Value,
    /// The same response as JSON text. A request frame caps every array at
    /// 4,096 items, and a bundle's threat feeds run far past that, so a
    /// caller sends the response this way when the runtime advertises
    /// [`NETWORK_PROTECTION_VERIFY_RESPONSE_JSON_FEATURE`]. Exactly one of
    /// this, `response` and `response_path` may carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_json: Option<String>,
    /// A file holding the response as JSON. A frame bounds each string at
    /// 4 MiB and a production bundle's text already sits close to that, so a
    /// caller writes the response to a private file instead when the runtime
    /// advertises [`NETWORK_PROTECTION_VERIFY_RESPONSE_FILE_FEATURE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_path: Option<String>,
    /// `sha256:` digest of that file's bytes. It is part of the request, so
    /// the request hash the reply is bound to covers the response the
    /// resident read, and a file changed after the caller wrote it is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_sha256: Option<String>,
    /// The workspace the bundle must belong to.
    pub workspace_id: String,
    /// The saved supply-chain keyring payload, passed through as stored. The
    /// resident parses it; absent or empty leaves the pinned production
    /// fingerprint as the only anchor.
    #[serde(default)]
    pub trusted_keys: Option<Value>,
    /// The bundle version already saved, so a rolled-back bundle is refused.
    #[serde(default)]
    pub cached_bundle_version: Option<String>,
    /// The caller's clock, or absent to use the resident's.
    #[serde(default)]
    pub now: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkProtectionVerifyResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok`: the verifier ran. Whether it accepted the bundle is the
    /// payload's `outcome`.
    pub status: String,
    /// `ok`.
    pub code: String,
    /// `{outcome: "verified", saved}` — `saved` being the form the caller
    /// writes to sync state — or `{outcome: "refused", message}`. The Python
    /// verifier raised one error class, so a refusal carries only its message.
    #[serde(default)]
    pub payload: Value,
}
