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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkProtectionVerifyRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The bundle response as fetched, unaltered: the resident recomputes the
    /// canonical payload over it rather than trusting a hash the caller
    /// derived.
    pub response: Value,
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
