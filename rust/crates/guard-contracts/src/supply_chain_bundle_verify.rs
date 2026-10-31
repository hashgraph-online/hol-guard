//! Supply-chain bundle verification contract.
//!
//! The resident checks one signed supply-chain bundle response end to end: the
//! canonical payload hash, rollback against the version the caller already
//! holds, freshness, the keyring the signing key must be anchored to, that
//! key's rotation state, and the RSA-PSS signature itself. The caller sends
//! the response exactly as it fetched or cached it together with the trusted
//! keyring it holds; it never decides whether the bundle holds, and a caller
//! that cannot reach the resident is left with an unverified bundle.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const SUPPLY_CHAIN_BUNDLE_VERIFY_REQUEST_SCHEMA: &str =
    "guard-supply-chain-bundle-verify-request.v1";
/// Schema discriminator for the result.
pub const SUPPLY_CHAIN_BUNDLE_VERIFY_RESULT_SCHEMA: &str =
    "guard-supply-chain-bundle-verify-result.v1";
/// Capability advertised by the runtime when `supply_chain_bundle_verify` is available.
pub const SUPPLY_CHAIN_BUNDLE_VERIFY_FEATURE: &str = "supply-chain-bundle-verify-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainBundleVerifyRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The bundle response as fetched or cached, unaltered: the resident
    /// recomputes the canonical payload over it rather than trusting a hash
    /// the caller derived.
    pub response: Value,
    /// The keyring the caller anchors the signing key to. Absent accepts
    /// whatever keyring the response advertises, which only a caller that has
    /// not yet saved one should send.
    #[serde(default)]
    pub trusted_keys: Option<Vec<Value>>,
    /// The bundle version already held, so a rolled-back bundle is refused.
    #[serde(default)]
    pub cached_bundle_version: Option<String>,
    /// The caller's clock, or absent to use the resident's.
    #[serde(default)]
    pub now: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainBundleVerifyResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok`: the verifier ran. Whether it accepted the bundle is the
    /// payload's `outcome`.
    pub status: String,
    /// `ok`.
    pub code: String,
    /// `{outcome: "verified"}` or `{outcome: "refused", kind, message}`, where
    /// `kind` names the refusal class the caller re-raises.
    #[serde(default)]
    pub payload: Value,
}
