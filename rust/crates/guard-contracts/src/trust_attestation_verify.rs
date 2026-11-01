//! Trust attestation verification contract.
//!
//! The resident checks one signed trust attestation end to end: the envelope,
//! the payload under a verifier's rules, the claim it was made over, the key
//! it was signed with, the rotation, replay and expiry state the caller holds,
//! and the signature itself. The caller sends the attestation and that state;
//! it never decides whether the attestation holds, and it never carries a key
//! or a digest the resident did not derive.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const TRUST_ATTESTATION_VERIFY_REQUEST_SCHEMA: &str =
    "guard-trust-attestation-verify-request.v1";
/// Schema discriminator for the result.
pub const TRUST_ATTESTATION_VERIFY_RESULT_SCHEMA: &str = "guard-trust-attestation-verify-result.v1";
/// Capability advertised by the runtime when `trust_attestation_verify` is available.
pub const TRUST_ATTESTATION_VERIFY_FEATURE: &str = "trust-attestation-verify-v1";

/// One public key a verifier is willing to accept an attestation under.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustAttestationVerifyKeyV1 {
    pub key_id: String,
    pub public_key_pem: String,
    pub fingerprint_sha256: String,
    #[serde(default)]
    pub public_jwk_thumbprint: Option<String>,
}

/// The rotation, revocation, replay and expiry state the verifier holds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustAttestationVerifyPolicyV1 {
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
    /// Key id to the earliest signing time that key may have been used at.
    #[serde(default)]
    pub key_not_before: BTreeMap<String, String>,
    /// The lowest sequence the verifier will accept, as decimal digits.
    ///
    /// Carried as text because the caller's integers are unbounded. A limit
    /// too wide for a fixed-width field would otherwise fail to decode, and
    /// the caller would read a refusal it has every right to see as a
    /// verifier that could not run at all.
    #[serde(default)]
    pub minimum_sequence: Option<String>,
    #[serde(default)]
    pub seen_replay_keys: Vec<String>,
    /// The verifier's current time, or absent to skip every time-of-day check.
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub require_nonce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustAttestationVerifyRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub payload: Map<String, Value>,
    pub envelope: Map<String, Value>,
    /// The claim the attestation was made over, or absent for a caller holding
    /// the envelope without it.
    #[serde(default)]
    pub claim: Option<Map<String, Value>>,
    /// Absent accepts whatever key the envelope ships, which only a caller that
    /// already trusts the transport should send.
    #[serde(default)]
    pub trusted_keys: Option<Vec<TrustAttestationVerifyKeyV1>>,
    pub policy: TrustAttestationVerifyPolicyV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrustAttestationVerifyResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `sha256:` digest of the canonical request, binding the reply to it.
    pub request_sha256: String,
    /// `ok`: the verifier ran. Whether it accepted the attestation is the
    /// payload's `outcome`.
    pub status: String,
    /// `ok`.
    pub code: String,
    /// `{outcome: "verified", replay_key}` or `{outcome: "refused", message}`.
    #[serde(default)]
    pub payload: Value,
}
