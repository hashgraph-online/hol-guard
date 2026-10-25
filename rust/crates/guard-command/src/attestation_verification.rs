//! What a verifier checks about a trust attestation before it checks the
//! signature.
//!
//! `verify_trust_attestation` reads the envelope, validates the payload, and
//! then asks a series of questions that do not need a key: does the payload
//! still hash to what the envelope claims, is this key one we trust and has it
//! been revoked, was the claim captured before it was signed, is the
//! attestation inside its own validity window, does its sequence advance, and
//! have we seen its replay identity before. Only once all of that holds does
//! it load the public key.
//!
//! This module is that stretch, up to but not including the key. It validates
//! the payload under the envelope's signing time first, exactly as Python does,
//! so no caller can reach the hash checks with a payload the rules would have
//! refused. It hands back the canonical bytes the signature covers and the
//! replay identity the caller records, so the signing half stays where the keys
//! are. Every refusal carries Python's wording.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::attestation_envelope::{
    normalize_pem, payload_with_signed_at, public_key_fingerprint, TrustAttestationEnvelope,
};
use crate::attestation_payload::{validate_attestation_payload, AttestationPayloadRules};
use crate::attestation_timestamp::{parse_attestation_timestamp, AttestationInstant};
use crate::evidence_hash::canonical_guard_evidence_payload;
use crate::trust_claim::{trust_attestation_replay_key, trust_claim_hash};

/// A key a verifier is willing to accept attestations from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAttestationVerificationKey {
    pub key_id: String,
    pub public_key_pem: String,
    pub fingerprint_sha256: String,
    pub public_jwk_thumbprint: Option<String>,
}

/// Local verification state for rotation, revocation and replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAttestationVerificationPolicy {
    pub revoked_key_ids: BTreeSet<String>,
    pub key_not_before: BTreeMap<String, String>,
    pub minimum_sequence: Option<i64>,
    pub seen_replay_keys: BTreeSet<String>,
    pub now: Option<String>,
    /// The verifier's own nonce policy, which Python defaults to false.
    ///
    /// This is not the nonce a signed payload must carry: that one is
    /// mandatory, and `AttestationPayloadRules::SIGNED` has already demanded
    /// it by the time a payload reaches here.
    pub require_nonce: bool,
}

/// What a verifier still needs once the key-free checks have passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAttestationUnderSignature {
    /// The exact bytes the signature covers.
    pub canonical_payload: Vec<u8>,
    /// The identity a verifier records so the same attestation cannot replay.
    pub replay_key: String,
}

/// Why an attestation was refused, in the wording Python uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationVerificationError(String);

impl AttestationVerificationError {
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AttestationVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AttestationVerificationError {}

fn refuse<T>(message: &str) -> Result<T, AttestationVerificationError> {
    Err(AttestationVerificationError(message.to_owned()))
}

fn instant(payload: &Map<String, Value>, field: &str) -> Option<AttestationInstant> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .and_then(parse_attestation_timestamp)
}

/// Python's `isinstance(sequence, int)` for a sequence the payload check kept.
///
/// That check already refused anything but a non-negative integer, so the
/// value is a run of digits here, and a run too wide for `i128` is wider than
/// any minimum a verifier can hold.
fn sequence_advances(sequence: Option<&Value>, minimum: i64) -> bool {
    let Some(Value::Number(number)) = sequence else {
        return false;
    };
    let text = number.to_string();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match text.parse::<i128>() {
        Ok(value) => value > i128::from(minimum),
        // A run of digits too wide for `i128` outruns every minimum.
        Err(_) => true,
    }
}

fn key_is_trusted(
    envelope: &TrustAttestationEnvelope,
    trusted_keys: &[TrustAttestationVerificationKey],
) -> bool {
    let public_key_pem = normalize_pem(&envelope.public_key_pem);
    trusted_keys.iter().any(|trusted_key| {
        trusted_key.key_id == envelope.key_id
            && trusted_key.fingerprint_sha256 == envelope.fingerprint_sha256
            && normalize_pem(&trusted_key.public_key_pem) == public_key_pem
            && match &envelope.public_jwk_thumbprint {
                None => true,
                Some(thumbprint) => trusted_key.public_jwk_thumbprint.as_ref() == Some(thumbprint),
            }
    })
}

/// Run every check a verifier makes before it loads the signing key.
///
/// `payload` is the payload as it arrived. The envelope's signing time replaces
/// whatever it carries and the result is validated under
/// `AttestationPayloadRules::SIGNED`, exactly as Python does, because every
/// later check reads the validated copy. `trusted_keys` of `None` is Python's
/// "any key the envelope ships", which only a caller that trusts the transport
/// should pass.
///
/// # Errors
///
/// Returns the refusal a verifier reports when the claim does not hash to the
/// payload's `claimHash`, the payload does not hash to the envelope's
/// `payloadHash`, the public key does not match its fingerprint, the key is
/// untrusted or revoked, the capture and signing times are out of order, the
/// attestation predates the key or falls outside its validity window, its
/// sequence does not advance, a required nonce is absent, or its replay
/// identity has been seen before.
pub fn trust_attestation_under_signature(
    payload: &Map<String, Value>,
    envelope: &TrustAttestationEnvelope,
    claim: Option<&Map<String, Value>>,
    trusted_keys: Option<&[TrustAttestationVerificationKey]>,
    policy: &TrustAttestationVerificationPolicy,
) -> Result<TrustAttestationUnderSignature, AttestationVerificationError> {
    let payload = &validate_attestation_payload(
        &payload_with_signed_at(payload, envelope),
        AttestationPayloadRules::SIGNED,
    )
    .map_err(|error| AttestationVerificationError(error.message().to_owned()))?;

    if let Some(claim) = claim {
        let require_layer_identity =
            payload.get("scope").and_then(Value::as_str) == Some("trust_layer");
        let hashed = trust_claim_hash(claim, require_layer_identity).map_err(|_| {
            AttestationVerificationError(
                "Trust claim is not locally derived or has invalid evidence".to_owned(),
            )
        })?;
        if Some(hashed.as_str()) != payload.get("claimHash").and_then(Value::as_str) {
            return refuse("Trust attestation claim hash mismatch");
        }
    }

    let canonical_payload = canonical_guard_evidence_payload(payload);
    let mut digest = Sha256::new();
    digest.update(&canonical_payload);
    if hex::encode(digest.finalize()) != envelope.payload_hash {
        return refuse("Trust attestation payload hash mismatch");
    }

    if public_key_fingerprint(&envelope.public_key_pem) != envelope.fingerprint_sha256 {
        return refuse("Trust attestation public key fingerprint mismatch");
    }

    if trusted_keys.is_some_and(|trusted_keys| !key_is_trusted(envelope, trusted_keys)) {
        return refuse("Trust attestation key is not trusted");
    }

    if policy.revoked_key_ids.contains(&envelope.key_id) {
        return refuse("Trust attestation key is revoked");
    }

    let (Some(signed_at), Some(captured_at)) =
        (instant(payload, "signedAt"), instant(payload, "capturedAt"))
    else {
        return refuse("Trust attestation timestamp ordering is invalid");
    };
    if captured_at > signed_at {
        return refuse("Trust attestation timestamp ordering is invalid");
    }

    if let Some(key_not_before) = policy.key_not_before.get(&envelope.key_id) {
        match parse_attestation_timestamp(key_not_before) {
            Some(activated_at) if signed_at >= activated_at => {}
            _ => return refuse("Trust attestation predates the trusted key activation"),
        }
    }

    if let Some(now) = &policy.now {
        let Some(current) = parse_attestation_timestamp(now) else {
            return refuse("Trust attestation verification time is invalid");
        };
        if signed_at > current {
            return refuse("Trust attestation is signed in the future");
        }
        if instant(payload, "expiresAt").is_some_and(|expires_at| expires_at <= current) {
            return refuse("Trust attestation is expired");
        }
    }

    if let Some(minimum) = policy.minimum_sequence {
        if !sequence_advances(payload.get("sequence"), minimum) {
            return refuse("Trust attestation sequence is not monotonic");
        }
    }

    if policy.require_nonce && !payload.contains_key("nonce") {
        return refuse("Trust attestation nonce is required");
    }

    let replay_key = trust_attestation_replay_key(payload);
    if policy.seen_replay_keys.contains(&replay_key) {
        return refuse("Trust attestation replay detected");
    }

    Ok(TrustAttestationUnderSignature {
        canonical_payload,
        replay_key,
    })
}
