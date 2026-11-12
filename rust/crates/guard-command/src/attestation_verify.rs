//! Verify a trust attestation end to end.
//!
//! The modules beside this one each answer one question a verifier asks: the
//! [envelope](crate::attestation_envelope) must be readable, the
//! [payload](crate::attestation_payload) must be well formed under a verifier's
//! rules, every [key-free check](crate::attestation_verification) must pass, and
//! the [signature](crate::attestation_signature) must hold over the canonical
//! bytes. This module runs them in the order Python's
//! `verify_trust_attestation` runs them and returns the same replay identity,
//! so a caller that reaches the end here has the answer Python would return and
//! a caller that does not has the refusal Python would raise.
//!
//! Two refusals are this side's own wording rather than Python's, because
//! Python does not word them at all:
//!
//! * A `publicKeyPem` that will not parse reaches `cryptography`'s loader
//!   outside Python's `try`, so Python surfaces that library's own
//!   deserialization `ValueError`. This side reports the loader's refusal,
//!   `Trust attestation public key must be RSA or EC` — the same message Python
//!   raises for a key that parses and is neither RSA nor EC. Reaching either
//!   arm means the envelope carried a fingerprint over a PEM that is not a
//!   usable public key, so both are refusals either way.
//! * A `signature` that is not base64 reaches `base64.b64decode(validate=True)`
//!   inside Python's `try`, which catches only `InvalidSignature`, so Python
//!   surfaces `binascii.Error`'s own text. This side reports
//!   `Trust attestation signature is not base64`. Which strings count as
//!   base64 is Python's: canonical padding is required, and a final character
//!   whose unused bits are set still decodes. CPython tightened its padding
//!   checks in 3.12, so an unpadded group followed by a stray `=` decodes on
//!   3.10 and 3.11 and is refused from 3.12 on. This side holds every version
//!   to the 3.12 rule, which refuses a signature the older interpreters would
//!   have accepted rather than the other way around.
//!
//! A caller that has to reproduce Python's exact text in those two cases cannot
//! read it off this function.

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use serde_json::{Map, Value};

use crate::attestation_envelope::validated_trust_attestation_envelope;
use crate::attestation_signature::{load_attestation_public_key, verify_attestation_signature};
use crate::attestation_verification::{
    trust_attestation_under_signature, TrustAttestationVerificationKey,
    TrustAttestationVerificationPolicy,
};

/// Why an attestation was refused, in the wording a verifier reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAttestationError(String);

impl TrustAttestationError {
    /// The refusal text, which is Python's own except for the two cases the
    /// module documentation names.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TrustAttestationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TrustAttestationError {}

/// `base64.b64decode(..., validate=True)`, which Python decodes the signature
/// with: the standard alphabet and canonical padding, and, as CPython does, a
/// final character whose unused bits are not zero still decodes. A strict
/// decoder would refuse a signature Python verifies.
const PYTHON_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Check a trust attestation and return its replay identity.
///
/// `trusted_keys` of `None` accepts whatever key the envelope ships, which only
/// a caller that already trusts the transport should pass. `claim` of `None`
/// skips the claim-hash check, for a caller holding the envelope without the
/// claim it was made over.
///
/// The returned replay key is the verifier-side identity Python returns, which
/// a caller records so the same attestation cannot be presented twice.
///
/// # Errors
///
/// Returns the first refusal any step reports: an unreadable envelope, a
/// payload that is not well formed, a claim, payload hash, fingerprint, key,
/// timestamp, sequence, nonce or replay failure, a key that is not a usable
/// public key, a signature that is not base64, or a signature that does not
/// hold over the canonical payload.
pub fn verify_trust_attestation(
    payload: &Map<String, Value>,
    envelope: &Map<String, Value>,
    claim: Option<&Map<String, Value>>,
    trusted_keys: Option<&[TrustAttestationVerificationKey]>,
    policy: &TrustAttestationVerificationPolicy,
) -> Result<String, TrustAttestationError> {
    let read = validated_trust_attestation_envelope(envelope)
        .map_err(|error| TrustAttestationError(error.message().to_owned()))?;

    // `trust_attestation_under_signature` carries the envelope's signing time
    // into the payload and validates the result under the rules a verifier
    // holds a signed attestation to, so the raw payload goes straight in.
    let under_signature =
        trust_attestation_under_signature(payload, &read, claim, trusted_keys, policy)
            .map_err(|error| TrustAttestationError(error.message().to_owned()))?;

    let public_key = load_attestation_public_key(&read.public_key_pem)
        .map_err(|error| TrustAttestationError(error.message().to_owned()))?;
    let Ok(signature) = PYTHON_BASE64.decode(&read.signature) else {
        return Err(TrustAttestationError(
            "Trust attestation signature is not base64".to_owned(),
        ));
    };
    verify_attestation_signature(
        &public_key,
        &under_signature.canonical_payload,
        &signature,
        &read.signature_algorithm,
    )
    .map_err(|error| TrustAttestationError(error.message().to_owned()))?;

    Ok(under_signature.replay_key)
}

#[cfg(test)]
mod tests {
    use super::PYTHON_BASE64;
    use base64::Engine;

    #[test]
    fn padding_must_be_exactly_what_the_last_group_needs() {
        // A 72-byte ECDSA DER signature encodes to 96 characters and needs no
        // padding at all.
        let unpadded = "A".repeat(96);
        assert_eq!(
            PYTHON_BASE64.decode(&unpadded).map(|bytes| bytes.len()),
            Ok(72)
        );
        // The same characters with padding they do not need are not base64,
        // the rule CPython has applied since 3.12.
        assert!(PYTHON_BASE64.decode(format!("{unpadded}=")).is_err());
        assert!(PYTHON_BASE64.decode(format!("{unpadded}==")).is_err());

        // A three-character group takes one `=`, and only one.
        assert_eq!(
            PYTHON_BASE64.decode("AAAAQUJ=").map(|bytes| bytes.len()),
            Ok(5)
        );
        assert!(PYTHON_BASE64.decode("AAAAQUJ==").is_err());

        // A two-character group takes two, and nothing shorter will do.
        assert_eq!(
            PYTHON_BASE64.decode("AAAAQU==").map(|bytes| bytes.len()),
            Ok(4)
        );
        assert!(PYTHON_BASE64.decode("AAAAQU=").is_err());
    }

    #[test]
    fn a_final_character_carrying_unused_bits_still_decodes() {
        // `cryptography` hands Python whatever `b64decode` returns, and
        // `b64decode` ignores the bits a final character cannot spend.
        assert_eq!(PYTHON_BASE64.decode("QUJE").map(|bytes| bytes.len()), Ok(3));
        assert_eq!(PYTHON_BASE64.decode("QUJ/").map(|bytes| bytes.len()), Ok(3));
        assert_eq!(PYTHON_BASE64.decode("QU==").map(|bytes| bytes.len()), Ok(1));
    }
}
