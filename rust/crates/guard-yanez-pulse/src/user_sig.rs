//! The approver's own signature on a Pulse decision.
//!
//! The YID app signs a decision envelope with the user's BLS12-381 key
//! (minimal-pubkey, basic scheme). The receipt carries the exact signed bytes
//! in `yanez_signed_message`; Guard verifies those bytes, never a
//! re-encoding, then reads the envelope with duplicate keys rejected.

use base64ct::{Base64UrlUnpadded, Encoding};
use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use serde_json::{Map, Value};

use crate::PulseError;

/// The only user-signature algorithm Guard accepts.
pub const USER_SIG_ALG: &str = "BLS12-381-G2-basic";
/// Domain separation tag for the basic scheme on G2.
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// `action` the envelope must name.
pub const ENVELOPE_ACTION: &str = "agent_authorizations.decision";
/// Largest signed message Guard will decode.
pub const MAX_SIGNED_MESSAGE_BYTES: usize = 8 * 1024;

/// A verified decision envelope.
#[derive(Debug, Clone)]
pub struct SignedEnvelope {
    pub fields: Map<String, Value>,
    /// Lower-case hex of the 48-byte compressed G1 public key.
    pub public_key_hex: String,
}

/// Decode `0x`-prefixed hex of an exact length.
pub fn decode_prefixed_hex(value: &str, bytes: usize) -> Option<Vec<u8>> {
    let digits = value.strip_prefix("0x")?;
    if digits.len() != bytes * 2 {
        return None;
    }
    hex::decode(digits).ok()
}

/// Verify the BLS signature over `signed_message_b64` and parse the envelope.
pub fn verify(
    alg: &str,
    public_key: &str,
    signature: &str,
    signed_message_b64: &str,
) -> Result<SignedEnvelope, PulseError> {
    if alg != USER_SIG_ALG {
        return Err(PulseError::UserSignatureInvalid("alg"));
    }
    let pk_bytes = decode_prefixed_hex(public_key, 48)
        .ok_or(PulseError::UserSignatureInvalid("public_key_encoding"))?;
    let sig_bytes = decode_prefixed_hex(signature, 96)
        .ok_or(PulseError::UserSignatureInvalid("signature_encoding"))?;
    if signed_message_b64.len() > MAX_SIGNED_MESSAGE_BYTES * 2 {
        return Err(PulseError::UserSignatureInvalid("message_size"));
    }
    let message = Base64UrlUnpadded::decode_vec(signed_message_b64.trim_end_matches('='))
        .map_err(|_| PulseError::UserSignatureInvalid("message_encoding"))?;
    if message.len() > MAX_SIGNED_MESSAGE_BYTES {
        return Err(PulseError::UserSignatureInvalid("message_size"));
    }
    // `key_validate` rejects the identity point and points off the subgroup.
    let pk = PublicKey::key_validate(&pk_bytes)
        .map_err(|_| PulseError::UserSignatureInvalid("public_key"))?;
    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|_| PulseError::UserSignatureInvalid("signature"))?;
    if sig.verify(true, &message, BLS_DST, &[], &pk, true) != BLST_ERROR::BLST_SUCCESS {
        return Err(PulseError::UserSignatureInvalid("signature"));
    }
    let fields = match crate::strict_json::parse_no_duplicates(&message) {
        Some(Value::Object(map)) => map,
        _ => return Err(PulseError::UserSignatureInvalid("envelope_json")),
    };
    Ok(SignedEnvelope {
        fields,
        public_key_hex: hex::encode(pk_bytes),
    })
}
