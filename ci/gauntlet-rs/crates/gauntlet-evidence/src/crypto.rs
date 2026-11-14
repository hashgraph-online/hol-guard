use crate::{EvidenceError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

pub fn sha256(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

pub fn decode_base64(value: &str, length: usize) -> Result<Vec<u8>> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| EvidenceError::Invalid("invalid base64 signature or public key"))?;
    if bytes.len() != length {
        return Err(EvidenceError::Invalid(
            "wrong signature or public key length",
        ));
    }
    Ok(bytes)
}

pub fn decode_hex(value: &str, length: usize) -> Result<Vec<u8>> {
    if value.len() != length * 2 {
        return Err(EvidenceError::Invalid("wrong hex signature length"));
    }
    let mut decoded = Vec::with_capacity(length);
    for pair in value.as_bytes().chunks_exact(2) {
        let upper = (pair[0] as char)
            .to_digit(16)
            .ok_or(EvidenceError::Invalid("invalid hex signature"))?;
        let lower = (pair[1] as char)
            .to_digit(16)
            .ok_or(EvidenceError::Invalid("invalid hex signature"))?;
        decoded.push(((upper << 4) | lower) as u8);
    }
    Ok(decoded)
}

pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if public_key.len() != 32 || signature.len() != 64 {
        return Err(EvidenceError::Invalid(
            "invalid Ed25519 key or signature length",
        ));
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| EvidenceError::Invalid("Ed25519 signature mismatch"))
}
