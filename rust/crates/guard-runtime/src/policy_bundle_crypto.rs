//! RSA public-key parsing and RSASSA-PSS (SHA-256, MGF1-SHA-256) verification
//! for policy bundle signatures. Verification is implemented over raw modular
//! exponentiation so keys above the `rsa` crate's default size ceiling and
//! signatures with any salt length (the signer's choice) verify exactly as the
//! Python reference does.

use rsa::pkcs1::RsaPublicKey as Pkcs1PublicKey;
use rsa::pkcs8::der::{asn1::ObjectIdentifier, Decode};
use rsa::pkcs8::spki::SubjectPublicKeyInfoRef;
use rsa::BigUint;
use sha2::{Digest, Sha256};

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const HASH_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRsaKey {
    modulus: BigUint,
    exponent: BigUint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// The PEM could not be loaded as any public key.
    Pem,
    /// A public key was loaded but it is not an RSA key.
    Type,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaltMode {
    /// Accept whatever salt the signer embedded (OpenSSL auto detection).
    Auto,
    /// Require the maximum salt length for the modulus.
    Maximum,
}

impl ParsedRsaKey {
    pub(crate) fn bit_length(&self) -> usize {
        self.modulus.bits()
    }
}

fn pem_body(pem: &str) -> Option<(String, Vec<u8>)> {
    use base64ct::{Base64, Encoding};
    let mut lines = pem.trim().lines().map(str::trim);
    let begin = lines.next()?;
    let label = begin.strip_prefix("-----BEGIN ")?.strip_suffix("-----")?;
    let end = format!("-----END {label}-----");
    let mut body = String::new();
    let mut closed = false;
    for line in lines {
        if line == end {
            closed = true;
            break;
        }
        if line.contains(':') {
            return None;
        }
        body.push_str(line);
    }
    if !closed {
        return None;
    }
    let der = Base64::decode_vec(&body).ok()?;
    Some((label.to_owned(), der))
}

/// Load a PEM `PUBLIC KEY` (SPKI) or `RSA PUBLIC KEY` (PKCS#1) block.
pub(crate) fn parse_public_key(pem: &str) -> Result<ParsedRsaKey, KeyError> {
    let (label, der) = pem_body(pem).ok_or(KeyError::Pem)?;
    let pkcs1_der: Vec<u8> = match label.as_str() {
        "PUBLIC KEY" => {
            let info = SubjectPublicKeyInfoRef::from_der(&der).map_err(|_| KeyError::Pem)?;
            if info.algorithm.oid != RSA_ENCRYPTION {
                return Err(KeyError::Type);
            }
            info.subject_public_key
                .as_bytes()
                .ok_or(KeyError::Pem)?
                .to_vec()
        }
        "RSA PUBLIC KEY" => der,
        _ => return Err(KeyError::Pem),
    };
    let key = Pkcs1PublicKey::from_der(&pkcs1_der).map_err(|_| KeyError::Pem)?;
    let modulus = BigUint::from_bytes_be(key.modulus.as_bytes());
    let exponent = BigUint::from_bytes_be(key.public_exponent.as_bytes());
    if modulus.bits() < 2 || exponent.bits() < 2 {
        return Err(KeyError::Pem);
    }
    Ok(ParsedRsaKey { modulus, exponent })
}

fn mgf1(seed: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + HASH_LEN);
    let mut counter = 0u32;
    while out.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(length);
    out
}

/// EMSA-PSS-VERIFY over `RSAVP1(signature)`.
pub(crate) fn verify_pss(
    key: &ParsedRsaKey,
    signature: &[u8],
    message: &[u8],
    salt: SaltMode,
) -> bool {
    let modulus_bytes = key.modulus.bits().div_ceil(8);
    if signature.len() != modulus_bytes {
        return false;
    }
    let value = BigUint::from_bytes_be(signature);
    if value >= key.modulus {
        return false;
    }
    let em_bits = key.modulus.bits() - 1;
    let em_len = em_bits.div_ceil(8);
    let recovered = value.modpow(&key.exponent, &key.modulus);
    let raw = recovered.to_bytes_be();
    if raw.len() > em_len {
        return false;
    }
    let mut encoded = vec![0u8; em_len - raw.len()];
    encoded.extend_from_slice(&raw);
    if em_len < HASH_LEN + 2 || encoded[em_len - 1] != 0xbc {
        return false;
    }
    let db_len = em_len - HASH_LEN - 1;
    let (masked, rest) = encoded.split_at(db_len);
    let digest = &rest[..HASH_LEN];
    let excess_bits = 8 * em_len - em_bits;
    if excess_bits > 0 && masked[0] >> (8 - excess_bits) != 0 {
        return false;
    }
    let mut block = mgf1(digest, db_len);
    for (byte, mask) in block.iter_mut().zip(masked) {
        *byte ^= mask;
    }
    if excess_bits > 0 {
        block[0] &= 0xff >> excess_bits;
    }
    let zeros = block.iter().take_while(|byte| **byte == 0).count();
    if zeros >= block.len() || block[zeros] != 1 {
        return false;
    }
    let salt_bytes = &block[zeros + 1..];
    if salt == SaltMode::Maximum && salt_bytes.len() != em_len - HASH_LEN - 2 {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();
    let mut hasher = Sha256::new();
    hasher.update([0u8; 8]);
    hasher.update(message_hash);
    hasher.update(salt_bytes);
    hasher.finalize().as_slice() == digest
}

/// `base64.b64decode(value, validate=True)`: strict alphabet, padding required,
/// trailing bits are not checked.
pub(crate) fn strict_base64_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - padding];
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let (mut accumulator, mut bits) = (0u32, 0u32);
    for byte in body {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
#[path = "policy_bundle_crypto_tests.rs"]
mod tests;
