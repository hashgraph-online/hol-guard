#![forbid(unsafe_code)]

//! Small, strict WebAuthn assertion decoder.
//!
//! The runtime intentionally implements only the assertion subset needed by
//! the approval ceremony: packed client data, 37-byte authenticator data, and
//! ES256/Ed25519 COSE keys. Definite-length CBOR is parsed locally to keep the
//! resident's trust boundary bounded and dependency-light.

use guard_contracts::{
    WebAuthnAssertionV4, NATIVE_APPROVAL_V4_ALGORITHM_ED25519, NATIVE_APPROVAL_V4_ALGORITHM_ES256,
    NATIVE_APPROVAL_V4_MAX_AUTHENTICATOR_DATA_BYTES, NATIVE_APPROVAL_V4_MAX_CLIENT_DATA_BYTES,
    NATIVE_APPROVAL_V4_MAX_COSE_KEY_BYTES, NATIVE_APPROVAL_V4_MAX_CREDENTIAL_ID_BYTES,
    NATIVE_APPROVAL_V4_MAX_SIGNATURE_BYTES,
};
use ring::signature;
use sha2::{Digest, Sha256};

const CBOR_MAX_DEPTH: usize = 8;
const CBOR_MAX_ITEMS: usize = 32;
const COSE_ED25519_CURVE: i64 = 6;
const COSE_P256_CURVE: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VerifiedAssertion {
    pub(super) sign_count: u32,
    pub(super) assertion_digest: [u8; 32],
}

pub(super) fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as usize;
        output.push(ALPHABET[first >> 2] as char);
        let second = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        output.push(ALPHABET[((first & 3) << 4) | (second >> 4)] as char);
        if chunk.len() > 1 {
            let third = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            output.push(ALPHABET[((second & 15) << 2) | (third >> 6)] as char);
            if chunk.len() > 2 {
                output.push(ALPHABET[third & 63] as char);
            }
        }
    }
    output
}

pub(super) fn decode_base64url(value: &str, maximum: usize, code: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() > maximum.saturating_mul(2).saturating_add(4) {
        return Err(code.to_owned());
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(code.to_owned()),
        } as u32;
        accumulator = (accumulator << 6) | digit;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits).saturating_sub(1);
            if output.len() > maximum {
                return Err(code.to_owned());
            }
        }
    }
    if bits >= 6 || (bits > 0 && accumulator != 0) {
        return Err(code.to_owned());
    }
    if encode_base64url(&output) != value {
        return Err(code.to_owned());
    }
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CborValue {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Map(Vec<(i64, CborValue)>),
    Bool(bool),
}

struct CborReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
}

impl<'a> CborReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            items: 0,
        }
    }

    fn read(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| "native_approval_v4_cbor_bounds_exceeded".to_owned())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "native_approval_v4_cbor_invalid".to_owned())?;
        self.offset = end;
        Ok(value)
    }

    fn length(&mut self, additional: u8) -> Result<usize, String> {
        let (value, encoded_bytes) = match additional {
            0..=23 => (u64::from(additional), 0),
            24 => (u64::from(self.read(1)?[0]), 1),
            25 => (
                u64::from(u16::from_be_bytes(self.read(2)?.try_into().unwrap())),
                2,
            ),
            26 => (
                u64::from(u32::from_be_bytes(self.read(4)?.try_into().unwrap())),
                4,
            ),
            27 => (u64::from_be_bytes(self.read(8)?.try_into().unwrap()), 8),
            _ => return Err("native_approval_v4_cbor_invalid".to_owned()),
        };
        if (encoded_bytes == 1 && value < 24)
            || (encoded_bytes == 2 && value <= u64::from(u8::MAX))
            || (encoded_bytes == 4 && value <= u64::from(u16::MAX))
            || (encoded_bytes == 8 && value <= u64::from(u32::MAX))
        {
            return Err("native_approval_v4_cbor_invalid".to_owned());
        }
        usize::try_from(value).map_err(|_| "native_approval_v4_cbor_bounds_exceeded".to_owned())
    }

    fn value(&mut self, depth: usize) -> Result<CborValue, String> {
        if depth > CBOR_MAX_DEPTH {
            return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
        }
        self.items = self
            .items
            .checked_add(1)
            .ok_or_else(|| "native_approval_v4_cbor_bounds_exceeded".to_owned())?;
        if self.items > CBOR_MAX_ITEMS * CBOR_MAX_DEPTH {
            return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
        }
        let header = *self
            .read(1)?
            .first()
            .ok_or_else(|| "native_approval_v4_cbor_invalid".to_owned())?;
        let major = header >> 5;
        let additional = header & 31;
        match major {
            0 => Ok(CborValue::Unsigned(self.length(additional)? as u64)),
            1 => {
                let magnitude = self.length(additional)? as u64;
                let value = i64::try_from(magnitude)
                    .ok()
                    .and_then(|number| number.checked_add(1))
                    .and_then(|number| number.checked_neg())
                    .ok_or_else(|| "native_approval_v4_cbor_bounds_exceeded".to_owned())?;
                Ok(CborValue::Negative(value))
            }
            2 => {
                let length = self.length(additional)?;
                if length > NATIVE_APPROVAL_V4_MAX_COSE_KEY_BYTES {
                    return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
                }
                Ok(CborValue::Bytes(self.read(length)?.to_owned()))
            }
            3 => {
                let length = self.length(additional)?;
                if length > 512 {
                    return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
                }
                let text = std::str::from_utf8(self.read(length)?)
                    .map_err(|_| "native_approval_v4_cbor_invalid".to_owned())?;
                Ok(CborValue::Text(text.to_owned()))
            }
            4 => {
                let length = self.length(additional)?;
                if length > CBOR_MAX_ITEMS {
                    return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    values.push((0, self.value(depth + 1)?));
                }
                Ok(CborValue::Map(values))
            }
            5 => {
                let length = self.length(additional)?;
                if length > CBOR_MAX_ITEMS {
                    return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    let key = match self.value(depth + 1)? {
                        CborValue::Unsigned(value) => i64::try_from(value)
                            .map_err(|_| "native_approval_v4_cbor_invalid".to_owned())?,
                        CborValue::Negative(value) => value,
                        _ => return Err("native_approval_v4_cbor_invalid".to_owned()),
                    };
                    if values.iter().any(|(existing, _)| *existing == key) {
                        return Err("native_approval_v4_cbor_invalid".to_owned());
                    }
                    values.push((key, self.value(depth + 1)?));
                }
                Ok(CborValue::Map(values))
            }
            7 if additional == 20 => Ok(CborValue::Bool(false)),
            7 if additional == 21 => Ok(CborValue::Bool(true)),
            _ => Err("native_approval_v4_cbor_invalid".to_owned()),
        }
    }
}

fn parse_cose_key(bytes: &[u8], algorithm: i32) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() > NATIVE_APPROVAL_V4_MAX_COSE_KEY_BYTES {
        return Err("native_approval_v4_cbor_bounds_exceeded".to_owned());
    }
    let mut reader = CborReader::new(bytes);
    let value = reader.value(0)?;
    if reader.offset != bytes.len() {
        return Err("native_approval_v4_cbor_invalid".to_owned());
    }
    let CborValue::Map(entries) = value else {
        return Err("native_approval_v4_cbor_invalid".to_owned());
    };
    let get = |key: i64| {
        entries
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, v)| v)
    };
    let int = |value: Option<&CborValue>| -> Option<i64> {
        match value {
            Some(CborValue::Unsigned(number)) => i64::try_from(*number).ok(),
            Some(CborValue::Negative(number)) => Some(*number),
            _ => None,
        }
    };
    let bytes_value = |value: Option<&CborValue>, length: usize| -> Option<Vec<u8>> {
        match value {
            Some(CborValue::Bytes(bytes)) if bytes.len() == length => Some(bytes.clone()),
            _ => None,
        }
    };
    let key_type = int(get(1));
    let cose_algorithm = int(get(3));
    let curve = int(get(-1));
    let x = bytes_value(get(-2), 32);
    match algorithm {
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519
            if entries.len() == 4
                && key_type == Some(1)
                && cose_algorithm == Some(-8)
                && curve == Some(COSE_ED25519_CURVE) =>
        {
            x.ok_or_else(|| "native_approval_v4_cbor_invalid".to_owned())
        }
        NATIVE_APPROVAL_V4_ALGORITHM_ES256
            if entries.len() == 5
                && key_type == Some(2)
                && cose_algorithm == Some(-7)
                && curve == Some(COSE_P256_CURVE) =>
        {
            let y = bytes_value(get(-3), 32)
                .ok_or_else(|| "native_approval_v4_cbor_invalid".to_owned())?;
            let mut point = Vec::with_capacity(65);
            point.push(4);
            point.extend(x.ok_or_else(|| "native_approval_v4_cbor_invalid".to_owned())?);
            point.extend(y);
            Ok(point)
        }
        _ => Err("native_approval_v4_algorithm_invalid".to_owned()),
    }
}

pub(crate) fn validate_cose_public_key(bytes: &[u8], algorithm: i32) -> Result<Vec<u8>, String> {
    parse_cose_key(bytes, algorithm)
}

fn verify_client_data(
    bytes: &[u8],
    expected_challenge: &str,
    expected_origin: &str,
) -> Result<[u8; 32], String> {
    if bytes.is_empty() || bytes.len() > NATIVE_APPROVAL_V4_MAX_CLIENT_DATA_BYTES {
        return Err("native_approval_v4_client_data_invalid".to_owned());
    }
    let value = crate::strict_json_value(bytes)
        .map_err(|_| "native_approval_v4_client_data_invalid".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "native_approval_v4_client_data_invalid".to_owned())?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "challenge" | "origin" | "crossOrigin"
        )
    }) {
        return Err("native_approval_v4_client_data_invalid".to_owned());
    }
    if object.get("type").and_then(serde_json::Value::as_str) != Some("webauthn.get") {
        return Err("native_approval_v4_client_data_type_invalid".to_owned());
    }
    if object.get("challenge").and_then(serde_json::Value::as_str) != Some(expected_challenge) {
        return Err("native_approval_v4_client_data_invalid".to_owned());
    }
    if object.get("origin").and_then(serde_json::Value::as_str) != Some(expected_origin) {
        return Err("native_approval_v4_origin_mismatch".to_owned());
    }
    if object
        .get("crossOrigin")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err("native_approval_v4_client_data_invalid".to_owned());
    }
    Ok(Sha256::digest(bytes).into())
}

pub(super) fn verify_assertion(
    assertion: &WebAuthnAssertionV4,
    expected_challenge: &str,
    expected_rp_id: &str,
    expected_origin: &str,
    expected_credential_id: &[u8],
    cose_public_key: &[u8],
    algorithm: i32,
) -> Result<VerifiedAssertion, String> {
    if assertion.assertion_type != "public-key" {
        return Err("native_approval_v4_artifact_invalid".to_owned());
    }
    let raw_id = decode_base64url(
        &assertion.raw_id,
        NATIVE_APPROVAL_V4_MAX_CREDENTIAL_ID_BYTES,
        "native_approval_v4_credential_mismatch",
    )?;
    let id = decode_base64url(
        &assertion.id,
        NATIVE_APPROVAL_V4_MAX_CREDENTIAL_ID_BYTES,
        "native_approval_v4_credential_mismatch",
    )?;
    if raw_id != id || raw_id != expected_credential_id {
        return Err("native_approval_v4_credential_mismatch".to_owned());
    }
    if encode_base64url(&raw_id) != assertion.raw_id || encode_base64url(&id) != assertion.id {
        return Err("native_approval_v4_credential_mismatch".to_owned());
    }
    if let Some(user_handle) = assertion.response.user_handle.as_ref() {
        let _ = decode_base64url(user_handle, 256, "native_approval_v4_artifact_invalid")?;
    }
    let client_data = decode_base64url(
        &assertion.response.client_data_json,
        NATIVE_APPROVAL_V4_MAX_CLIENT_DATA_BYTES,
        "native_approval_v4_client_data_invalid",
    )?;
    let authenticator_data = decode_base64url(
        &assertion.response.authenticator_data,
        NATIVE_APPROVAL_V4_MAX_AUTHENTICATOR_DATA_BYTES,
        "native_approval_v4_authenticator_data_invalid",
    )?;
    let signature_bytes = decode_base64url(
        &assertion.response.signature,
        NATIVE_APPROVAL_V4_MAX_SIGNATURE_BYTES,
        "native_approval_v4_signature_invalid",
    )?;
    if authenticator_data.len() != 37 {
        return Err("native_approval_v4_authenticator_data_invalid".to_owned());
    }
    let client_hash = verify_client_data(&client_data, expected_challenge, expected_origin)?;
    let rp_hash: [u8; 32] = Sha256::digest(expected_rp_id.as_bytes()).into();
    if authenticator_data[..32] != rp_hash {
        return Err("native_approval_v4_rp_id_mismatch".to_owned());
    }
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 || flags & 0x04 == 0 || flags & (0x02 | 0x20 | 0x40 | 0x80) != 0 {
        return Err("native_approval_v4_authenticator_flags_invalid".to_owned());
    }
    let sign_count = u32::from_be_bytes(authenticator_data[33..37].try_into().unwrap());
    let public_key = parse_cose_key(cose_public_key, algorithm)?;
    let mut signed = Vec::with_capacity(authenticator_data.len() + client_hash.len());
    signed.extend_from_slice(&authenticator_data);
    signed.extend_from_slice(&client_hash);
    let verification_algorithm: &dyn signature::VerificationAlgorithm = match algorithm {
        NATIVE_APPROVAL_V4_ALGORITHM_ES256 => &signature::ECDSA_P256_SHA256_ASN1,
        NATIVE_APPROVAL_V4_ALGORITHM_ED25519 => &signature::ED25519,
        _ => return Err("native_approval_v4_algorithm_invalid".to_owned()),
    };
    signature::UnparsedPublicKey::new(verification_algorithm, public_key)
        .verify(&signed, &signature_bytes)
        .map_err(|_| "native_approval_v4_signature_invalid".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(&raw_id);
    digest.update(&client_data);
    digest.update(&authenticator_data);
    digest.update(&signature_bytes);
    Ok(VerifiedAssertion {
        sign_count,
        assertion_digest: digest.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_rejects_noncanonical_and_round_trips() {
        let encoded = encode_base64url(b"webauthn");
        assert_eq!(decode_base64url(&encoded, 32, "bad").unwrap(), b"webauthn");
        assert!(decode_base64url("ab=", 32, "bad").is_err());
        assert!(decode_base64url("aB", 32, "bad").is_err());
    }

    #[test]
    fn cbor_rejects_duplicate_keys_and_indefinite_maps() {
        assert!(parse_cose_key(&[0xa2, 0x01, 0x01, 0x01, 0x01], -8).is_err());
        assert!(parse_cose_key(&[0xbf, 0xff], -8).is_err());
    }
}
