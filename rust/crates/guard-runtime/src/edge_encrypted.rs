//! Authenticate the existing generated post-hook reference without changing its commitment.
#[cfg(unix)]
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde_json::Value;
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::path::Path;
use std::time::Instant;

#[cfg(unix)]
#[path = "edge_encrypted_file.rs"]
mod private_file;

#[cfg(unix)]
const MAX_BYTES: usize = 5 * 1024 * 1024;
#[cfg(unix)]
const KEYS: &[&str] = &[
    "version",
    "path",
    "sha256",
    "encoding",
    "encryption",
    "key",
    "nonce",
    "serialized_chars",
];

#[cfg(unix)]
fn error(code: &str) -> String {
    format!("native_hook_encrypted_payload_{code}")
}

pub(super) fn deadline_check(deadline: Option<Instant>) -> Result<(), String> {
    if deadline.is_some_and(|value| Instant::now() >= value) {
        return Err("native_request_deadline_exceeded".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| error("metadata_invalid"))
}

/// The generated Node producer uses canonical unpadded base64url for fixed-size keys.
#[cfg(unix)]
fn fixed_base64url<const N: usize>(input: &str) -> Result<[u8; N], String> {
    if input.len() != (N * 8).div_ceil(6) {
        return Err(error("key_or_nonce_invalid"));
    }
    let mut output = [0; N];
    let (mut buffer, mut bits, mut written) = (0u32, 0usize, 0usize);
    for character in input.bytes() {
        let value = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(error("key_or_nonce_invalid")),
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let target = output
                .get_mut(written)
                .ok_or_else(|| error("key_or_nonce_invalid"))?;
            *target = (buffer >> bits) as u8;
            written += 1;
        }
        buffer &= (1 << bits) - 1;
    }
    if written != N || buffer != 0 {
        return Err(error("key_or_nonce_invalid"));
    }
    Ok(output)
}

/// Only the actual generated POSIX PostToolUse producer is admitted here.
/// Other platforms keep the pre-existing explicit unsupported outcome until
/// their generated private-file handle/ACL contract is independently qualified.
pub(super) fn hydrate(payload: &Value, deadline: Option<Instant>) -> Result<Value, String> {
    deadline_check(deadline)?;
    #[cfg(not(unix))]
    {
        let _ = payload;
        Err("native_hook_encrypted_payload_unsupported".to_owned())
    }
    #[cfg(unix)]
    {
        let reference = payload
            .get("guard_payload_ref")
            .ok_or_else(|| error("metadata_invalid"))?;
        let record = reference
            .as_object()
            .ok_or_else(|| error("metadata_invalid"))?;
        if record.len() != KEYS.len()
            || !KEYS.iter().all(|key| record.contains_key(*key))
            || reference.get("version").and_then(Value::as_u64) != Some(1)
            || text(reference, "encoding")? != "json"
            || text(reference, "encryption")? != "aes-256-gcm"
        {
            return Err(error("metadata_invalid"));
        }
        let path = text(reference, "path")?;
        if path.is_empty() || path.len() > super::MAX_PATH_BYTES || path.contains('\0') {
            return Err(error("path_invalid"));
        }
        let expected = text(reference, "sha256")?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(error("digest_invalid"));
        }
        let chars = reference
            .get("serialized_chars")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0 && *value <= MAX_BYTES as u64)
            .ok_or_else(|| error("size_invalid"))?;
        let key = fixed_base64url::<32>(text(reference, "key")?)?;
        let nonce = fixed_base64url::<12>(text(reference, "nonce")?)?;
        let mut ciphertext = private_file::read(Path::new(path), MAX_BYTES, deadline)?;
        if hex::encode(Sha256::digest(&ciphertext)) != expected {
            return Err(error("digest_mismatch"));
        }
        deadline_check(deadline)?;
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &key).map_err(|_| error("key_or_nonce_invalid"))?,
        );
        let plaintext = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut ciphertext,
            )
            .map_err(|_| error("authentication_failed"))?;
        deadline_check(deadline)?;
        let plaintext = std::str::from_utf8(plaintext).map_err(|_| error("json_invalid"))?;
        if plaintext.encode_utf16().count() as u64 != chars {
            return Err(error("size_mismatch"));
        }
        let inner: Value = serde_json::from_str(plaintext).map_err(|_| error("json_invalid"))?;
        if !inner.is_object() || inner.get("guard_payload_ref").is_some() {
            return Err(error("inner_invalid"));
        }
        if super::payload_event(&inner)?.as_deref() != Some("PostToolUse") {
            return Err(error("event_mismatch"));
        }
        for key in ["tool_name", "config_path", "is_error"] {
            if inner.get(key) != payload.get(key) {
                return Err(error("metadata_mismatch"));
            }
        }
        deadline_check(deadline)?;
        Ok(inner)
    }
}

#[cfg(all(test, unix))]
#[path = "edge_encrypted_tests.rs"]
mod tests;
