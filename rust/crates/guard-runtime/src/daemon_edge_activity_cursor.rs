//! The command-activity page cursor: `_signed_cursor` and
//! `decode_activity_cursor`, signed with the daemon key.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use super::{Parsed, API_SCHEMA_VERSION, CURSOR_PREFIX};

/// `_signed_cursor` over the next page's marker.
pub(super) fn signed_cursor(
    occurred_at: &str,
    activity_id: &str,
    binding: &Value,
    key: &[u8],
) -> Option<String> {
    if !occurred_at.is_ascii() || !activity_id.is_ascii() {
        return None;
    }
    sign(
        &json!({
            "activity_id": activity_id,
            "binding": binding,
            "occurred_at": occurred_at,
            "version": API_SCHEMA_VERSION,
        }),
        key,
    )
}

/// `_signed_cursor`: the payload as `json.dumps(sort_keys=True,
/// separators=(",", ":"))` writes it, signed with the daemon key. Text other
/// than ASCII goes to the daemon, which escapes it.
pub(super) fn sign(payload: &Value, key: &[u8]) -> Option<String> {
    let raw = serde_json::to_string(payload).ok()?;
    if !raw.is_ascii() {
        return None;
    }
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(encoded.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Some(format!("{CURSOR_PREFIX}.{encoded}.{signature}"))
}

/// `_verified_cursor`: the payload object of a cursor this daemon signed, or
/// the daemon's `invalid_cursor`.
pub(super) fn verify(cursor: &str, key: &[u8]) -> Parsed<Map<String, Value>> {
    const INVALID: &str = "invalid_cursor";
    if cursor.len() > 2_048 {
        return Some(Err(INVALID));
    }
    let parts: Vec<&str> = cursor.split('.').collect();
    let [prefix, encoded, signature] = parts.as_slice() else {
        return Some(Err(INVALID));
    };
    if *prefix != CURSOR_PREFIX || encoded.is_empty() || signature.is_empty() {
        return Some(Err(INVALID));
    }
    let Ok(supplied) = URL_SAFE_NO_PAD.decode(signature) else {
        return Some(Err(INVALID));
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(encoded.as_bytes());
    if mac.verify_slice(&supplied).is_err() {
        return Some(Err(INVALID));
    }
    let Ok(raw) = URL_SAFE_NO_PAD.decode(encoded) else {
        return Some(Err(INVALID));
    };
    // Text `json.loads` reads differently (other encodings, NaN) goes to the
    // daemon.
    match serde_json::from_slice::<Value>(&raw).ok()? {
        Value::Object(payload) => Some(Ok(payload)),
        _ => Some(Err(INVALID)),
    }
}

/// `decode_activity_cursor`: a cursor this daemon signed for the same
/// filters, or the daemon's `invalid_cursor`.
pub(super) fn verified_cursor(
    cursor: &str,
    binding: &Value,
    key: &[u8],
) -> Parsed<(String, String)> {
    const INVALID: &str = "invalid_cursor";
    let payload = match verify(cursor, key)? {
        Ok(payload) => payload,
        Err(code) => return Some(Err(code)),
    };
    // Python compares `1 == True`; a number anywhere in the binding goes to
    // the daemon.
    let stored = payload.get("binding");
    if stored
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(Value::is_number))
    {
        return None;
    }
    match (
        payload.get("version"),
        stored,
        payload.get("occurred_at"),
        payload.get("activity_id"),
    ) {
        (
            Some(Value::String(version)),
            Some(stored),
            Some(Value::String(at)),
            Some(Value::String(id)),
        ) if version == API_SCHEMA_VERSION && stored == binding => {
            Some(Ok((at.clone(), id.clone())))
        }
        _ => Some(Err(INVALID)),
    }
}
