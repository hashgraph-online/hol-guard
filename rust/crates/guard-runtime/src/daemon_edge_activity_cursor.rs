//! The command-activity page cursor: `_signed_cursor` and
//! `decode_activity_cursor`, signed with the daemon key.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use super::{Parsed, API_SCHEMA_VERSION, CURSOR_PREFIX};

/// `_signed_cursor` over the next page's marker.
pub(super) fn signed_cursor(
    occurred_at: &str,
    activity_id: &str,
    binding: &Value,
    token: &[u8],
) -> Option<String> {
    if !occurred_at.is_ascii() || !activity_id.is_ascii() {
        return None;
    }
    // `json.dumps(sort_keys=True, separators=(",", ":"))`.
    let raw = serde_json::to_string(&json!({
        "activity_id": activity_id,
        "binding": binding,
        "occurred_at": occurred_at,
        "version": API_SCHEMA_VERSION,
    }))
    .ok()?;
    let encoded = URL_SAFE_NO_PAD.encode(raw);
    let mut mac = Hmac::<Sha256>::new_from_slice(token).ok()?;
    mac.update(encoded.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Some(format!("{CURSOR_PREFIX}.{encoded}.{signature}"))
}

/// `decode_activity_cursor`: a cursor this daemon signed for the same
/// filters, or the daemon's `invalid_cursor`.
pub(super) fn verified_cursor(
    cursor: &str,
    binding: &Value,
    token: &[u8],
) -> Parsed<(String, String)> {
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
    let mut mac = Hmac::<Sha256>::new_from_slice(token).ok()?;
    mac.update(encoded.as_bytes());
    if mac.verify_slice(&supplied).is_err() {
        return Some(Err(INVALID));
    }
    let Ok(raw) = URL_SAFE_NO_PAD.decode(encoded) else {
        return Some(Err(INVALID));
    };
    // Text `json.loads` reads differently (other encodings, NaN) goes to the
    // daemon.
    let Value::Object(payload) = serde_json::from_slice::<Value>(&raw).ok()? else {
        return Some(Err(INVALID));
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
