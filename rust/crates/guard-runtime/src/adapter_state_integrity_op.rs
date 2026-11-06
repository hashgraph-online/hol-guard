//! `AdapterStateIntegrity` - resident op that authenticates an adapter's
//! durable lifecycle state.
//!
//! Faithful port of `adapters/adapter_state_integrity.py`'s `_message`,
//! `authenticate_adapter_state`, `adapter_state_is_authenticated` and
//! `authenticated_adapter_path`. Those functions decided whether a path read
//! back out of an adapter manifest was one Guard itself had written, which
//! made the Python edge the thing standing between an edited manifest and the
//! file Guard restores over during install, repair and uninstall. The runtime
//! now owns the canonical message, the MAC and every field check; the caller
//! resolves the key file and applies the verdict.

use guard_contracts::{
    adapter_state_action_supported, AdapterStateIntegrityRequestV1, AdapterStateIntegrityResultV1,
    ADAPTER_STATE_ACTION_AUTHENTICATE, ADAPTER_STATE_ACTION_FIELD, ADAPTER_STATE_ACTION_VERIFY,
    ADAPTER_STATE_AUTHENTICATION_KEY, ADAPTER_STATE_INTEGRITY_DOMAIN,
    ADAPTER_STATE_INTEGRITY_MAC_ALGORITHM, ADAPTER_STATE_INTEGRITY_MAX_BYTES,
    ADAPTER_STATE_INTEGRITY_REQUEST_SCHEMA, ADAPTER_STATE_INTEGRITY_RESULT_SCHEMA,
    ADAPTER_STATE_INTEGRITY_SCHEMA_VERSION,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::guard_store_json::dumps_sorted;
use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_adapter_state_integrity_request(
    request: &AdapterStateIntegrityRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)
        .map_err(|_| "native_adapter_state_integrity_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => match evaluate(request) {
            Ok(payload) => ("ok", "ok", Some(payload)),
            Err(code) => ("error", code, None),
        },
    };
    crate::encode_response(&AdapterStateIntegrityResultV1 {
        schema: ADAPTER_STATE_INTEGRITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The reply's binding digest never covers the key, so a caller that sees the
/// digest learns nothing about the secret it sent.
fn request_digest(request: &AdapterStateIntegrityRequestV1) -> Result<String, String> {
    let mut material = serde_json::to_value(request)
        .map_err(|_| "native_adapter_state_integrity_invalid".to_owned())?;
    if let Some(object) = material.as_object_mut() {
        object.insert("integrity_key_b64".to_owned(), Value::Null);
    }
    request_digest_with_limit(&material, ADAPTER_STATE_INTEGRITY_MAX_BYTES)
}

fn refusal(request: &AdapterStateIntegrityRequestV1) -> Option<&'static str> {
    if request.schema != ADAPTER_STATE_INTEGRITY_REQUEST_SCHEMA {
        return Some("native_adapter_state_integrity_schema_mismatch");
    }
    if !adapter_state_action_supported(&request.action) {
        return Some("native_adapter_state_integrity_action_unsupported");
    }
    if request.harness.is_empty() {
        return Some("native_adapter_state_integrity_invalid");
    }
    if !request.payload.is_object() {
        return Some("native_adapter_state_integrity_invalid");
    }
    if request.action == ADAPTER_STATE_ACTION_FIELD
        && request.field.as_deref().unwrap_or("").is_empty()
    {
        return Some("native_adapter_state_integrity_invalid");
    }
    None
}

fn evaluate(request: &AdapterStateIntegrityRequestV1) -> Result<Value, &'static str> {
    match request.action.as_str() {
        ADAPTER_STATE_ACTION_AUTHENTICATE => authenticate(request),
        ADAPTER_STATE_ACTION_VERIFY => Ok(json!({
            "authenticated": is_authenticated(request),
        })),
        ADAPTER_STATE_ACTION_FIELD => Ok(json!({
            "authenticated": is_authenticated(request),
            "value": authenticated_field(request),
        })),
        _ => Err("native_adapter_state_integrity_action_unsupported"),
    }
}

/// `authenticate_adapter_state` (:60-86): stamp the manifest with the block a
/// later `verify` recomputes. The MAC covers the payload *without* the block,
/// so stamping and verifying see the same bytes.
fn authenticate(request: &AdapterStateIntegrityRequestV1) -> Result<Value, &'static str> {
    let key = decode_key(request.integrity_key_b64.as_deref())
        .ok_or("native_adapter_state_integrity_key_unavailable")?;
    let key_id = request
        .integrity_key_id
        .as_deref()
        .ok_or("native_adapter_state_integrity_key_unavailable")?;
    let mut payload = object(&request.payload)?.clone();
    payload.remove(ADAPTER_STATE_AUTHENTICATION_KEY);
    let mac = mac_hex(&key, &request.harness, &payload)?;
    let mut authenticated = payload;
    authenticated.insert(
        ADAPTER_STATE_AUTHENTICATION_KEY.to_owned(),
        json!({
            "algorithm": ADAPTER_STATE_INTEGRITY_MAC_ALGORITHM,
            "key_id": key_id,
            "mac": mac,
            "schema_version": ADAPTER_STATE_INTEGRITY_SCHEMA_VERSION,
        }),
    );
    Ok(Value::Object(authenticated))
}

/// `adapter_state_is_authenticated` (:89-128). Every mismatch is the same
/// answer - false - so a caller cannot tell a wrong key from a wrong MAC.
fn is_authenticated(request: &AdapterStateIntegrityRequestV1) -> bool {
    let Ok(payload) = object(&request.payload) else {
        return false;
    };
    let Some(Value::Object(block)) = payload.get(ADAPTER_STATE_AUTHENTICATION_KEY) else {
        return false;
    };
    if block.get("algorithm").and_then(Value::as_str) != Some(ADAPTER_STATE_INTEGRITY_MAC_ALGORITHM)
    {
        return false;
    }
    if block.get("schema_version").and_then(Value::as_i64)
        != Some(ADAPTER_STATE_INTEGRITY_SCHEMA_VERSION)
    {
        return false;
    }
    let Some(stored_key_id) = block.get("key_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(key_id) = request.integrity_key_id.as_deref() else {
        return false;
    };
    if !constant_time_equal(stored_key_id.as_bytes(), key_id.as_bytes()) {
        return false;
    }
    let Some(supplied_mac) = block.get("mac").and_then(Value::as_str) else {
        return false;
    };
    let Some(key) = decode_key(request.integrity_key_b64.as_deref()) else {
        return false;
    };
    let mut unsigned = payload.clone();
    unsigned.remove(ADAPTER_STATE_AUTHENTICATION_KEY);
    let Ok(expected) = mac_hex(&key, &request.harness, &unsigned) else {
        return false;
    };
    constant_time_equal(supplied_mac.as_bytes(), expected.as_bytes())
}

/// `authenticated_adapter_path` (:131-152), minus the final `Path.resolve()`.
/// Resolution stays with the caller: Rust's `canonicalize` fails on a path
/// that does not exist yet, and an adapter's recorded backup target often
/// does not, so moving it here would change which manifests still work.
fn authenticated_field(request: &AdapterStateIntegrityRequestV1) -> Value {
    if !is_authenticated(request) {
        return Value::Null;
    }
    let Some(field) = request.field.as_deref() else {
        return Value::Null;
    };
    let Ok(payload) = object(&request.payload) else {
        return Value::Null;
    };
    let Some(value) = payload.get(field).and_then(Value::as_str) else {
        return Value::Null;
    };
    if value.is_empty() || value.contains('\0') {
        return Value::Null;
    }
    if !is_absolute_path(value) {
        return Value::Null;
    }
    Value::String(value.to_owned())
}

/// `pathlib.Path.is_absolute` for both families, because a manifest written on
/// one platform can be read on another and a relative path must never become
/// a write target.
fn is_absolute_path(value: &str) -> bool {
    if value.starts_with('/') {
        return true;
    }
    let bytes = value.as_bytes();
    if value.starts_with("\\\\") {
        return true;
    }
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }
    false
}

/// `_message` (:228-235): the domain, the harness and the canonical payload,
/// NUL-separated. The separators keep a harness name from running into the
/// payload, so no two different inputs share a message.
fn mac_hex(
    key: &[u8],
    harness: &str,
    payload: &Map<String, Value>,
) -> Result<String, &'static str> {
    let canonical = dumps_sorted(&Value::Object(payload.clone()))
        .ok_or("native_adapter_state_integrity_unencodable")?;
    let mut message = Vec::new();
    message.extend_from_slice(ADAPTER_STATE_INTEGRITY_DOMAIN.as_bytes());
    message.push(0);
    message.extend_from_slice(harness.as_bytes());
    message.push(0);
    message.extend_from_slice(canonical.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "native_adapter_state_integrity_key_unavailable")?;
    mac.update(&message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn object(value: &Value) -> Result<&Map<String, Value>, &'static str> {
    value
        .as_object()
        .ok_or("native_adapter_state_integrity_invalid")
}

fn decode_key(encoded: Option<&str>) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded?).ok()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(test)]
#[path = "adapter_state_integrity_op_tests.rs"]
mod tests;
