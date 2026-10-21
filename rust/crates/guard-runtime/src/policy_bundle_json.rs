//! JSON handling for policy bundles: bounded parsing of chunked JSON text, the
//! v1 stable serialization, the v2 RFC 8785 style canonical form, and the
//! resource limits both contracts enforce before any authority is derived.

use guard_contracts::write_canonical_json_utf8;
use serde_json::Value;

pub(crate) const MAX_BYTES: usize = 2_097_152;
pub(crate) const MAX_DEPTH: usize = 40;
pub(crate) const MAX_COLLECTION_ITEMS: usize = 2_048;
pub(crate) const MAX_STRING_BYTES: usize = 1_048_576;
const MAX_KEY_BYTES: usize = 128;
/// Transport ceiling for the re-assembled JSON text (bundles are capped at 2 MiB
/// of canonical output, which this bound comfortably covers).
pub(crate) const MAX_TRANSPORT_BYTES: usize = 3 * 1024 * 1024;

/// Join transport chunks and parse them. `None` means the text is not JSON or
/// nests deeper than the parser allows; callers report `limit_depth` for the
/// latter via the resource checks on a structurally valid document.
pub(crate) fn parse_chunks(chunks: &[Value]) -> Result<Value, &'static str> {
    let mut text = String::new();
    for chunk in chunks {
        let Value::String(piece) = chunk else {
            return Err("invalid_json_value");
        };
        if text.len() + piece.len() > MAX_TRANSPORT_BYTES {
            return Err("limit_bytes");
        }
        text.push_str(piece);
    }
    parse_text(&text)
}

pub(crate) fn parse_text(text: &str) -> Result<Value, &'static str> {
    match serde_json::from_str::<Value>(text) {
        Ok(value) => Ok(value),
        Err(error) if error.is_syntax() && error.to_string().contains("recursion limit") => {
            Err("limit_depth")
        }
        Err(_) => Err("invalid_json_value"),
    }
}

/// v1 `_policy_bundle_resource_limit_error`.
pub(crate) fn v1_resource_limit_error(value: &Value) -> Option<&'static str> {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 0)];
    while let Some((current, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Some("limit_depth");
        }
        match current {
            Value::String(text) => {
                if text.len() > MAX_STRING_BYTES {
                    return Some("limit_string");
                }
            }
            Value::Object(items) => {
                if items.len() > MAX_COLLECTION_ITEMS {
                    return Some("limit_collection");
                }
                stack.extend(items.values().map(|item| (item, depth + 1)));
            }
            Value::Array(items) => {
                if items.len() > MAX_COLLECTION_ITEMS {
                    return Some("limit_collection");
                }
                stack.extend(items.iter().map(|item| (item, depth + 1)));
            }
            _ => {}
        }
    }
    let mut encoded = Vec::new();
    if write_canonical_json_utf8(value, &mut encoded).is_err() {
        return Some("invalid_json_value");
    }
    (encoded.len() > MAX_BYTES).then_some("limit_bytes")
}

/// v1 `stable_json_serialize`.
pub(crate) fn stable_serialize(value: &Value) -> Result<String, &'static str> {
    let mut out = Vec::new();
    write_canonical_json_utf8(value, &mut out)?;
    String::from_utf8(out).map_err(|_| "invalid_json_value")
}

/// v2 `_json_value` validation (limits and integer-only numbers).
pub(crate) fn v2_check(value: &Value, depth: usize) -> Result<(), &'static str> {
    if depth > MAX_DEPTH {
        return Err("limit_depth");
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(text) => {
            if text.len() > MAX_STRING_BYTES {
                Err("limit_string")
            } else {
                Ok(())
            }
        }
        Value::Number(number) => {
            let raw = number.as_str();
            if raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                Err("unsupported_number")
            } else {
                Ok(())
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_COLLECTION_ITEMS {
                return Err("limit_collection");
            }
            items.iter().try_for_each(|item| v2_check(item, depth + 1))
        }
        Value::Object(items) => {
            if items.len() > MAX_COLLECTION_ITEMS {
                return Err("limit_collection");
            }
            for (key, item) in items {
                if key.len() > MAX_KEY_BYTES {
                    return Err("limit_key");
                }
                v2_check(item, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn utf16_key(key: &str) -> Vec<u8> {
    key.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    // json.dumps(ensure_ascii=False) escapes only the quote, backslash, and
    // control characters below 0x20.
    let mut single = Vec::new();
    write_canonical_json_utf8(&Value::String(text.to_owned()), &mut single)
        .expect("strings always encode");
    out.extend_from_slice(&single);
}

/// v2 `canonical_json_bytes` over an integer-only value.
pub(crate) fn v2_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), &'static str> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(flag) => out.extend_from_slice(if *flag { b"true" } else { b"false" }),
        Value::Number(number) => {
            let raw = number.as_str();
            if raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                return Err("unsupported_canonical_json_value");
            }
            out.extend_from_slice(if raw == "-0" { b"0" } else { raw.as_bytes() });
        }
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                v2_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(items) => {
            let mut ordered: Vec<(&String, &Value)> = items.iter().collect();
            ordered.sort_by_cached_key(|(key, _)| utf16_key(key));
            out.push(b'{');
            for (index, (key, item)) in ordered.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                v2_canonical(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

pub(crate) fn v2_canonical_bytes(value: &Value) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    v2_canonical(value, &mut out)?;
    Ok(out)
}

#[cfg(test)]
#[path = "policy_bundle_json_tests.rs"]
mod tests;
