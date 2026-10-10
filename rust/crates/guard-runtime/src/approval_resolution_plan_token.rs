//! `parse_approval_context_token(...) is not None` for the resolution plan.
//!
//! A token is `guard-approval-context:v1:` plus a url-safe base64 JSON object
//! carrying exactly `version`, `identity`, `content`, `capabilities`, `policy`
//! and `sandbox`. Only validity matters to the plan, so nothing is returned
//! beyond whether the token is well formed.

use guard_contracts::APPROVAL_CONTEXT_TOKEN_PREFIX;
use serde_json::Value;

const MAX_TOKEN_LENGTH: usize = 2048;
const HASH_FIELDS: [&str; 5] = ["identity", "content", "capabilities", "policy", "sandbox"];

fn sextet(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Unpadded url-safe base64 as CPython's `base64.b64decode(..., validate=True)`
/// reads it once the missing padding is restored: a lone trailing character is
/// invalid and unused trailing bits are ignored rather than rejected.
fn decode(encoded: &str) -> Option<Vec<u8>> {
    if encoded.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(encoded.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in encoded.bytes() {
        accumulator = (accumulator << 6) | sextet(byte)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((accumulator >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

fn is_sha256_hex(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// Python equality `version == 1`: the integer, the float and the boolean.
fn is_version_one(value: &Value) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() == Some(1.0),
        _ => false,
    }
}

pub(crate) fn is_valid_approval_context_token(token: &str) -> bool {
    let Some(encoded) = token.strip_prefix(APPROVAL_CONTEXT_TOKEN_PREFIX) else {
        return false;
    };
    if token.chars().count() > MAX_TOKEN_LENGTH || encoded.is_empty() {
        return false;
    }
    let Some(raw) = decode(encoded) else {
        return false;
    };
    let Ok(text) = String::from_utf8(raw) else {
        return false;
    };
    let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    payload.len() == 6
        && payload.get("version").is_some_and(is_version_one)
        && HASH_FIELDS
            .iter()
            .all(|field| payload.get(*field).is_some_and(is_sha256_hex))
}
