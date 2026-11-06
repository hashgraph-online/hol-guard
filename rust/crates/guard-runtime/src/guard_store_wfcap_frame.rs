//! Shared primitives of the workflow-capability contracts: identifier, digest
//! and canonical-timestamp validation, the length-delimited signing frame, and
//! strict-object field access, each with the exact error codes of the Python
//! contract module.

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_json::dumps_sorted;
use crate::guard_store_wfcap_error::{cap, WfResult};

const FRAME_MAGIC: &[u8] = b"hol-guard.workflow-capability\x00";

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// `canonical_framed_payload(purpose, payload)`.
pub(crate) fn frame(purpose: &str, payload: &Value) -> Vec<u8> {
    let canonical = dumps_sorted(payload).unwrap_or_default().into_bytes();
    let mut out = Vec::with_capacity(FRAME_MAGIC.len() + purpose.len() + canonical.len() + 12);
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&(purpose.len() as u32).to_be_bytes());
    out.extend_from_slice(purpose.as_bytes());
    out.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    out.extend_from_slice(&canonical);
    out
}

/// `sha256(canonical_framed_payload(purpose, text))` for a text payload.
pub(crate) fn framed_text_digest(purpose: &str, text: &str) -> String {
    sha256_hex(&frame(purpose, &Value::from(text)))
}

pub(crate) fn private_reference(purpose: &str, value: &str) -> String {
    framed_text_digest(&format!("audit-{purpose}"), value)
}

pub(crate) fn canonical(payload: &Value) -> String {
    dumps_sorted(payload).unwrap_or_default()
}

pub(crate) fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

/// `hmac.compare_digest` on two ASCII digests.
pub(crate) fn digests_equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

pub(crate) fn validate_key(key: &[u8]) -> WfResult<()> {
    if key.len() < 32 {
        return cap("invalid_capability_key");
    }
    Ok(())
}

pub(crate) fn is_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    value.chars().count() <= 256
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || "._:/@+-".contains(c))
}

pub(crate) fn ident(name: &str, value: &str) -> WfResult<()> {
    if !is_ident(value) {
        return cap(format!("invalid_{name}"));
    }
    Ok(())
}

pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn digest(name: &str, value: &str) -> WfResult<()> {
    if !is_digest(value) {
        return cap(format!("invalid_{name}"));
    }
    Ok(())
}

pub(crate) fn is_reason_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `parse_utc_timestamp`: the strict `YYYY-MM-DDTHH:MM:SS.ffffffZ` form,
/// returned as microseconds since the Unix epoch.
pub(crate) fn parse_ts(value: &str) -> WfResult<i64> {
    let bytes = value.as_bytes();
    let shape = b"dddd-dd-ddTdd:dd:dd.ddddddZ";
    let well_formed = bytes.len() == shape.len()
        && bytes.iter().zip(shape).all(|(b, s)| match s {
            b'd' => b.is_ascii_digit(),
            other => b == other,
        });
    if !well_formed {
        return cap("invalid_canonical_timestamp");
    }
    let number =
        |range: std::ops::Range<usize>| -> i64 { value[range].parse::<i64>().unwrap_or(-1) };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    let (hour, minute, second, micro) = (
        number(11..13),
        number(14..16),
        number(17..19),
        number(20..26),
    );
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year < 1 || !(1..=month_days).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return cap("invalid_canonical_timestamp");
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Ok(seconds * 1_000_000 + micro)
}

/// `_strict_object`: an object with exactly `keys`.
pub(crate) fn strict<'a>(value: &'a Value, keys: &[&str]) -> WfResult<&'a Map<String, Value>> {
    match value.as_object() {
        Some(map) if map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)) => {
            Ok(map)
        }
        _ => cap("invalid_contract_keys"),
    }
}

pub(crate) fn req_str(map: &Map<String, Value>, name: &str) -> WfResult<String> {
    match map.get(name).and_then(Value::as_str) {
        Some(text) => Ok(text.to_owned()),
        None => cap(format!("invalid_{name}")),
    }
}

pub(crate) fn opt_str(map: &Map<String, Value>, name: &str) -> WfResult<Option<String>> {
    match map.get(name) {
        Some(Value::Null) => Ok(None),
        _ => req_str(map, name).map(Some),
    }
}

/// An integer field (`type(value) is int`); `code` is the error raised otherwise.
pub(crate) fn req_int(map: &Map<String, Value>, name: &str, code: &str) -> WfResult<i64> {
    match map.get(name) {
        Some(Value::Number(number)) if number.as_i64().is_some() => {
            Ok(number.as_i64().unwrap_or(0))
        }
        _ => cap(code),
    }
}

pub(crate) fn opt_int(map: &Map<String, Value>, name: &str, code: &str) -> WfResult<Option<i64>> {
    match map.get(name) {
        Some(Value::Null) => Ok(None),
        _ => req_int(map, name, code).map(Some),
    }
}

pub(crate) fn opt_value(value: &Option<String>) -> Value {
    value.as_deref().map_or(Value::Null, Value::from)
}
