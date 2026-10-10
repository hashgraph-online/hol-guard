//! Python value and query-string semantics the daemon handlers must keep:
//! `str.strip`, `parse_qs(...)[-1]`, the boolean spellings a body or query may
//! use, and `int()` over a query value.

use crate::policy_bundle_py::py_strip;
use guard_contracts::DaemonFieldV1;

/// `value.strip() or None` for a text field; every other state is `None`.
pub(crate) fn optional_string(field: &DaemonFieldV1) -> Option<String> {
    match field {
        DaemonFieldV1::Text { value } => {
            let stripped = py_strip(value);
            (!stripped.is_empty()).then(|| stripped.to_owned())
        }
        _ => None,
    }
}

/// Boolean spelling shared by bodies and queries; `None` when unrecognized.
fn spelled_bool(text: &str, empty_is_false: bool) -> Option<bool> {
    match py_strip(text).to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        "" if empty_is_false => Some(false),
        _ => None,
    }
}

/// Body boolean: absent means `default`, a JSON bool or boolean spelling is
/// itself, and anything else is invalid (`Err`).
pub(crate) fn optional_bool(field: &DaemonFieldV1, default: bool) -> Result<bool, ()> {
    match field {
        DaemonFieldV1::Absent => Ok(default),
        DaemonFieldV1::Bool { value } => Ok(*value),
        DaemonFieldV1::Text { value } => spelled_bool(value, true).ok_or(()),
        _ => Err(()),
    }
}

fn unquote_plus(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'+' {
            out.push(b' ');
        } else if byte == b'%' && hex_pair(&bytes[index + 1..]) {
            let high = (bytes[index + 1] as char).to_digit(16).unwrap_or(0);
            let low = (bytes[index + 2] as char).to_digit(16).unwrap_or(0);
            out.push((high * 16 + low) as u8);
            index += 2;
        } else {
            out.push(byte);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_pair(rest: &[u8]) -> bool {
    rest.len() >= 2 && rest[0].is_ascii_hexdigit() && rest[1].is_ascii_hexdigit()
}

/// `parse_qs(query).get(key, [None])[-1]`: blank values are dropped, the last
/// remaining value wins.
pub(crate) fn query_last(query: &str, key: &str) -> Option<String> {
    let mut found = None;
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        if value.is_empty() || unquote_plus(name) != key {
            continue;
        }
        found = Some(unquote_plus(value));
    }
    found
}

/// `_query_string`: the stripped, non-blank last value.
pub(crate) fn query_string(query: &str, key: &str) -> Option<String> {
    let value = query_last(query, key)?;
    let stripped = py_strip(&value);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// `_query_bool`: an unrecognized or missing value is `default`.
pub(crate) fn query_bool(query: &str, key: &str, default: bool) -> bool {
    query_last(query, key)
        .and_then(|value| spelled_bool(&value, false))
        .unwrap_or(default)
}

/// A parsed `int()` result: the exact value, or saturated when it exceeds
/// `i64` (the sign survives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsedInt {
    Value(i64),
    Huge { negative: bool },
}

/// `int(text)` for ASCII digits: surrounding whitespace, one sign, and single
/// underscores between digits. Non-ASCII digit forms are rejected.
pub(crate) fn parse_int(text: &str) -> Option<ParsedInt> {
    let trimmed = py_strip(text);
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let cleaned: String = digits.chars().filter(|ch| *ch != '_').collect();
    if !cleaned.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let significant = cleaned.trim_start_matches('0');
    if significant.len() > 18 {
        return Some(ParsedInt::Huge { negative });
    }
    let magnitude: i64 = if significant.is_empty() {
        0
    } else {
        significant.parse().ok()?
    };
    Some(ParsedInt::Value(if negative {
        -magnitude
    } else {
        magnitude
    }))
}
