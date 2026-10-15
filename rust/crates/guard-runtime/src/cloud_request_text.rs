//! Python-compatible text and JSON helpers for the cloud request projections
//! (`local_request_snapshots.py` bounding, truthiness and byte accounting).

use guard_command::cloud_scrub::cloud_scrub_text;
use serde_json::{Map, Number, Value};

pub(crate) const LOCAL_REQUEST_SNAPSHOT_MAX_STRING_CHARS: usize = 2_000;
pub(crate) const LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS: usize = 20;
pub(crate) const LOCAL_REQUEST_TEXT_FIELD_MAX_CHARS: usize = 256;
pub(crate) const LOCAL_REQUEST_COMMAND_FIELD_MAX_CHARS: usize = 1_024;

const SENSITIVE_CLOUD_FIELD_MARKERS: [&str; 8] = [
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
];

/// Python `str.isspace()`.
pub(crate) fn py_isspace(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1c}'..='\u{1f}'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python `str.strip()`.
pub(crate) fn py_strip(value: &str) -> &str {
    value.trim_matches(py_isspace)
}

/// `_optional_string`: stripped non-empty string, else `None`.
pub(crate) fn optional_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(py_strip)
        .filter(|text| !text.is_empty())
}

/// `_first_optional_string`.
pub(crate) fn first_optional_string<'a>(
    mapping: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| optional_string(mapping.get(*key)))
}

/// Python truthiness of a JSON value.
pub(crate) fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number_as_f64(number) != 0.0,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
    }
}

fn number_as_f64(number: &Number) -> f64 {
    number.to_string().parse::<f64>().unwrap_or(f64::NAN)
}

/// `isinstance(value, int)` (bool is an int in Python).
pub(crate) fn is_py_int(value: &Value) -> bool {
    match value {
        Value::Bool(_) => true,
        Value::Number(number) => {
            let text = number.to_string();
            let digits = text.strip_prefix('-').unwrap_or(&text);
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

fn scalar_number(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(flag) => Some(f64::from(u8::from(*flag))),
        Value::Number(number) => Some(number_as_f64(number)),
        _ => None,
    }
}

/// Python `==` over decoded JSON values (`1 == 1.0 == True`).
pub(crate) fn py_eq(left: &Value, right: &Value) -> bool {
    if let (Some(a), Some(b)) = (scalar_number(left), scalar_number(right)) {
        if let (Value::Number(x), Value::Number(y)) = (left, right) {
            let (xt, yt) = (x.to_string(), y.to_string());
            if is_py_int(left) && is_py_int(right) {
                return xt == yt;
            }
        }
        return a == b;
    }
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| py_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, x)| b.get(key).is_some_and(|y| py_eq(x, y)))
        }
        _ => false,
    }
}

/// `_bounded_text`.
pub(crate) fn bounded_text_with(value: &str, max_chars: usize) -> String {
    let length = value.chars().count();
    if length <= max_chars {
        return value.to_owned();
    }
    let prefix: String = value.chars().take(max_chars).collect();
    format!("{prefix}...[truncated {} chars]", length - max_chars)
}

pub(crate) fn bounded_text(value: &str) -> String {
    bounded_text_with(value, LOCAL_REQUEST_TEXT_FIELD_MAX_CHARS)
}

pub(crate) fn bounded_command(value: &str) -> String {
    bounded_text_with(value, LOCAL_REQUEST_COMMAND_FIELD_MAX_CHARS)
}

pub(crate) fn scrubbed_text(value: &str) -> String {
    bounded_text(&cloud_scrub_text(value))
}

pub(crate) fn scrubbed_command(value: &str) -> String {
    bounded_command(&cloud_scrub_text(value))
}

/// `_is_sensitive_cloud_field`.
pub(crate) fn is_sensitive_cloud_field(field_name: Option<&str>) -> bool {
    let Some(name) = field_name else {
        return false;
    };
    let normalized = py_strip(name).to_lowercase().replace('-', "_");
    SENSITIVE_CLOUD_FIELD_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

/// `_is_sensitive_cli_flag`.
fn is_sensitive_cli_flag(value: &str) -> bool {
    let flag = py_strip(value).split('=').next().unwrap_or("");
    flag.starts_with('-') && is_sensitive_cloud_field(Some(flag.trim_start_matches('-')))
}

/// `_bounded_cloud_value`. Mappings keep their first 20 keys in the order the
/// resident sees them (sorted); Python saw insertion order.
pub(crate) fn bounded_cloud_value(value: &Value, field_name: Option<&str>) -> Value {
    if is_sensitive_cloud_field(field_name) {
        return Value::String("[redacted]".to_owned());
    }
    match value {
        Value::String(text) => Value::String(scrubbed_text(text)),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .take(LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS)
                .map(|(key, item)| (key.clone(), bounded_cloud_value(item, Some(key))))
                .collect(),
        ),
        Value::Array(items) => {
            let mut scrubbed = Vec::new();
            let mut redact_next = false;
            for item in items.iter().take(LOCAL_REQUEST_SNAPSHOT_MAX_LIST_ITEMS) {
                if redact_next {
                    scrubbed.push(Value::String("[redacted]".to_owned()));
                    redact_next = false;
                    continue;
                }
                scrubbed.push(bounded_cloud_value(item, field_name));
                if item.as_str().is_some_and(is_sensitive_cli_flag) {
                    redact_next = true;
                }
            }
            Value::Array(scrubbed)
        }
        other => other.clone(),
    }
}

/// `_set_dual_key`.
pub(crate) fn set_dual_key(
    payload: &mut Map<String, Value>,
    snake_key: &str,
    camel_key: &str,
    value: &Value,
) {
    let normalized = match value {
        Value::String(text) => {
            let stripped = py_strip(text);
            if stripped.is_empty() {
                return;
            }
            Value::String(bounded_text(stripped))
        }
        Value::Number(_) | Value::Bool(_) => value.clone(),
        Value::Null => return,
        other => bounded_cloud_value(other, None),
    };
    payload.insert(snake_key.to_owned(), normalized.clone());
    payload.insert(camel_key.to_owned(), normalized);
}

fn json_string_len(text: &str) -> usize {
    let mut length = 2;
    for character in text.chars() {
        length += match character {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            ' '..='~' => 1,
            c if (c as u32) > 0xFFFF => 12,
            _ => 6,
        };
    }
    length
}

/// Length of Python `json.dumps(value, separators=(",", ":"), sort_keys=True)`
/// encoded as UTF-8 (`ensure_ascii` default).
pub(crate) fn py_json_len(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(text) => json_string_len(text),
        Value::Array(items) => {
            2 + items.iter().map(py_json_len).sum::<usize>() + items.len().saturating_sub(1)
        }
        Value::Object(items) => {
            2 + items
                .iter()
                .map(|(key, item)| json_string_len(key) + 1 + py_json_len(item))
                .sum::<usize>()
                + items.len().saturating_sub(1)
        }
    }
}
