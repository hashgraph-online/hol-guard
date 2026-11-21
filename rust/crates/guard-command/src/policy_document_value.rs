//! Exact portable JSON and Python presentation for typed document DTOs.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

pub(super) type Error = Value;

pub(super) fn failure(kind: &str, message: &str, code: Option<(&str, &str)>) -> Error {
    let mut value = json!({"type":kind,"message":message});
    if let Some((code, id)) = code {
        value["code"] = json!(code);
        value["rule_id"] = json!(id);
    }
    value
}

pub(super) fn canonical(value: &Value) -> Result<String, Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => serde_json::to_string(value)
            .map_err(|_| failure("TypeError", "unsupported_canonical_json_value", None)),
        Value::Number(number) => {
            let value = number.to_string();
            if value.contains(['.', 'e', 'E']) {
                Err(failure(
                    "TypeError",
                    "unsupported_canonical_json_value",
                    None,
                ))
            } else {
                Ok(if value == "-0" { "0".into() } else { value })
            }
        }
        Value::Array(items) => {
            let values = items.iter().map(canonical).collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", values.join(",")))
        }
        Value::Object(items) => {
            let mut keys = items.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            let values = keys
                .iter()
                .map(|key| {
                    Ok(format!(
                        "{}:{}",
                        canonical(&json!(key))?,
                        canonical(&items[*key])?
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(format!("{{{}}}", values.join(",")))
        }
    }
}

fn quoted(value: &str) -> String {
    static NON_PRINTABLE: OnceLock<Regex> = OnceLock::new();
    let non_printable = NON_PRINTABLE
        .get_or_init(|| Regex::new(r"[\p{C}\p{Z}]").expect("static Unicode printability pattern"));
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::from(quote);
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character if character == quote => {
                result.push('\\');
                result.push(character);
            }
            character if character != ' ' && non_printable.is_match(&character.to_string()) => {
                let point = u32::from(character);
                result.push_str(&if point <= 255 {
                    format!("\\x{point:02x}")
                } else if point <= 65535 {
                    format!("\\u{point:04x}")
                } else {
                    format!("\\U{point:08x}")
                });
            }
            character => result.push(character),
        }
    }
    result.push(quote);
    result
}

fn repr(value: &Value) -> String {
    match value {
        Value::String(value) => quoted(value),
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(items) => {
            let mut keys = items.keys().collect::<Vec<_>>();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|key| format!("{}: {}", quoted(key), repr(&items[*key])))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        value => text(value),
    }
}

pub(super) fn text(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => repr(value),
        Value::Number(number) => {
            let raw = number.to_string();
            if raw.contains(['.', 'e', 'E']) {
                number
                    .as_f64()
                    .map(guard_contracts::python_float_repr)
                    .unwrap_or(raw)
            } else {
                raw
            }
        }
    }
}

pub(super) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Number(value) => value.as_f64().is_none_or(|value| value != 0.0),
    }
}
/// Match Python's unbounded integer ordering without narrowing to i64.
#[derive(Eq, PartialEq)]
pub(super) struct IntegerOrder(bool, String);

impl IntegerOrder {
    pub(super) fn from_value(value: &Value) -> Self {
        let spelling = value
            .as_number()
            .map(ToString::to_string)
            .unwrap_or_default();
        if spelling.is_empty() || spelling.contains(['.', 'e', 'E']) {
            return Self(false, "0".into());
        }
        let digits = spelling.trim_start_matches('-').trim_start_matches('0');
        Self(
            spelling.starts_with('-') && !digits.is_empty(),
            if digits.is_empty() { "0" } else { digits }.into(),
        )
    }
}

impl Ord for IntegerOrder {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let sign = other.0.cmp(&self.0);
        if !sign.is_eq() {
            return sign;
        }
        let magnitude = (self.1.len(), &self.1).cmp(&(other.1.len(), &other.1));
        if self.0 {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
}

impl PartialOrd for IntegerOrder {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
