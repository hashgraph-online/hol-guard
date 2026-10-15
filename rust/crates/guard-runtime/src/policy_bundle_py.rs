//! Python value semantics the policy-bundle authority must reproduce exactly:
//! `str.strip`, truthiness, cross-type equality (`1 == 1.0 == True`) and
//! arbitrary-size integer comparison over JSON number tokens.

use std::cmp::Ordering;

use serde_json::{Map, Value};

pub(crate) type Obj = Map<String, Value>;

pub(crate) fn is_py_space(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// `str.strip()`.
pub(crate) fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

/// `value if isinstance(value, str) and value.strip() else None`.
pub(crate) fn non_empty(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if !py_strip(text).is_empty() => Some(text),
        _ => None,
    }
}

/// Strict variant: stripped-equal, non-empty and at most `maximum` UTF-8 bytes.
pub(crate) fn strict_non_empty(value: Option<&Value>, maximum: usize) -> Option<&str> {
    match value {
        Some(Value::String(text))
            if !text.is_empty() && py_strip(text) == text && text.len() <= maximum =>
        {
            Some(text)
        }
        _ => None,
    }
}

pub(crate) fn text(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn number_token(value: &Value) -> Option<&str> {
    match value {
        Value::Number(number) => Some(number.as_str()),
        _ => None,
    }
}

/// Decimal token of a JSON integer (never a bool or a float), `-0` as `0`.
pub(crate) fn int_token(value: &Value) -> Option<&str> {
    let token = number_token(value)?;
    if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        return None;
    }
    Some(if token == "-0" { "0" } else { token })
}

pub(crate) fn is_int(value: Option<&Value>) -> bool {
    value.and_then(int_token).is_some()
}

pub(crate) fn int_cmp(left: &str, right: &str) -> Ordering {
    let (left_negative, left_digits) = split_sign(left);
    let (right_negative, right_digits) = split_sign(right);
    match (left_negative, right_negative) {
        (false, true) => Ordering::Greater,
        (true, false) => Ordering::Less,
        (negative, _) => {
            let magnitude = digits_cmp(left_digits, right_digits);
            if negative {
                magnitude.reverse()
            } else {
                magnitude
            }
        }
    }
}

fn split_sign(token: &str) -> (bool, &str) {
    match token.strip_prefix('-') {
        Some(rest) => (!rest.chars().all(|ch| ch == '0'), rest),
        None => (false, token),
    }
}

pub(crate) fn digits_cmp(left: &str, right: &str) -> Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

enum Numeric {
    Int(String),
    Float(f64),
}

fn numeric(value: &Value) -> Option<Numeric> {
    match value {
        Value::Bool(flag) => Some(Numeric::Int(if *flag { "1" } else { "0" }.to_owned())),
        Value::Number(number) => match int_token(value) {
            Some(token) => Some(Numeric::Int(token.to_owned())),
            None => number.as_f64().map(Numeric::Float),
        },
        _ => None,
    }
}

fn numeric_eq(left: &Numeric, right: &Numeric) -> bool {
    match (left, right) {
        (Numeric::Int(a), Numeric::Int(b)) => int_cmp(a, b) == Ordering::Equal,
        (Numeric::Float(a), Numeric::Float(b)) => a == b,
        (Numeric::Int(token), Numeric::Float(float))
        | (Numeric::Float(float), Numeric::Int(token)) => {
            float.is_finite()
                && float.fract() == 0.0
                && int_cmp(token, &format!("{float:.0}")) == Ordering::Equal
        }
    }
}

/// Python `==` over JSON-decoded values.
pub(crate) fn py_eq(left: &Value, right: &Value) -> bool {
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
        _ => match (numeric(left), numeric(right)) {
            (Some(a), Some(b)) => numeric_eq(&a, &b),
            _ => false,
        },
    }
}

pub(crate) fn py_eq_opt(left: Option<&Value>, right: Option<&Value>) -> bool {
    py_eq(left.unwrap_or(&Value::Null), right.unwrap_or(&Value::Null))
}

/// `dict.get(key) in <frozenset of strings>`.
pub(crate) fn in_set(value: Option<&Value>, set: &[&str]) -> bool {
    matches!(value, Some(Value::String(text)) if set.contains(&text.as_str()))
}

/// Python truthiness of a JSON-decoded value.
pub(crate) fn py_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(items)) => !items.is_empty(),
        Some(Value::Number(number)) => {
            let token = number.as_str();
            let is_float = token.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'));
            if is_float {
                number.as_f64().is_none_or(|float| float != 0.0)
            } else {
                token.bytes().any(|b| matches!(b, b'1'..=b'9'))
            }
        }
        Some(Value::Bool(true)) => true,
    }
}

/// `_has_constraint`: malformed values count as constraints.
pub(crate) fn has_constraint(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !py_strip(text).is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
        _ => true,
    }
}

/// `re.split(r"[^0-9]+", value)` tokens, `None` when no digit run exists.
pub(crate) fn version_tuple(value: &str) -> Option<Vec<String>> {
    let tokens: Vec<String> = value
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|token| !token.is_empty())
        .map(|token| token.trim_start_matches('0').to_owned())
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens)
    }
}

/// Tuple ordering over [`version_tuple`] values.
pub(crate) fn version_cmp(left: &[String], right: &[String]) -> Ordering {
    for (a, b) in left.iter().zip(right) {
        let order = a.len().cmp(&b.len()).then_with(|| a.cmp(b));
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

/// `contract_validation.canonical_uuid`.
pub(crate) fn canonical_uuid(value: Option<&Value>, maximum_bytes: usize) -> bool {
    let Some(Value::String(text)) = value else {
        return false;
    };
    if text.is_empty() || py_strip(text) != text || text.len() > maximum_bytes {
        return false;
    }
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

/// `contract_validation.positive_integer`.
pub(crate) fn is_positive_int(value: Option<&Value>) -> bool {
    value
        .and_then(int_token)
        .is_some_and(|token| int_cmp(token, "1") != Ordering::Less)
}

pub(crate) fn is_non_negative_int(value: Option<&Value>) -> bool {
    value
        .and_then(int_token)
        .is_some_and(|token| int_cmp(token, "0") != Ordering::Less)
}

/// `^sha256:[0-9a-f]{64}$` via `fullmatch`.
pub(crate) fn is_sha256_digest(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(text)) if text.strip_prefix("sha256:").is_some_and(is_hex64))
}

pub(crate) fn is_hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn obj(value: Option<&Value>) -> Option<&Obj> {
    value.and_then(Value::as_object)
}

pub(crate) fn string_list(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Array(items)) if items.iter().all(Value::is_string))
}

#[cfg(test)]
#[path = "policy_bundle_py_tests.rs"]
mod tests;
