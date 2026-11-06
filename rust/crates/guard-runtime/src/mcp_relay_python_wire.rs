//! The frame the proxy hands the child for a host frame.
//!
//! The proxy decodes each host line with `json.loads` and writes the child
//! `json.dumps` of the result through the resident, which decodes it again
//! and frames it. Keys and strings survive that unchanged, and the resident
//! writes the keys sorted, as the relay's own parser holds them; only numbers
//! take Python's text: `-0` reads as the integer zero and a float prints as
//! `repr(float(text))`. `python_canonical` applies exactly that, and refuses
//! any number the proxy could not carry to the child.

use serde_json::{Map, Number, Value};

/// CPython's `sys.get_int_max_str_digits()` default: `json.loads` raises on
/// an integer literal with more digits.
const MAX_INT_DIGITS: usize = 4_300;

/// `json.dumps(json.loads(value))` as the child receives it, or `None` when
/// the proxy would not deliver it: a float that is not finite (written as
/// `Infinity`, which the resident refuses) or an integer past the digit
/// limit.
pub(super) fn python_canonical(value: &Value) -> Option<Value> {
    Some(match value {
        Value::Number(number) => Value::Number(python_number(&number.to_string())?),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(python_canonical)
                .collect::<Option<Vec<_>>>()?,
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| Some((key.clone(), python_canonical(value)?)))
                .collect::<Option<Map<String, Value>>>()?,
        ),
        Value::Null | Value::Bool(_) | Value::String(_) => value.clone(),
    })
}

/// One JSON number literal as Python re-serializes it.
fn python_number(text: &str) -> Option<Number> {
    let canonical = if text.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
        // Both parsers round a decimal literal correctly, so they agree on
        // the double; `python_float_repr` is CPython's shortest `repr`.
        let float = text.parse::<f64>().ok().filter(|float| float.is_finite())?;
        guard_contracts::python_float_repr(float)
    } else {
        let digits = text.strip_prefix('-').unwrap_or(text);
        if digits.is_empty()
            || digits.len() > MAX_INT_DIGITS
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        if digits.bytes().all(|byte| byte == b'0') {
            "0".to_owned()
        } else {
            text.to_owned()
        }
    };
    canonical.parse::<Number>().ok()
}

#[cfg(test)]
#[path = "mcp_relay_python_wire_tests.rs"]
mod tests;
