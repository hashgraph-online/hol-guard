//! JSON parsing and comparison rules Pulse requires.
//!
//! The approver's signed envelope must be parsed with duplicate keys
//! rejected, and terms are compared structurally: a boolean never equals a
//! number, `-0` equals `0`, array order matters, and only integers within
//! 2^53-1 are allowed.

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Largest integer Pulse allows anywhere in terms or the envelope.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

const ARBITRARY_PRECISION_TOKEN: &str = "$serde_json::private::Number";

/// Parse JSON bytes, rejecting duplicate object keys at any depth.
pub fn parse_no_duplicates(bytes: &[u8]) -> Option<Value> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = NoDupSeed.deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(value)
}

struct NoDupSeed;

impl<'de> DeserializeSeed<'de> for NoDupSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(NoDupVisitor)
    }
}

struct NoDupVisitor;

impl<'de> Visitor<'de> for NoDupVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON without duplicate keys")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            // The workspace builds serde_json with `arbitrary_precision`,
            // which hands every number to `visit_map` under this token.
            if map.is_empty() && key == ARBITRARY_PRECISION_TOKEN {
                let text: String = access.next_value()?;
                return serde_json::from_str::<Number>(&text)
                    .map(Value::Number)
                    .map_err(|_| de::Error::custom("invalid number"));
            }
            if map.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let value = access.next_value_seed(NoDupSeed)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element_seed(NoDupSeed)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
}

/// An integer within Pulse's safe range, or `None` for floats, decimal
/// strings and out-of-range values. `-0` reads as `0`.
pub fn safe_integer(value: &Value) -> Option<i64> {
    let number = value.as_number()?;
    let text = number.to_string();
    if text.contains(['.', 'e', 'E']) {
        return None;
    }
    let parsed: i64 = text.parse().ok()?;
    (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER)
        .contains(&parsed)
        .then_some(parsed)
}

/// Pulse structural equality. Any non-integer number makes the values unequal.
pub fn terms_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(_), Value::Number(_)) => match (safe_integer(left), safe_integer(right)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| terms_equal(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, x)| b.get(key).is_some_and(|y| terms_equal(x, y)))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        assert!(parse_no_duplicates(br#"{"a":1,"a":2}"#).is_none());
        assert!(parse_no_duplicates(br#"{"a":{"b":1,"b":1}}"#).is_none());
        assert!(parse_no_duplicates(br#"{"a":[{"b":1}],"c":2}"#).is_some());
        assert!(parse_no_duplicates(br#"{"a":1} trailing"#).is_none());
    }

    #[test]
    fn structural_equality_follows_pulse_rules() {
        assert!(terms_equal(&json!({"a": 0}), &json!({"a": -0})));
        assert!(!terms_equal(&json!({"a": true}), &json!({"a": 1})));
        assert!(!terms_equal(&json!([1, 2]), &json!([2, 1])));
        assert!(!terms_equal(&json!({"a": 1}), &json!({"a": 1, "b": 2})));
        assert!(!terms_equal(&json!({"a": 1.5}), &json!({"a": 1.5})));
        assert!(terms_equal(
            &serde_json::from_str::<Value>(r#"{"b":[1,{"c":"x"}],"a":null}"#).unwrap(),
            &json!({"a": null, "b": [1, {"c": "x"}]})
        ));
    }

    #[test]
    fn safe_integer_rejects_out_of_range() {
        assert_eq!(
            safe_integer(&json!(MAX_SAFE_INTEGER)),
            Some(MAX_SAFE_INTEGER)
        );
        assert_eq!(safe_integer(&json!(9_007_199_254_740_992_i64)), None);
        assert_eq!(safe_integer(&json!(2.0)), None);
    }
}
