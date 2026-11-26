//! Strict JSON for provider responses.
//!
//! A provider body is parsed with duplicate object keys refused at every depth, so a response
//! cannot carry two different answers under one pointer. Trailing bytes are refused and the body
//! must fit `MAX_BODY_BYTES`. The duplicate-key visitor follows `guard-yanez-pulse`'s
//! `strict_json::parse_no_duplicates`; it is copied rather than shared so this crate does not depend
//! on the Pulse crate. serde_json's own nesting limit still applies.
//!
//! Pointer reads are bounded: a pointer is at most `MAX_POINTER_SEGMENTS` RFC 6901 segments, and a
//! string read refuses values longer than the caller's cap.

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// The largest response body this crate parses, whatever the manifest allows.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The deepest JSON pointer a manifest may name.
pub const MAX_POINTER_SEGMENTS: usize = 16;

const ARBITRARY_PRECISION_TOKEN: &str = "$serde_json::private::Number";

/// Parse a response body, refusing duplicate keys at any depth, trailing bytes and oversize bodies.
pub fn parse_strict(bytes: &[u8]) -> Option<Value> {
    if bytes.len() > MAX_BODY_BYTES {
        return None;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictSeed.deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(value)
}

struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            // The workspace builds serde_json with `arbitrary_precision`, which hands every number
            // to `visit_map` under this token.
            if map.is_empty() && key == ARBITRARY_PRECISION_TOKEN {
                let text: String = access.next_value()?;
                return serde_json::from_str::<Number>(&text)
                    .map(Value::Number)
                    .map_err(|_| de::Error::custom("invalid number"));
            }
            if map.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let value = access.next_value_seed(StrictSeed)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element_seed(StrictSeed)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }
}

/// Whether `pointer` is an RFC 6901 pointer this crate will follow: empty (the whole document) or
/// up to `MAX_POINTER_SEGMENTS` segments, each with only `~0` and `~1` escapes.
pub fn is_bounded_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return false;
    };
    pointer.len() <= 256
        && rest.split('/').count() <= MAX_POINTER_SEGMENTS
        && rest.split('/').all(|segment| {
            let mut bytes = segment.bytes();
            while let Some(byte) = bytes.next() {
                if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
                    return false;
                }
            }
            true
        })
}

/// The value at `pointer`, or `None` when the pointer is unbounded or names nothing.
pub fn read_pointer<'a>(document: &'a Value, pointer: &str) -> Option<&'a Value> {
    if !is_bounded_pointer(pointer) {
        return None;
    }
    document.pointer(pointer)
}

/// The string at `pointer`, or `None` when it is absent, not a string, or longer than `max_bytes`.
pub fn read_string<'a>(document: &'a Value, pointer: &str, max_bytes: usize) -> Option<&'a str> {
    read_pointer(document, pointer)?
        .as_str()
        .filter(|text| text.len() <= max_bytes)
}

/// Up to `max_items` strings from the array at `pointer`. Non-string entries and strings longer
/// than `max_bytes` are skipped; `None` when the pointer names no array.
pub fn read_strings<'a>(
    document: &'a Value,
    pointer: &str,
    max_items: usize,
    max_bytes: usize,
) -> Option<Vec<&'a str>> {
    let items = read_pointer(document, pointer)?.as_array()?;
    Some(
        items
            .iter()
            .filter_map(Value::as_str)
            .filter(|text| text.len() <= max_bytes)
            .take(max_items)
            .collect(),
    )
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
