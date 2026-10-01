//! Bounded source JSON decoding. Duplicate keys must not disappear into Value.

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

pub(super) const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_VALUES: usize = 1_000_000;
// Inline matcher trees add object/array syntax levels around each matcher.
// Matcher depth itself is independently limited to 32 during lowering.
const MAX_JSON_DEPTH: usize = 96;

pub(super) fn decode(bytes: &[u8]) -> Result<Value, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err("command_source_bytes_invalid");
    }
    let mut remaining = MAX_VALUES;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        remaining: &mut remaining,
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| "command_source_json_invalid")?;
    decoder.end().map_err(|_| "command_source_json_invalid")?;
    Ok(value)
}

struct Seed<'a> {
    remaining: &'a mut usize,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > MAX_JSON_DEPTH || *self.remaining == 0 {
            return Err(D::Error::custom("source_work_or_depth_limit"));
        }
        *self.remaining -= 1;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded source JSON")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        if value > i64::MAX as u64 {
            return Err(E::custom("source_integer_limit"));
        }
        Ok(Value::from(value))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > 4_096 {
            return Err(E::custom("source_string_limit"));
        }
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        if value.len() > 4_096 {
            return Err(E::custom("source_string_limit"));
        }
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            remaining: self.remaining,
            depth: self.depth + 1,
        })? {
            if values.len() >= 4_096 {
                return Err(A::Error::custom("source_items_limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = mapping.next_key::<String>()? {
            if key.len() > 4_096 || values.len() >= 4_096 || values.contains_key(&key) {
                return Err(A::Error::custom("source_duplicate_key_or_items_limit"));
            }
            let value = mapping.next_value_seed(Seed {
                remaining: self.remaining,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_and_unbounded_source_json() {
        for input in [
            r#"{"op":"all.v1","op":"any.v1"}"#,
            r#"{"config":{"flag":true,"flag":false}}"#,
            "1.0",
            "9223372036854775808",
            "{} {}",
        ] {
            assert!(decode(input.as_bytes()).is_err(), "{input}");
        }
        assert!(decode(&vec![b' '; MAX_SOURCE_BYTES + 1]).is_err());
        let deep = format!("{}0{}", "[".repeat(97), "]".repeat(97));
        assert!(decode(deep.as_bytes()).is_err());
        let wide = format!("[{}]", vec!["0"; 4097].join(","));
        assert!(decode(wide.as_bytes()).is_err());
    }

    #[test]
    fn preserves_unicode_integer_and_ordered_array_values() {
        let value = decode("{\"z\": [\"ß\", \"İ\", -2, 1], \"a\":true}\r\n".as_bytes()).unwrap();
        assert_eq!(value["z"], serde_json::json!(["ß", "İ", -2, 1]));
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            "{\"a\":true,\"z\":[\"ß\",\"İ\",-2,1]}"
        );
    }
}
