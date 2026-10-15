//! Bounded source JSON decoding. Duplicate keys must not disappear into Value.

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

// The complete canonical inventory now exceeds 4 MiB. Keep a finite envelope
// bound; value count, depth, string size and lowering budgets remain independent.
pub(super) const MAX_SOURCE_BYTES: usize = 8 * 1024 * 1024;
const MAX_VALUES: usize = 1_000_000;
// Inline matcher trees add object/array syntax levels around each matcher.
// Matcher depth itself is independently limited to 32 during lowering.
const MAX_JSON_DEPTH: usize = 96;
const MAX_OBJECT_MEMBERS: usize = 4_096;
// A compiled program keys every lowered matcher node in one object, and
// program admission accepts up to 16,384 nodes. Requests that embed a whole
// packaged program (offline parity) must decode that same envelope.
pub(super) const MAX_PROGRAM_OBJECT_MEMBERS: usize = 16_384;

pub(super) fn decode(bytes: &[u8]) -> Result<Value, &'static str> {
    decode_with_object_members(bytes, MAX_OBJECT_MEMBERS)
}

pub(super) fn decode_with_object_members(
    bytes: &[u8],
    max_object_members: usize,
) -> Result<Value, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_SOURCE_BYTES {
        return Err("command_source_bytes_invalid");
    }
    let mut remaining = MAX_VALUES;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        remaining: &mut remaining,
        depth: 0,
        max_object_members,
    }
    .deserialize(&mut decoder)
    .map_err(|_| "command_source_json_invalid")?;
    decoder.end().map_err(|_| "command_source_json_invalid")?;
    // A source program must be a JSON object. Under serde_json
    // `arbitrary_precision`, a bare number decodes through the private
    // `$serde_json::private::Number` marker map and `is_object()` reports true;
    // reject that marker shape too so scalars and ambiguous top-levels are
    // refused regardless of numeric encoding.
    let is_number_marker = value
        .as_object()
        .map(|map| map.len() == 1 && map.contains_key("$serde_json::private::Number"))
        .unwrap_or(false);
    if !value.is_object() || is_number_marker {
        return Err("command_source_json_invalid");
    }
    Ok(value)
}

struct Seed<'a> {
    remaining: &'a mut usize,
    depth: usize,
    max_object_members: usize,
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
            max_object_members: self.max_object_members,
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
            // arbitrary_precision routes unsupported numbers through a private
            // marker map, even when nested. Never admit that as source data.
            if key == "$serde_json::private::Number" {
                return Err(A::Error::custom("source_integer_limit"));
            }
            if key.len() > 4_096
                || values.len() >= self.max_object_members
                || values.contains_key(&key)
            {
                return Err(A::Error::custom("source_duplicate_key_or_items_limit"));
            }
            let value = mapping.next_value_seed(Seed {
                remaining: self.remaining,
                depth: self.depth + 1,
                max_object_members: self.max_object_members,
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
            r#"{"limit":18446744073709551616}"#,
            r#"{"limit":-9223372036854775809}"#,
            r#"{"values":[1,1.0]}"#,
            r#"{"nested":{"$serde_json::private::Number":"1"}}"#,
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
    fn program_envelopes_admit_wide_node_maps_but_sources_do_not() {
        let members = |count: usize| {
            let fields: Vec<String> = (0..count).map(|index| format!("\"n{index}\":0")).collect();
            format!("{{\"nodes\":{{{}}}}}", fields.join(","))
        };
        let wide = members(MAX_OBJECT_MEMBERS + 1);
        assert!(decode(wide.as_bytes()).is_err());
        assert!(decode_with_object_members(wide.as_bytes(), MAX_PROGRAM_OBJECT_MEMBERS).is_ok());
        let too_wide = members(MAX_PROGRAM_OBJECT_MEMBERS + 1);
        assert!(
            decode_with_object_members(too_wide.as_bytes(), MAX_PROGRAM_OBJECT_MEMBERS).is_err()
        );
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
