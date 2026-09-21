#![forbid(unsafe_code)]

use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::HashSet;
use std::fmt;

const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_COLLECTION_ITEMS: usize = 4_096;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy)]
struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(serde::de::Error::custom("native_json_depth_exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("native_json_number_invalid"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_JSON_STRING_BYTES {
            return Err(E::custom("native_json_string_too_large"));
        }
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJsonSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed {
            depth: self.depth + 1,
        })? {
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_array_too_wide"));
            }
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if key.len() > MAX_JSON_STRING_BYTES {
                return Err(serde::de::Error::custom("native_json_key_too_large"));
            }
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom("native_json_duplicate_key"));
            }
            if output.len() >= MAX_JSON_COLLECTION_ITEMS {
                return Err(serde::de::Error::custom("native_json_object_too_wide"));
            }
            let value = object.next_value_seed(StrictJsonSeed {
                depth: self.depth + 1,
            })?;
            output.insert(key, value);
        }
        Ok(Value::Object(output))
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| "native_request_invalid_json".to_owned())?;
    deserializer
        .end()
        .map_err(|_| "native_request_trailing_json".to_owned())?;
    Ok(value)
}

#[cfg(test)]
pub(crate) const TEST_MAX_JSON_DEPTH: usize = MAX_JSON_DEPTH;

#[cfg(test)]
pub(crate) const TEST_MAX_JSON_COLLECTION_ITEMS: usize = MAX_JSON_COLLECTION_ITEMS;
