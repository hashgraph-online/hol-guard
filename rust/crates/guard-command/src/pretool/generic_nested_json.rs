use super::*;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

#[derive(Clone, Copy)]
struct StrictNestedJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictNestedJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_PRE_TOOL_DEPTH {
            return Err(serde::de::Error::custom(
                "native_pre_tool_nested_depth_exceeded",
            ));
        }
        deserializer.deserialize_any(StrictNestedJsonVisitor { depth: self.depth })
    }
}

struct StrictNestedJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictNestedJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("native_pre_tool_nested_number_invalid"))
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
        if value.len() > MAX_COMMAND_BYTES {
            return Err(E::custom("native_pre_tool_nested_string_too_large"));
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
        StrictNestedJsonSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictNestedJsonSeed {
            depth: self.depth.saturating_add(1),
        })? {
            if output.len() >= MAX_PRE_TOOL_ARRAY_ITEMS {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_array_too_wide",
                ));
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
            if key.len() > MAX_COMMAND_BYTES {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_key_too_large",
                ));
            }
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_duplicate_key",
                ));
            }
            if output.len() >= MAX_NESTED_JSON_OBJECT_ITEMS {
                return Err(serde::de::Error::custom(
                    "native_pre_tool_nested_object_too_wide",
                ));
            }
            let value = object.next_value_seed(StrictNestedJsonSeed {
                depth: self.depth.saturating_add(1),
            })?;
            output.insert(key, value);
        }
        Ok(Value::Object(output))
    }
}

pub(crate) fn parse_strict_nested_json(bytes: &[u8]) -> Result<Value, GenericExtractionError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictNestedJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("duplicate_key") {
                GenericExtractionError::Ambiguous
            } else if message.contains("depth_exceeded")
                || message.contains("too_wide")
                || message.contains("too_large")
            {
                GenericExtractionError::Bounds
            } else {
                GenericExtractionError::Malformed
            }
        })?;
    deserializer
        .end()
        .map_err(|_| GenericExtractionError::Malformed)?;
    Ok(value)
}
