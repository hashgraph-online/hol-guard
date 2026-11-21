//! `json.loads(..., object_pairs_hook=_unique_object)`: a strict JSON parse
//! that rejects a duplicate object key instead of letting the last one win.
//!
//! Guard reads manifests an attacker may have written, where two keys of the
//! same name let one reader see what the other does not. Callers map the
//! failure into whatever reason their own contract publishes.

use serde::de::{Deserialize, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Why a strict parse refused the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictJsonError {
    /// Two entries of one object carried the same key.
    DuplicateKey,
    /// Nesting beyond what the parser will walk.
    DepthLimit,
    /// Anything else the JSON grammar refuses.
    Syntax,
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
                Ok(Value::from(v))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
                Ok(Value::from(v))
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
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<UniqueJson>()? {
                    items.push(item.0);
                }
                Ok(Value::Array(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut object = Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
                    if object.contains_key(&key) {
                        return Err(A::Error::custom("duplicate_key"));
                    }
                    object.insert(key, value.0);
                }
                Ok(Value::Object(object))
            }
        }
        deserializer.deserialize_any(UniqueVisitor).map(UniqueJson)
    }
}

/// Parse `text` as JSON, refusing a repeated object key.
pub fn parse_unique_json(text: &str) -> Result<Value, StrictJsonError> {
    serde_json::from_str::<UniqueJson>(text)
        .map(|value| value.0)
        .map_err(|error| {
            let message = error.to_string();
            if message.starts_with("duplicate_key") {
                StrictJsonError::DuplicateKey
            } else if message.contains("recursion limit") {
                StrictJsonError::DepthLimit
            } else {
                StrictJsonError::Syntax
            }
        })
}
