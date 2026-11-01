//! Reject duplicate fields at every nesting level before typed deserialization.
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};
use std::fmt;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Values;
        impl<'de> Visitor<'de> for Values {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Strict, E> {
                Number::from_f64(value)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON field"));
                    }
                    let Strict(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Values)
    }
}
pub(crate) fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, serde_json::Error> {
    let Strict(value) = serde_json::from_slice(bytes)?;
    serde_json::from_value(value)
}
