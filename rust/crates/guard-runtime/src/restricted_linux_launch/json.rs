//! Duplicate-key rejection for large bounded inode indexes.
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::fmt;

struct Unique(Value);
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a unique Linux plan JSON value")
    }
    fn visit_bool<E: Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(Value::Bool(v)))
    }
    fn visit_unit<E: Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_i64<E: Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(v.into())))
    }
    fn visit_u64<E: Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(Value::Number(v.into())))
    }
    fn visit_f64<E: Error>(self, v: f64) -> Result<Unique, E> {
        Number::from_f64(v)
            .map(|v| Unique(Value::Number(v)))
            .ok_or_else(|| E::custom("Invalid Linux JSON number."))
    }
    fn visit_str<E: Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(Value::String(v.to_owned())))
    }
    fn visit_string<E: Error>(self, v: String) -> Result<Unique, E> {
        Ok(Unique(Value::String(v)))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Unique, A::Error> {
        let mut items = Vec::new();
        while let Some(Unique(value)) = sequence.next_element()? {
            if items.len() >= 250_000 {
                return Err(A::Error::custom("Linux plan exceeds its boundary."));
            }
            items.push(value);
        }
        Ok(Unique(Value::Array(items)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Unique, A::Error> {
        let mut items = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if items.contains_key(&key) {
                return Err(A::Error::custom("Duplicate Linux plan field."));
            }
            if items.len() >= 250_000 {
                return Err(A::Error::custom("Linux plan exceeds its boundary."));
            }
            let Unique(value) = object.next_value()?;
            items.insert(key, value);
        }
        Ok(Unique(Value::Object(items)))
    }
}
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

pub(super) fn parse(bytes: &[u8]) -> super::plan::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let Unique(value) = Unique::deserialize(&mut deserializer)
        .map_err(|_| "Invalid or duplicate Linux plan JSON.")?;
    deserializer.end().map_err(|_| "Invalid Linux plan JSON.")?;
    Ok(value)
}
