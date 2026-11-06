//! Duplicate-safe metadata JSON with complete u64 epochs and decimal payloads.
//! Parse objects explicitly so serde's private arbitrary-precision number
//! representation cannot turn a literal user object into an identity integer.
use serde::de::{Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{value::RawValue, Map, Value};
use std::fmt;

struct Container {
    depth: usize,
}
impl<'de> Visitor<'de> for Container {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unique installed metadata container")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate metadata key"));
            }
            let raw: Box<RawValue> = map.next_value()?;
            let value = decode_value(raw.get(), self.depth + 1).map_err(A::Error::custom)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(raw) = sequence.next_element::<Box<RawValue>>()? {
            values.push(decode_value(raw.get(), self.depth + 1).map_err(A::Error::custom)?);
        }
        Ok(Value::Array(values))
    }
}

fn decode_value(text: &str, depth: usize) -> Result<Value, &'static str> {
    if depth > 128 {
        return Err("installed bundle metadata JSON depth invalid");
    }
    let mut decoder = serde_json::Deserializer::from_str(text);
    let result = match text.as_bytes().first() {
        Some(b'{') => decoder.deserialize_map(Container { depth }),
        Some(b'[') => decoder.deserialize_seq(Container { depth }),
        _ => {
            return serde_json::from_str(text).map_err(|_| "installed bundle metadata JSON invalid")
        }
    }
    .map_err(|_| "installed bundle metadata JSON invalid")?;
    decoder
        .end()
        .map_err(|_| "installed bundle metadata JSON invalid")?;
    Ok(result)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Value, &'static str> {
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err("installed bundle metadata bounds invalid");
    }
    let raw: Box<RawValue> =
        serde_json::from_slice(bytes).map_err(|_| "installed bundle metadata JSON invalid")?;
    decode_value(raw.get(), 0)
}
