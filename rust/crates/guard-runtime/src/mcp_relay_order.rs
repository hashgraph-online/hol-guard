//! The key order of a `tools/call`'s `params.arguments` as the host sent it.
//!
//! `serde_json` maps sort their keys, but the proxy evaluates the arguments in
//! the order `json.loads` kept them, and the risk signals read them in that
//! order. The host line is walked once more for that path only, skipping
//! every other value. A duplicate key on the path, which `json.loads` would
//! fold differently from the decoded map, yields no order.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};

/// The keys of `params.arguments` in host order, or `None` when the line has
/// no such object or its path repeats a key.
pub(crate) fn argument_order(line: &[u8]) -> Option<Vec<String>> {
    let mut deserializer = serde_json::Deserializer::from_slice(line);
    let order = Level::Message.deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    order
}

#[derive(Clone, Copy)]
enum Level {
    Message,
    Params,
    Arguments,
}

impl<'de> DeserializeSeed<'de> for Level {
    type Value = Option<Vec<String>>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Level {
    type Value = Option<Vec<String>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        let mut keys = Vec::new();
        let mut found = None;
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate key"));
            }
            match (self, key.as_str()) {
                (Self::Message, "params") => found = map.next_value_seed(Self::Params)?,
                (Self::Params, "arguments") => found = map.next_value_seed(Self::Arguments)?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            if matches!(self, Self::Arguments) {
                keys.push(key);
            }
        }
        Ok(match self {
            Self::Arguments => Some(keys),
            Self::Message | Self::Params => found,
        })
    }
}

#[cfg(test)]
#[path = "mcp_relay_order_tests.rs"]
mod tests;
