//! Strict JSON with original pair order and numeric spelling preserved.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use serde_json::{Map, Value};

#[derive(Debug)]
pub(super) enum Node {
    Object(Vec<(String, Node)>),
    Array,
    Scalar(Value),
}

struct Pairs(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Pairs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PairsVisitor;
        impl<'de> Visitor<'de> for PairsVisitor {
            type Value = Pairs;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON object without duplicate fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Pairs, A::Error> {
                let mut seen = BTreeSet::new();
                let mut pairs = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                    pairs.push((key, value));
                }
                Ok(Pairs(pairs))
            }
        }
        deserializer.deserialize_map(PairsVisitor)
    }
}

pub(super) fn parse(text: &str) -> Result<Node, ()> {
    parse_at(text, 0)
}

fn parse_at(text: &str, depth: usize) -> Result<Node, ()> {
    if depth > 128 {
        return Err(());
    }
    let text = text.trim();
    match text.as_bytes().first() {
        Some(b'{') => {
            let pairs: Pairs = serde_json::from_str(text).map_err(|_| ())?;
            Ok(Node::Object(
                pairs
                    .0
                    .into_iter()
                    .map(|(key, raw)| Ok((key, parse_at(raw.get(), depth + 1)?)))
                    .collect::<Result<_, ()>>()?,
            ))
        }
        Some(b'[') => {
            let raw: Vec<Box<RawValue>> = serde_json::from_str(text).map_err(|_| ())?;
            for item in raw {
                parse_at(item.get(), depth + 1)?;
            }
            Ok(Node::Array)
        }
        _ => Ok(Node::Scalar(serde_json::from_str(text).map_err(|_| ())?)),
    }
}

pub(super) fn canonical(node: &Node) -> Option<Value> {
    match node {
        Node::Object(pairs) => {
            let map = pairs
                .iter()
                .map(|(key, node)| Some((key.clone(), canonical(node)?)))
                .collect::<Option<Map<_, _>>>()?;
            Some(Value::Object(map))
        }
        Node::Array => None,
        Node::Scalar(Value::Number(number)) => {
            let spelling = number.to_string();
            if spelling.contains(['.', 'e', 'E']) {
                return None;
            }
            let value = spelling.parse::<i64>().ok()?;
            if value.unsigned_abs() > 9_007_199_254_740_991 {
                return None;
            }
            Some(Value::Number(value.into()))
        }
        Node::Scalar(value) => Some(value.clone()),
    }
}
