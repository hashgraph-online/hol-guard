//! Order-preserving JSON value used by the hook adapter port.
//!
//! The resident protocol parses frames into key-sorted `serde_json::Value`s,
//! but the adapter output (`raw_payload_redacted`, prepared payloads) keeps the
//! host payload's key order, and Python truthiness / dict semantics decide
//! several branches. `OValue` keeps insertion order, preserves Python number
//! spelling (ints as digit tokens, floats as `repr` tokens), and carries the
//! CPython-compatible helpers the port needs.
//!
//! Wire form (order preserving over the sorted-object frame parser): a dict is
//! `["d", key1, value1, ...]`, a list is `["l", item, ...]`, scalars are raw.

use guard_contracts::{python_float_repr, write_json_string};
use serde_json::{Number, Value};

/// Insertion-ordered string-keyed map with Python dict assignment semantics.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OMap {
    entries: Vec<(String, OValue)>,
}

/// One JSON value with Python-faithful number spelling.
#[derive(Debug, Clone, PartialEq)]
pub enum OValue {
    Null,
    Bool(bool),
    /// Canonical integer digits (`-0` is normalized to `0`).
    Int(String),
    /// CPython `repr(float)` spelling of a finite float.
    Float(String),
    Str(String),
    List(Vec<OValue>),
    Map(OMap),
}

impl OMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&OValue> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// `dict[key] = value`: an existing key keeps its position.
    pub fn insert(&mut self, key: &str, value: OValue) {
        match self.entries.iter_mut().find(|(name, _)| name == key) {
            Some((_, slot)) => *slot = value,
            None => self.entries.push((key.to_owned(), value)),
        }
    }

    /// `dict.setdefault(key, value)`.
    pub fn set_default(&mut self, key: &str, value: OValue) {
        if !self.contains_key(key) {
            self.entries.push((key.to_owned(), value));
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &OValue)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Lookup that yields `None` for a missing key and for JSON `null`
    /// (`payload.get(key)` followed by an `is None` check).
    pub fn get_non_null(&self, key: &str) -> Option<&OValue> {
        self.get(key).filter(|value| !matches!(value, OValue::Null))
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(OValue::Str(text)) => Some(text),
            _ => None,
        }
    }
}

impl OValue {
    pub fn str(text: impl Into<String>) -> Self {
        Self::Str(text.into())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&OMap> {
        match self {
            Self::Map(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[OValue]> {
        match self {
            Self::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Python `bool(value)`.
    pub fn truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(flag) => *flag,
            Self::Int(digits) => digits != "0",
            Self::Float(text) => text != "0.0" && text != "-0.0",
            Self::Str(text) => !text.is_empty(),
            Self::List(items) => !items.is_empty(),
            Self::Map(map) => !map.is_empty(),
        }
    }

    /// `value in ({}, None)`.
    pub fn is_empty_dict_or_null(&self) -> bool {
        match self {
            Self::Null => true,
            Self::Map(map) => map.is_empty(),
            _ => false,
        }
    }

    /// Python `value.strip()` text when the value is a non-blank string.
    pub fn non_blank_str(&self) -> Option<&str> {
        self.as_str()
            .filter(|text| !crate::hook_adapter_pytext::py_strip(text).is_empty())
    }
}

pub(crate) fn canonical_int(token: &str) -> String {
    if token == "-0" {
        "0".to_owned()
    } else {
        token.to_owned()
    }
}

pub(crate) fn canonical_float(token: &str) -> Result<String, &'static str> {
    let value: f64 = token
        .parse()
        .map_err(|_| "native_hook_adapter_number_invalid")?;
    if !value.is_finite() {
        return Err("native_hook_adapter_number_unsupported");
    }
    Ok(python_float_repr(value))
}

impl OValue {
    /// Decode the tagged-array wire form.
    pub fn from_wire(value: &Value) -> Result<Self, &'static str> {
        match value {
            Value::Null => Ok(Self::Null),
            Value::Bool(flag) => Ok(Self::Bool(*flag)),
            Value::Number(number) => {
                let token = number.as_str();
                if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                    Ok(Self::Float(canonical_float(token)?))
                } else {
                    Ok(Self::Int(canonical_int(token)))
                }
            }
            Value::String(text) => Ok(Self::Str(text.clone())),
            Value::Array(items) => {
                let (tag, rest) = items
                    .split_first()
                    .ok_or("native_hook_adapter_wire_invalid")?;
                match tag.as_str() {
                    Some("l") => rest
                        .iter()
                        .map(Self::from_wire)
                        .collect::<Result<Vec<_>, _>>()
                        .map(Self::List),
                    Some("d") => {
                        if rest.len() % 2 != 0 {
                            return Err("native_hook_adapter_wire_invalid");
                        }
                        let mut map = OMap::new();
                        for pair in rest.chunks_exact(2) {
                            let key = pair[0].as_str().ok_or("native_hook_adapter_wire_invalid")?;
                            map.insert(key, Self::from_wire(&pair[1])?);
                        }
                        Ok(Self::Map(map))
                    }
                    _ => Err("native_hook_adapter_wire_invalid"),
                }
            }
            Value::Object(_) => Err("native_hook_adapter_wire_invalid"),
        }
    }

    /// Encode to the tagged-array wire form.
    pub fn to_wire(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(flag) => Value::Bool(*flag),
            Self::Int(token) | Self::Float(token) => token
                .parse::<Number>()
                .map(Value::Number)
                .unwrap_or(Value::Null),
            Self::Str(text) => Value::String(text.clone()),
            Self::List(items) => {
                let mut wire = Vec::with_capacity(items.len() + 1);
                wire.push(Value::String("l".to_owned()));
                wire.extend(items.iter().map(Self::to_wire));
                Value::Array(wire)
            }
            Self::Map(map) => {
                let mut wire = Vec::with_capacity(map.len() * 2 + 1);
                wire.push(Value::String("d".to_owned()));
                for (key, item) in map.iter() {
                    wire.push(Value::String(key.to_owned()));
                    wire.push(item.to_wire());
                }
                Value::Array(wire)
            }
        }
    }

    /// `json.dumps(value, sort_keys=True, separators=(",", ":"),
    /// ensure_ascii=True)` for finite values.
    pub fn canonical_json(&self) -> String {
        let mut out = Vec::new();
        self.write_json(&mut out, true);
        String::from_utf8(out).unwrap_or_default()
    }

    /// `json.dumps(value, separators=(",", ":"))` (insertion order,
    /// `ensure_ascii`) for finite values.
    pub fn compact_json(&self) -> String {
        let mut out = Vec::new();
        self.write_json(&mut out, false);
        String::from_utf8(out).unwrap_or_default()
    }

    fn write_json(&self, out: &mut Vec<u8>, sort: bool) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Bool(flag) => out.extend_from_slice(if *flag { b"true" } else { b"false" }),
            Self::Int(token) | Self::Float(token) => out.extend_from_slice(token.as_bytes()),
            Self::Str(text) => write_json_string(text, out),
            Self::List(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write_json(out, sort);
                }
                out.push(b']');
            }
            Self::Map(map) => {
                let mut sorted: Vec<(&str, &OValue)> = map.iter().collect();
                if sort {
                    sorted.sort_by(|left, right| left.0.cmp(right.0));
                }
                out.push(b'{');
                for (index, (key, item)) in sorted.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_json_string(key, out);
                    out.push(b':');
                    item.write_json(out, sort);
                }
                out.push(b'}');
            }
        }
    }
}

pub use crate::hook_adapter_pyjson::{parse_python_json, PyJsonError};
