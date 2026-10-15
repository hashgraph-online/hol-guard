//! Structural validation for the complete-or-fail lockfile parser: duplicate
//! key rejection, node/depth/entry bounds and per-format shape checks.

use std::time::Instant;

use serde::de::{Deserialize, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};

use super::lockfile_parse::{reason, within, Reason, LOCKFILE_MAX_DEPTH, LOCKFILE_MAX_NODES};
use super::*;
use crate::jsonc::{loads_jsonc_pairs_checked, JsoncError, JsoncPairs};
use crate::package_manifest_diff::py_splitlines;

/// `json.loads(..., object_pairs_hook=_unique_object)`: duplicate keys fail.
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

fn parse_unique_json(text: &str) -> Result<Value, Reason> {
    let source = if text.is_empty() { "{}" } else { text };
    serde_json::from_str::<UniqueJson>(source)
        .map(|value| value.0)
        .map_err(|error| {
            let message = error.to_string();
            if message.starts_with("duplicate_key") {
                reason("duplicate_key")
            } else if message.contains("recursion limit") {
                reason("depth_limit_exceeded")
            } else {
                reason("syntax_error")
            }
        })
}

fn pairs_to_value(pairs: &JsoncPairs, depth: usize) -> Result<Value, Reason> {
    if depth > LOCKFILE_MAX_DEPTH {
        return Err(reason("depth_limit_exceeded"));
    }
    Ok(match pairs {
        JsoncPairs::Null => Value::Null,
        JsoncPairs::Bool(value) => Value::Bool(*value),
        JsoncPairs::Number(value) => {
            if value.fract() == 0.0 && value.abs() < 9.0e15 {
                Value::from(*value as i64)
            } else {
                Value::from(*value)
            }
        }
        JsoncPairs::String(value) => Value::String(value.clone()),
        JsoncPairs::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| pairs_to_value(item, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        JsoncPairs::Object(entries) => {
            let mut object = Map::new();
            for (key, value) in entries {
                if object.contains_key(key) {
                    return Err(reason("duplicate_key"));
                }
                object.insert(key.clone(), pairs_to_value(value, depth + 1)?);
            }
            Value::Object(object)
        }
    })
}

fn validate_object_bounds(payload: &Value, deadline: Instant) -> Result<(), Reason> {
    let mut stack: Vec<(&Value, usize)> = vec![(payload, 0)];
    let mut visited = 0usize;
    while let Some((value, depth)) = stack.pop() {
        within(deadline)?;
        visited += 1;
        if visited > LOCKFILE_MAX_NODES {
            return Err(reason("node_limit_exceeded"));
        }
        if depth > LOCKFILE_MAX_DEPTH {
            return Err(reason("depth_limit_exceeded"));
        }
        match value {
            Value::Object(map) => stack.extend(map.values().map(|item| (item, depth + 1))),
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn validate_structure(name: &str, text: &str, deadline: Instant) -> Result<(), Reason> {
    match name {
        "package-lock.json" | "composer.lock" | "pipfile.lock" => {
            let payload = parse_unique_json(text)?;
            validate_object_bounds(&payload, deadline)?;
            let Value::Object(object) = &payload else {
                return Err(reason("unsupported_shape"));
            };
            match name {
                "package-lock.json" => {
                    validate_lock_version(object, &[1.0, 2.0, 3.0])?;
                    validate_optional_mappings(object, &["packages", "dependencies"])
                }
                "composer.lock" => validate_optional_lists(object, &["packages", "packages-dev"]),
                _ => validate_optional_mappings(object, &["default", "develop"]),
            }
        }
        "bun.lock" => {
            let source = if text.is_empty() { "{}" } else { text };
            let pairs = loads_jsonc_pairs_checked(source, &mut || {
                within(deadline).map_err(|_| JsoncError::Deadline("deadline_exceeded".to_owned()))
            })
            .map_err(|error| match error {
                JsoncError::Deadline(_) => reason("deadline_exceeded"),
                JsoncError::Decode(_) => reason("syntax_error"),
            })?;
            let payload = pairs_to_value(&pairs, 0)?;
            validate_object_bounds(&payload, deadline)?;
            let Value::Object(object) = &payload else {
                return Err(reason("unsupported_shape"));
            };
            validate_lock_version(object, &[0.0, 1.0, 2.0])?;
            validate_optional_mappings(object, &["workspaces", "packages"])
        }
        "cargo.lock" | "poetry.lock" | "uv.lock" => {
            let table: toml::Table = toml::from_str(text).map_err(|_| reason("syntax_error"))?;
            let payload = serde_json::to_value(&table).map_err(|_| reason("parse_error"))?;
            validate_object_bounds(&payload, deadline)?;
            match table.get("package") {
                None | Some(toml::Value::Array(_)) => Ok(()),
                Some(_) => Err(reason("unsupported_shape")),
            }
        }
        _ => validate_text_lockfile(name, text, deadline),
    }
}

fn validate_lock_version(object: &Map<String, Value>, allowed: &[f64]) -> Result<(), Reason> {
    match object.get("lockfileVersion") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Number(number))
            if number
                .as_f64()
                .is_some_and(|version| allowed.contains(&version)) =>
        {
            Ok(())
        }
        Some(_) => Err(reason("unsupported_version")),
    }
}

fn validate_optional_mappings(object: &Map<String, Value>, keys: &[&str]) -> Result<(), Reason> {
    for key in keys {
        if object.get(*key).is_some_and(|value| !value.is_object()) {
            return Err(reason("unsupported_shape"));
        }
    }
    Ok(())
}

fn validate_optional_lists(object: &Map<String, Value>, keys: &[&str]) -> Result<(), Reason> {
    for key in keys {
        if object.get(*key).is_some_and(|value| !value.is_array()) {
            return Err(reason("unsupported_shape"));
        }
    }
    Ok(())
}

fn validate_text_lockfile(name: &str, text: &str, deadline: Instant) -> Result<(), Reason> {
    let mut bracket_depth: i64 = 0;
    for raw_line in py_splitlines(text) {
        within(deadline)?;
        if raw_line.contains('\0') || (raw_line.contains('\t') && name == "pnpm-lock.yaml") {
            return Err(reason("syntax_error"));
        }
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let opens = raw_line.matches(['[', '{']).count() as i64;
        let closes = raw_line.matches([']', '}']).count() as i64;
        bracket_depth += opens - closes;
        if bracket_depth < 0 {
            return Err(reason("syntax_error"));
        }
        if name == "pnpm-lock.yaml" && !stripped.contains(':') && !stripped.starts_with('-') {
            return Err(reason("syntax_error"));
        }
        if name == "yarn.lock" && !raw_line.starts_with([' ', '\t']) && !stripped.ends_with(':') {
            return Err(reason("syntax_error"));
        }
    }
    if bracket_depth != 0 {
        return Err(reason("syntax_error"));
    }
    Ok(())
}
