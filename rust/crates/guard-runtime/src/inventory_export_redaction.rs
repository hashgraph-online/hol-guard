//! `inventory_export_redaction` runner-authority kind: the serializer half of
//! the inventory export's redaction (`_safe_json` and
//! `_assert_serialized_inventory_payload_safe` in
//! `inventory_contract_redaction`, before they moved here).
//!
//! Every exported inventory snapshot and every AIBOM metadata extension passes
//! through this net, so a private path, credential value or secret assignment
//! that an earlier stage missed is masked before it leaves the machine.
//! `guard_command::inventory_redaction` already owned the string rules, pinned
//! against CPython by `testdata/inventory_redaction_parity.json`; this module
//! walks the caller's value with them.
//!
//! Values travel as JSON text so the parse keeps their key order: the export
//! keeps the order its producer wrote. Three operations are served:
//!
//! * `{"op": "safe_json", "value": <JSON text>, "parent_key": str,
//!   "parent_sensitive": bool}` answers `{"value": <JSON text>}`, the value
//!   with every string and key passed through the serializer rules.
//! * `{"op": "assert_payload_safe", "payload": <JSON text>}` answers
//!   `{"safe": bool}`, whether `json.dumps(payload, sort_keys=True)` text is
//!   free of private paths, credential values and secret assignments.
//! * `{"op": "item_description", ...}` answers `{"description": str}`, an
//!   inventory item's exported description (see `inventory_item_description`).
//! * `{"op": "artifact_metadata", ...}` answers `{"metadata": [<JSON text>]}`,
//!   the metadata each artifact exports (see `inventory_artifact_metadata`).

use std::collections::HashMap;

use guard_command::inventory_redaction::{
    encoded_payload_is_safe, matches_sensitive_key, sanitize_serializer_string,
};
use serde_json::{json, Map, Value};

use crate::hook_env_stamp::{dumps, float_text, write_string};
use crate::pyjson::{self, in_surrogate_plane, PyVal};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

#[path = "inventory_artifact_metadata.rs"]
mod artifact_metadata;
#[path = "inventory_item_description.rs"]
mod item_description;

const SAFE_JSON_KEYS: [&str; 4] = ["op", "value", "parent_key", "parent_sensitive"];
const ASSERT_KEYS: [&str; 2] = ["op", "payload"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    match fields.get("op").and_then(Value::as_str) {
        Some("safe_json") => {
            exact_keys(fields, &SAFE_JSON_KEYS)?;
            let (value, mapped) = parse(text(fields, "value")?)?;
            let parent_key = text(fields, "parent_key")?;
            let parent_sensitive = fields
                .get("parent_sensitive")
                .and_then(Value::as_bool)
                .ok_or(ERR_INVALID)?;
            let mut answer = String::new();
            dumps(
                &safe_json(&value, parent_key, parent_sensitive),
                false,
                mapped,
                &mut answer,
            );
            Ok(json!({ "value": answer }))
        }
        Some("assert_payload_safe") => {
            exact_keys(fields, &ASSERT_KEYS)?;
            let (payload, mapped) = parse(text(fields, "payload")?)?;
            let mut encoded = String::new();
            dumps_sorted_spaced(&payload, mapped, &mut encoded);
            Ok(json!({ "safe": encoded_payload_is_safe(&encoded) }))
        }
        Some("item_description") => item_description::dispatch(fields),
        Some("artifact_metadata") => artifact_metadata::dispatch(fields),
        _ => Err(ERR_INVALID),
    }
}

fn exact_keys(fields: &Map<String, Value>, keys: &[&str]) -> Result<(), &'static str> {
    if fields.len() != keys.len() || !keys.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    Ok(())
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// The value, and whether a lone surrogate was mapped into the stand-in range.
/// Without one, every private-use character in that range is genuine and
/// travels as itself; with one, a genuine character there could not be told
/// apart from a stand-in, so the request is refused.
fn parse(text: &str) -> Result<(PyVal, bool), &'static str> {
    let parsed = pyjson::parse_mapping_lone_surrogates(text).map_err(|_| ERR_INVALID)?;
    if parsed.mapped && parsed.collision {
        return Err(ERR_INVALID);
    }
    Ok((parsed.value, parsed.mapped))
}

/// `_safe_json(value, *, parent_key="", parent_sensitive=False)`.
///
/// Two keys that redact to the same text collapse the way the Python dict
/// comprehension does: the first key keeps its place, the later value wins.
fn safe_json(value: &PyVal, parent_key: &str, parent_sensitive: bool) -> PyVal {
    match value {
        PyVal::Dict(entries) => {
            let key_sensitive =
                parent_sensitive || (!parent_key.is_empty() && matches_sensitive_key(parent_key));
            let mut projected: Vec<(String, PyVal)> = Vec::with_capacity(entries.len());
            let mut places: HashMap<String, usize> = HashMap::with_capacity(entries.len());
            for (key, item) in entries {
                let redacted = sanitize_serializer_string(key, "", false);
                let value = safe_json(item, key, key_sensitive);
                match places.get(&redacted) {
                    Some(&place) => projected[place].1 = value,
                    None => {
                        places.insert(redacted.clone(), projected.len());
                        projected.push((redacted, value));
                    }
                }
            }
            PyVal::Dict(projected)
        }
        PyVal::List(items) => PyVal::List(
            items
                .iter()
                .map(|item| safe_json(item, parent_key, parent_sensitive))
                .collect(),
        ),
        PyVal::Str(text) => PyVal::Str(sanitize_serializer_string(
            text,
            parent_key,
            parent_sensitive,
        )),
        other => other.clone(),
    }
}

/// `json.dumps(value, sort_keys=True)`: `", "` and `": "` separators, every
/// non-ASCII character escaped, keys in code point order with a lone
/// surrogate sorting where CPython puts it.
fn dumps_sorted_spaced(value: &PyVal, mapped: bool, out: &mut String) {
    match value {
        PyVal::Null => out.push_str("null"),
        PyVal::Bool(true) => out.push_str("true"),
        PyVal::Bool(false) => out.push_str("false"),
        PyVal::Int(digits) => out.push_str(digits),
        PyVal::Float(number) => out.push_str(&float_text(*number)),
        PyVal::Str(text) => write_string(text, true, mapped, out),
        PyVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                dumps_sorted_spaced(item, mapped, out);
            }
            out.push(']');
        }
        PyVal::Dict(entries) => {
            let mut ordered: Vec<&(String, PyVal)> = entries.iter().collect();
            ordered.sort_by(|left, right| {
                code_points(&left.0, mapped).cmp(code_points(&right.0, mapped))
            });
            out.push('{');
            for (index, (key, item)) in ordered.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_string(key, true, mapped, out);
                out.push_str(": ");
                dumps_sorted_spaced(item, mapped, out);
            }
            out.push('}');
        }
    }
}

/// A key's code points, with a mapped lone surrogate back at its own value.
fn code_points(key: &str, mapped: bool) -> impl Iterator<Item = u32> + '_ {
    key.chars().map(move |character| {
        if mapped && in_surrogate_plane(character) {
            character as u32 - pyjson::SURROGATE_PLANE_BASE + 0xd800
        } else {
            character as u32
        }
    })
}

#[cfg(test)]
#[path = "inventory_export_redaction_tests.rs"]
mod tests;
