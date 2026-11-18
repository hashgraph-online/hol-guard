//! What an observer accepts of one hook launch: the observation line a
//! modern package writes to stderr, the verdict the hook and its receipt must
//! agree on, and the digests the admission evidence carries.
//!
//! Ported from `_probe_observation`, `transition_hook_observation`, the
//! protection checks of `_observe_configured_codex_hook` and `_digest`.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::cloud_request_text::py_strip;
use crate::native_decision_receipt::{dumps_sorted, valid};
use crate::pyjson::{self, PyVal};

pub(super) const OBSERVATION_SCHEMA: &str = "hol-guard.transition-hook-observation.v1";
pub(super) const PROBE_SCHEMA: &str = "hol-guard.transition-hook-probe.v1";
pub(super) const PROBE_FIELD: &str = "guard_transition_probe";

/// The characters `str.splitlines` ends a line at.
fn line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r'
            | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// `_probe_observation`: the observation line the hook wrote among the
/// runtime's own diagnostics. Naming the line by its schema only finds it;
/// the caller still rebuilds it from the probe and the receipt it carries.
fn probe_observation(stderr: &str) -> Option<PyVal> {
    for line in stderr.split(line_break).rev() {
        let candidate = py_strip(line);
        if !candidate.starts_with('{') || !candidate.contains(OBSERVATION_SCHEMA) {
            continue;
        }
        let Ok(parsed) = pyjson::parse(candidate) else {
            continue;
        };
        if parsed.get("schema").and_then(PyVal::as_str) == Some(OBSERVATION_SCHEMA) {
            return Some(parsed);
        }
    }
    None
}

fn text<'a>(value: &'a PyVal, key: &str) -> Option<&'a str> {
    value.get(key).and_then(PyVal::as_str)
}

/// `transition_hook_observation` for the probe this observer sent, and the
/// comparison of its result with the line the hook wrote: the one receipt that
/// line carries, when the runtime accepts it as the record of this probe.
pub(super) fn modern_receipt(stderr: &str, operation_id: &str, request_id: &str) -> Option<Value> {
    let observation = probe_observation(stderr)?;
    let entries = observation.as_dict()?;
    if entries.len() != 4
        || text(&observation, "operation_id") != Some(operation_id)
        || text(&observation, "request_id") != Some(request_id)
    {
        return None;
    }
    let receipt = observation.get("native_receipt")?;
    if !valid(receipt) {
        return None;
    }
    let harness = text(receipt, "harness")?;
    if text(receipt, "request_id") != Some(request_id)
        || text(receipt, "event_name") != Some("PreToolUse")
        || !matches!(harness, "codex" | "omp")
        || text(receipt, "payload_kind") != Some("inline")
        || !matches!(receipt.get("observe_mode"), Some(PyVal::Bool(false)))
    {
        return None;
    }
    receipt.to_json()
}

/// Whether the hook's output and the receipt both show the expected
/// `decision` under the runtime the admission is for.
pub(super) fn protects(
    receipt: &Value,
    output: &Value,
    decision: &str,
    runtime_sha256: &str,
) -> bool {
    let text = |key: &str| receipt.get(key).and_then(Value::as_str);
    if text("decision") != Some(decision) || text("runtime_identity") != Some(runtime_sha256) {
        return false;
    }
    let permission = match output.get("hookSpecificOutput") {
        Some(Value::Object(specific)) => specific.get("permissionDecision"),
        _ => None,
    };
    let permission = match permission {
        None | Some(Value::Null) => None,
        Some(other) => Some(other),
    };
    if decision == "allow" {
        output.get("continue") != Some(&Value::Bool(false))
            && matches!(text("policy_action"), Some("allow" | "warn"))
            && permission.is_none_or(|value| value.as_str() == Some("allow"))
    } else {
        permission.and_then(Value::as_str) == Some("deny")
    }
}

/// `_digest`: SHA-256 of the canonical compact JSON of `value`.
pub(super) fn digest(value: &PyVal) -> String {
    hex::encode(Sha256::digest(dumps_sorted(value, true).as_bytes()))
}

pub(super) fn strings(items: &[String]) -> PyVal {
    PyVal::List(items.iter().cloned().map(PyVal::Str).collect())
}

pub(super) fn mapping<'a>(items: impl Iterator<Item = (&'a String, &'a String)>) -> PyVal {
    PyVal::Dict(
        items
            .map(|(key, value)| (key.clone(), PyVal::Str(value.clone())))
            .collect(),
    )
}

/// `str(uuid.UUID(value)) == value`: the lowercase, hyphenated spelling.
pub(super) fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                matches!(character, '0'..='9' | 'a'..='f')
            }
        })
}
