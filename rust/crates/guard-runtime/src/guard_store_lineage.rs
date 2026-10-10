//! Retry-lineage preservation for operation updates: the first valid lineage
//! recorded on an operation survives later metadata writes. A lineage is valid
//! only when its content digest matches, so a tampered record is dropped.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::{dumps_sorted, py_strip};

const LINEAGE_KEYS: [&str; 14] = [
    "version",
    "source",
    "harness",
    "session_id",
    "thread_id",
    "tool_call_id",
    "turn_id",
    "invocation_id",
    "provider_request_id",
    "original_request_id",
    "workspace_sha256",
    "device_sha256",
    "action_sha256",
    "lineage_id",
];
const PROVIDER_KEYS: [&str; 5] = [
    "session_id",
    "thread_id",
    "tool_call_id",
    "turn_id",
    "invocation_id",
];
const MAX_IDENTIFIER_CHARS: usize = 256;
const HEX_DIGEST_CHARS: usize = 64;

/// The `metadata_json` to persist when `requested_json` updates an operation
/// whose stored metadata is `existing_json`. Malformed or non-object stored
/// metadata carries no lineage and leaves the request untouched.
pub(crate) fn persisted_metadata(existing_json: &str, requested_json: &str) -> StoreResult<String> {
    let Ok(Value::Object(existing)) = serde_json::from_str::<Value>(existing_json) else {
        return Ok(requested_json.to_owned());
    };
    let Some(lineage) = existing.get("retry_lineage") else {
        return Ok(requested_json.to_owned());
    };
    if !valid_lineage(lineage) {
        return Ok(requested_json.to_owned());
    }
    let Ok(Value::Object(mut merged)) = serde_json::from_str::<Value>(requested_json) else {
        return Err(StoreError::Invalid("native_guard_store_args_invalid"));
    };
    merged.insert("retry_lineage".to_owned(), lineage.clone());
    dumps_sorted(&Value::Object(merged))
        .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))
}

fn identifier(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    let invalid = text.is_empty()
        || text != py_strip(text)
        || text.chars().count() > MAX_IDENTIFIER_CHARS
        || text
            .chars()
            .any(|character| (character as u32) < 0x20 || character as u32 == 0x7f);
    (!invalid).then_some(text)
}

fn is_hex_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.chars().count() == HEX_DIGEST_CHARS
            && text
                .chars()
                .all(|character| matches!(character, '0'..='9' | 'a'..='f'))
    })
}

fn valid_lineage(value: &Value) -> bool {
    let Some(lineage) = value.as_object() else {
        return false;
    };
    if lineage
        .keys()
        .any(|key| !LINEAGE_KEYS.contains(&key.as_str()))
    {
        return false;
    }
    let version_ok = lineage
        .get("version")
        .is_some_and(|version| version.as_i64() == Some(1) || version.as_u64() == Some(1));
    let source_ok = lineage.get("source").and_then(Value::as_str) == Some("hook");
    let harness_ok = lineage.get("harness").and_then(identifier).is_some();
    let has_provider_key = PROVIDER_KEYS.iter().any(|key| lineage.contains_key(*key));
    if !(version_ok && source_ok && harness_ok && has_provider_key) {
        return false;
    }
    let identifiers_ok = PROVIDER_KEYS
        .iter()
        .chain(["provider_request_id", "original_request_id"].iter())
        .all(|key| {
            lineage
                .get(*key)
                .is_none_or(|item| identifier(item).is_some())
        });
    let digests_ok = ["workspace_sha256", "device_sha256", "action_sha256"]
        .iter()
        .all(|key| lineage.get(*key).is_none_or(is_hex_digest));
    let Some(lineage_id) = lineage.get("lineage_id") else {
        return false;
    };
    if !identifiers_ok || !digests_ok || !is_hex_digest(lineage_id) {
        return false;
    }
    let unsigned: Map<String, Value> = lineage
        .iter()
        .filter(|(key, _)| key.as_str() != "lineage_id")
        .map(|(key, item)| (key.clone(), item.clone()))
        .collect();
    lineage_id.as_str() == Some(digest(&unsigned).as_str())
}

/// SHA-256 of `json.dumps(value, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=False)`. Validated lineage values are strings plus the
/// integer version, so only string escaping needs spelling out.
fn digest(map: &Map<String, Value>) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in map.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_string(&mut out, key);
        out.push(':');
        match value {
            Value::String(text) => push_string(&mut out, text),
            other => out.push_str(&other.to_string()),
        }
    }
    out.push('}');
    hex::encode(Sha256::digest(out.as_bytes()))
}

fn push_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
