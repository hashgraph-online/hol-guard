//! `receipt_embedded_scripts` runner-authority kind: the heredoc scripts a
//! receipt recorded, for `hol-guard history explain` (the reconstruction in
//! `commands_dispatch_records._embedded_scripts_for_receipt` before it moved
//! here). Python keeps the receipt lookup and the output.
//!
//! The request carries the receipt's `scanner_evidence`, its
//! `raw_command_text` and the `command` of its action envelope, each as
//! stored. Every `embedded_script` heredoc marker in the evidence yields one
//! script: the marker's recorded facts, and, when the receipt kept command
//! text, the body sliced back out of it with whether it hashes to the
//! recorded digest.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 3] = ["scanner_evidence", "raw_command_text", "envelope_command"];
const MARKER_KEYS: [&str; 10] = [
    "index",
    "delimiter",
    "quoted",
    "executable",
    "executed",
    "execution_status",
    "sha256",
    "bytes",
    "lines",
    "span",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let Some(evidence) = fields.get("scanner_evidence").and_then(Value::as_array) else {
        return Ok(json!({"scripts": []}));
    };
    let command_text = [
        fields.get("raw_command_text"),
        fields.get("envelope_command"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .find(|text| !text.is_empty())
    .map(|text| text.chars().collect::<Vec<char>>());
    let scripts = evidence
        .iter()
        .filter_map(Value::as_object)
        .filter(|entry| {
            entry.get("source").and_then(Value::as_str) == Some("embedded_script")
                && entry.get("kind").and_then(Value::as_str) == Some("heredoc")
        })
        .map(|marker| script(marker, command_text.as_deref()))
        .collect::<Vec<Value>>();
    Ok(json!({"scripts": scripts}))
}

fn script(marker: &Map<String, Value>, command_text: Option<&[char]>) -> Value {
    let mut item = MARKER_KEYS
        .iter()
        .map(|key| {
            let value = marker.get(*key).cloned().unwrap_or(Value::Null);
            ((*key).to_owned(), value)
        })
        .collect::<Map<String, Value>>();
    if let Some((body, verified)) = command_text.and_then(|text| recover_body(text, marker)) {
        item.insert("sha256_verified".to_owned(), Value::Bool(verified));
        item.insert("body".to_owned(), Value::String(body));
    }
    Value::Object(item)
}

/// The recorded span was computed against the command text the hook
/// evaluated, which can differ from the retained command by surrounding
/// whitespace. Spans count code points while `bytes`, the authoritative body
/// length, counts UTF-8 bytes: search the neighbourhood of the recorded start
/// for the slice that hashes to the recorded digest, then fall back to the
/// recorded span itself.
fn recover_body(text: &[char], marker: &Map<String, Value>) -> Option<(String, bool)> {
    let expected = marker.get("sha256").and_then(Value::as_str)?;
    let byte_len = marker
        .get("bytes")
        .and_then(Value::as_i64)
        .filter(|length| *length >= 0)?;
    let span = marker.get("span").and_then(Value::as_object)?;
    let start = span.get("start").and_then(Value::as_i64)?;
    let length = i64::try_from(text.len()).ok()?;
    for candidate in [start, start.saturating_sub(1), start.saturating_add(1)] {
        if !(0..=length).contains(&candidate) {
            continue;
        }
        let body = usize::try_from(candidate)
            .ok()
            .and_then(|offset| slice_by_utf8_length(text, offset, byte_len));
        if let Some(body) = body.filter(|body| sha256_hex(body) == expected) {
            return Some((body, true));
        }
    }
    let end = span.get("end").and_then(Value::as_i64)?;
    if !(0..=end).contains(&start) || end > length {
        return None;
    }
    let body = text[usize::try_from(start).ok()?..usize::try_from(end).ok()?]
        .iter()
        .collect::<String>();
    let verified = sha256_hex(&body) == expected;
    Some((body, verified))
}

/// The slice starting at `start` whose UTF-8 encoding is exactly `byte_len`
/// bytes, if one exists.
fn slice_by_utf8_length(text: &[char], start: usize, byte_len: i64) -> Option<String> {
    let mut total = 0_i64;
    for (offset, character) in text.get(start..)?.iter().enumerate() {
        total += i64::try_from(character.len_utf8()).ok()?;
        if total > byte_len {
            return None;
        }
        if total == byte_len {
            return Some(text[start..=start + offset].iter().collect());
        }
    }
    None
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[cfg(test)]
#[path = "receipt_embedded_scripts_tests.rs"]
mod tests;
