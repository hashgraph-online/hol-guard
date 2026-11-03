//! `mcp_output` runner-authority kind: the default-deny sanitizer for what
//! the guard-mcp.v1 read tools (`search`, `fetch`, `get_guard_status`) return.
//!
//! The caller sends exactly one of `{"search": [raw, ...]}`, `{"fetch": raw}`
//! or `{"status": raw}`, where each `raw` is the adapter's projection of a
//! store row. Every field not in the allowlist is dropped. Text is NFKC
//! normalized, stripped of control characters other than tab and line breaks,
//! and cut by character; enums fall back to a fixed default. The answer is
//! `{"results": [...]}`, `{"result": {...}}` or `{"status": {...}}`.
//!
//! Fetch text is also held to `MAX_FETCH_TEXT_BYTES` of UTF-8, cut on a
//! character boundary, and marked `truncated` when the cut removed anything.
//! A value an adapter never produces (a fraction, list or object where text
//! belongs) is dropped as empty text rather than rendered.

use serde_json::{json, Map, Value};
use unicode_normalization::UnicodeNormalization;

use crate::cloud_request_text::py_truthy;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_FIELD_LENGTH: usize = 1024;
const MAX_ID_LENGTH: usize = 256;
const MAX_TITLE_LENGTH: usize = 256;
const MAX_FETCH_TEXT_BYTES: usize = 32_768;
/// `MAX_SEARCH_LIMIT`: the read tools never return more results.
const MAX_SEARCH_RESULTS: usize = 20;

const KINDS: &[&str] = &["receipt", "artifact", "inventory", "device"];
const DECISIONS: &[&str] = &["allow", "deny", "warn", "block", "unknown"];
const HARNESSES: &[&str] = &[
    "codex",
    "claude",
    "cursor",
    "copilot",
    "opencode",
    "gemini",
    "hermes",
    "openclaw",
    "antigravity",
    "pi",
    "omp",
    "devin",
    "muse",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    if args.len() != 1 {
        return Err(ERR_INVALID);
    }
    if let Some(raw) = args.get("search") {
        let items = raw.as_array().ok_or(ERR_INVALID)?;
        if items.len() > MAX_SEARCH_RESULTS {
            return Err(ERR_INVALID);
        }
        let results = items
            .iter()
            .map(|item| item.as_object().map(common_fields).map(Value::Object))
            .collect::<Option<Vec<Value>>>()
            .ok_or(ERR_INVALID)?;
        return Ok(json!({ "results": results }));
    }
    if let Some(raw) = args.get("fetch") {
        let raw = raw.as_object().ok_or(ERR_INVALID)?;
        return Ok(json!({ "result": fetch(raw) }));
    }
    if let Some(raw) = args.get("status") {
        let raw = raw.as_object().ok_or(ERR_INVALID)?;
        return Ok(json!({ "status": status(raw) }));
    }
    Err(ERR_INVALID)
}

/// Python's `str(value)` for the values the adapters produce; `None` and
/// anything they never produce is empty.
fn py_str(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(true)) => "True".to_owned(),
        Some(Value::Bool(false)) => "False".to_owned(),
        Some(Value::Number(number)) if number.is_i64() || number.is_u64() => number.to_string(),
        _ => String::new(),
    }
}

/// `_normalize_text`: NFKC, then control characters (C0, DEL and C1) out
/// except tab, newline and carriage return, then a character cut.
fn normalized_text(value: Option<&Value>, max_chars: usize) -> String {
    py_str(value)
        .nfkc()
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .take(max_chars)
        .collect()
}

fn enum_value(value: Option<&Value>, valid: &[&str], default: &str) -> String {
    match value {
        None | Some(Value::Null) => default.to_owned(),
        _ => {
            let text = py_str(value);
            if valid.contains(&text.as_str()) {
                text
            } else {
                default.to_owned()
            }
        }
    }
}

fn common_fields(raw: &Map<String, Value>) -> Map<String, Value> {
    let mut allowed = Map::new();
    let id = normalized_text(raw.get("id"), MAX_ID_LENGTH);
    if !id.is_empty() {
        allowed.insert("id".to_owned(), Value::String(id));
    }
    allowed.insert(
        "title".to_owned(),
        Value::String(normalized_text(raw.get("title"), MAX_TITLE_LENGTH)),
    );
    allowed.insert(
        "kind".to_owned(),
        Value::String(enum_value(raw.get("kind"), KINDS, "receipt")),
    );
    allowed.insert(
        "harness".to_owned(),
        Value::String(enum_value(raw.get("harness"), HARNESSES, "")),
    );
    allowed.insert(
        "decision".to_owned(),
        Value::String(enum_value(raw.get("decision"), DECISIONS, "unknown")),
    );
    if let Some(Value::Bool(changed)) = raw.get("changedSinceLastApproval") {
        allowed.insert("changedSinceLastApproval".to_owned(), Value::Bool(*changed));
    }
    allowed
}

/// The longest prefix of `text` that fits in `limit` UTF-8 bytes.
fn byte_prefix(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let end = (0..=limit)
        .rev()
        .find(|end| text.is_char_boundary(*end))
        .unwrap_or(0);
    &text[..end]
}

fn fetch(raw: &Map<String, Value>) -> Value {
    let mut allowed = common_fields(raw);
    // Cut by bytes alone: a character is at least one byte, so a separate
    // character cut could only drop text the truncation flag never saw.
    let text = normalized_text(raw.get("text"), usize::MAX);
    let fitted = byte_prefix(&text, MAX_FETCH_TEXT_BYTES);
    let truncated = fitted.len() < text.len() || raw.get("truncated").is_some_and(py_truthy);
    allowed.insert("text".to_owned(), Value::String(fitted.to_owned()));
    allowed.insert("truncated".to_owned(), Value::Bool(truncated));
    Value::Object(allowed)
}

/// `int(value)` for a JSON number or boolean; anything else counts zero.
fn count(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Bool(flag)) => json!(u8::from(*flag)),
        Some(Value::Number(number)) if number.is_i64() || number.is_u64() => {
            Value::Number(number.clone())
        }
        Some(Value::Number(number)) => {
            let truncated = number.as_f64().map_or(0.0, f64::trunc);
            // A finite fraction outside i64 never comes from a store count.
            json!(truncated as i64)
        }
        _ => json!(0),
    }
}

fn status(raw: &Map<String, Value>) -> Value {
    let mut allowed = Map::new();
    allowed.insert(
        "cliAvailable".to_owned(),
        Value::Bool(raw.get("cliAvailable").is_none_or(py_truthy)),
    );
    allowed.insert("receiptCount".to_owned(), count(raw.get("receiptCount")));
    allowed.insert(
        "inventoryCount".to_owned(),
        count(raw.get("inventoryCount")),
    );
    let version = normalized_text(raw.get("cliVersion"), MAX_FIELD_LENGTH);
    if !version.is_empty() {
        allowed.insert("cliVersion".to_owned(), Value::String(version));
    }
    Value::Object(allowed)
}

#[cfg(test)]
#[path = "mcp_output_tests.rs"]
mod tests;
