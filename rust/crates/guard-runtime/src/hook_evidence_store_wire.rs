//! The wire shapes the evidence seam sends to the store ops and the small
//! Python behaviours it has to reproduce exactly.
//!
//! `store_command_activity_wire.py` builds these payloads today, and a few of
//! its helpers lean on Python semantics — `bool(payload)` on a null answer,
//! `str.title()` on a harness name — that a straight Rust translation would
//! get subtly wrong. They are ported here with the Python they stand in for
//! named on each one.

use std::io;

use guard_command::hook_evidence_writer::CorrelationHandle;
use serde_json::{json, Map, Value};

use crate::guard_store_db::StoreError;

/// `command_activity_display.INVOCATION_PREVIEW_MAX_CHARS`.
const INVOCATION_PREVIEW_MAX_CHARS: usize = 4_096;

/// A failed store call as the evidence writer sees it. A busy or locked
/// database is a timeout, which the writer waits out rather than counting
/// against the attempts it gives a write the store keeps refusing.
pub(crate) fn store_failure(method: &str, error: &StoreError) -> io::Error {
    let message = format!("{method}: {} ({})", error.code(), error.message());
    if error.code() == "native_guard_store_busy" {
        io::Error::new(io::ErrorKind::TimedOut, message)
    } else {
        io::Error::other(message)
    }
}

/// The failure codes `_recover_fatal_sqlite_store` acts on: a store whose
/// image is unreadable, and one whose device is failing. Python routes both
/// through `sqlite_failure_kind` and recovers either; every other code is an
/// ordinary failed call.
pub(crate) fn fatal_store_code(error: &StoreError) -> Option<&'static str> {
    match error.code() {
        code @ ("native_guard_store_sqlite_corrupt" | "native_guard_store_sqlite_io") => Some(code),
        _ => None,
    }
}

pub(crate) fn evidence_args(evidence: &Map<String, Value>) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("evidence".to_owned(), Value::Object(evidence.clone()));
    args
}

/// `bool(payload)` on what the resident answered: these ops return null when
/// nothing matched, which Python narrows to False.
pub(crate) fn python_truthy(payload: &Value) -> bool {
    match payload {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

pub(crate) fn request_correlation(evidence: &Map<String, Value>) -> Option<&Map<String, Value>> {
    evidence
        .get("activity")?
        .as_object()?
        .get("request_correlation")?
        .as_object()
}

/// `handle_wire(correlation)` (`store_command_activity_wire.py`).
pub(crate) fn handle_wire(correlation: &CorrelationHandle) -> Value {
    json!({
        "kind": correlation.kind,
        "harness": correlation.harness,
        "key_id": correlation.key_id,
        "digest": correlation.digest,
    })
}

pub(crate) fn needs_barrier(answer: &Value) -> bool {
    answer.get("need_barrier") == Some(&Value::Bool(true))
}

/// `_validated_invocation_preview` — the store refuses a preview it cannot
/// store rather than truncating one.
pub(crate) fn validated_invocation_preview(
    preview: Option<&str>,
) -> Result<Option<String>, io::Error> {
    let Some(preview) = preview else {
        return Ok(None);
    };
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid_invocation_preview");
    if preview.contains('\0') {
        return Err(invalid());
    }
    let trimmed = preview.trim();
    if trimmed.is_empty() || trimmed.chars().count() > INVOCATION_PREVIEW_MAX_CHARS {
        return Err(invalid());
    }
    Ok(Some(trimmed.to_owned()))
}

/// Python `str.title()`: every run of letters is capitalized at its first
/// character and lowercased after it, so `claude-code` becomes `Claude-Code`.
pub(crate) fn python_title(value: &str) -> String {
    let mut titled = String::with_capacity(value.len());
    let mut in_word = false;
    for character in value.chars() {
        if character.is_alphabetic() {
            if in_word {
                titled.extend(character.to_lowercase());
            } else {
                titled.extend(character.to_uppercase());
            }
            in_word = true;
        } else {
            titled.push(character);
            in_word = false;
        }
    }
    titled
}
