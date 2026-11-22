//! `hook_failure` -- the fixed fail-closed answer a hook gets when review
//! cannot finish, per harness and event.
//!
//! `{"harness", "event_name", "reason"}` answers `{"document", "exit_code"}`:
//! the compact ASCII JSON document the harness reads, without a trailing
//! newline, and the exit status that goes with it. A tool, permission or prompt event is denied in the harness's own
//! envelope; an event that only observes finished activity gets a payload that
//! authorizes nothing. Nothing here reads a verdict or authorizes an action.
//!
//! A harness whose hook reads its refusal from stderr (Muse's CLI edge) adds
//! `"stderr": true` and gets `{"document": "", "stderr", "exit_code"}`: the
//! reason and exit 2 for an event that decides whether something runs (a
//! tool call, a permission request or a prompt), and silence with exit 0 for
//! one that only reports on finished work, where exit 2 on `Stop` would keep
//! the agent from stopping.
//!
//! The per-harness shapes are `bounded_hook_bridge_render::failure_payload`,
//! the table the bounded bridge writes itself. Grok answers in the decision
//! envelope OpenClaw uses, and keeps its observe events silent.

use serde_json::{json, Map, Value};

use crate::bounded_hook_bridge_render::failure_output_for;
use crate::claude_hook_bridge_render::py_strip;
use crate::hook_fail_closed_envelopes::{envelope, event_kind, ENVELOPES};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const DECIDING_EVENTS: [&str; 3] = ["pretooluse", "permissionrequest", "userpromptsubmit"];
const GROK_OBSERVE_EVENTS: [&str; 6] = [
    "sessionstart",
    "sessionend",
    "subagentstart",
    "subagentstop",
    "posttooluse",
    "permissiondenied",
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    let on_stderr = match fields.get("stderr") {
        None => false,
        Some(Value::Bool(on_stderr)) => *on_stderr,
        Some(_) => return Err(ERR_INVALID),
    };
    let optional_count = usize::from(fields.contains_key("stderr"))
        + usize::from(fields.contains_key("reason_code"));
    if fields.len() != 3 + optional_count {
        return Err(ERR_INVALID);
    }
    let harness = text(fields, "harness")?;
    let event_name = text(fields, "event_name")?;
    let reason = text(fields, "reason")?;
    let reason_code = fields
        .get("reason_code")
        .map(|value| value.as_str().ok_or(ERR_INVALID))
        .transpose()?;
    if on_stderr {
        let compact = event_name.replace(['_', '-'], "").to_lowercase();
        let (stderr, exit_code) = if DECIDING_EVENTS.contains(&compact.as_str()) {
            (reason, 2)
        } else {
            ("", 0)
        };
        return Ok(json!({ "document": "", "stderr": stderr, "exit_code": exit_code }));
    }
    let (document, exit_code) = failure(harness, event_name, reason, reason_code);
    Ok(json!({ "document": document, "exit_code": exit_code }))
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn failure(
    harness: &str,
    event_name: &str,
    reason: &str,
    reason_code: Option<&str>,
) -> (String, i32) {
    if harness == "grok" {
        let compact: String = py_strip(event_name)
            .to_lowercase()
            .chars()
            .filter(|character| *character != '_' && *character != '-')
            .collect();
        if GROK_OBSERVE_EVENTS.contains(&compact.as_str()) {
            return ("{}".to_owned(), 0);
        }
    }
    // Grok reads the decision envelope OpenClaw reads.
    let shape = if harness == "grok" {
        "openclaw"
    } else {
        harness
    };
    if reason_code.is_none() {
        let (mut document, exit_code) = failure_output_for(shape, event_name, reason, false);
        if document.ends_with('\n') {
            document.pop();
        }
        return (document, exit_code);
    }
    let contract: Value = serde_json::from_str(ENVELOPES).unwrap_or(Value::Null);
    let kind = event_kind(&contract, event_name);
    let effective_reason = if kind == "prompt" {
        contract["defaults"]["prompt_reason"]
            .as_str()
            .unwrap_or(reason)
    } else {
        reason
    };
    let effective_code = reason_code.unwrap_or("native_hook_render_unavailable");
    let document = envelope(
        &kind,
        harness,
        &[
            ("$reason", effective_reason),
            ("$reason_code", effective_code),
            ("$event_name", event_name),
        ],
    );
    if document.as_object().is_some_and(|map| !map.is_empty()) {
        let rendered = ascii_json(&document);
        let (_, exit_code) = failure_output_for(shape, event_name, effective_reason, false);
        return (rendered, exit_code);
    }
    let (mut fallback, exit_code) = failure_output_for(shape, event_name, effective_reason, false);
    if fallback.ends_with('\n') {
        fallback.pop();
    }
    (fallback, exit_code)
}

fn ascii_json(value: &Value) -> String {
    let raw = serde_json::to_string(value).unwrap_or_default();
    let mut output = String::with_capacity(raw.len());
    for character in raw.chars() {
        if character.is_ascii() {
            output.push(character);
        } else {
            let code = character as u32;
            if code <= 0xffff {
                output.push_str(&format!("\\u{code:04x}"));
            } else {
                let value = code - 0x1_0000;
                let high = 0xd800 + (value >> 10);
                let low = 0xdc00 + (value & 0x3ff);
                output.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
        }
    }
    output
}

#[cfg(test)]
#[path = "hook_failure_op_tests.rs"]
mod tests;
