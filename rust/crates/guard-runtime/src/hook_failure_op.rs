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
    if fields.len() != if fields.contains_key("stderr") { 4 } else { 3 } {
        return Err(ERR_INVALID);
    }
    let harness = text(fields, "harness")?;
    let event_name = text(fields, "event_name")?;
    let reason = text(fields, "reason")?;
    if on_stderr {
        let compact = event_name.replace(['_', '-'], "").to_lowercase();
        let (stderr, exit_code) = if DECIDING_EVENTS.contains(&compact.as_str()) {
            (reason, 2)
        } else {
            ("", 0)
        };
        return Ok(json!({ "document": "", "stderr": stderr, "exit_code": exit_code }));
    }
    let (document, exit_code) = failure(harness, event_name, reason);
    Ok(json!({ "document": document, "exit_code": exit_code }))
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// The document and exit status for a hook whose review could not finish.
fn failure(harness: &str, event_name: &str, reason: &str) -> (String, i32) {
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
    let (mut document, exit_code) = failure_output_for(shape, event_name, reason, false);
    if document.ends_with('\n') {
        document.pop();
    }
    (document, exit_code)
}

#[cfg(test)]
#[path = "hook_failure_op_tests.rs"]
mod tests;
