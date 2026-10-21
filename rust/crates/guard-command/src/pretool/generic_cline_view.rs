//! Cline 4.1 sends each tool call twice, a typed `tool_call` and a
//! compatibility `preToolUse`, under its own event label (`tool_call`).
//! Prepare reconciles both onto `tool_name` and `tool_input` and refuses
//! copies that disagree, but keeps them so the receipt records the call as
//! sent. The generic extractor reads every name and event key, so Cline's
//! spellings (`read_files` beside `read_file`, `tool_call` beside
//! `PreToolUse`) would read as two calls. Evaluation judges a view without
//! the copies prepare has already reconciled.

use crate::hook_adapter_cline_tables::EVENT_NAMES;
use serde_json::{Map, Value};

const EVENT_KEYS: [&str; 6] = [
    "hook_event_name",
    "hookEventName",
    "hook_name",
    "hookName",
    "event",
    "eventName",
];

/// The prepared payload without Cline's reconciled duplicates, or `None`
/// when nothing needs to change.
pub(super) fn evaluated_view(payload: &Value) -> Option<Value> {
    let root = payload.as_object()?;
    // Prepare always writes the canonical `hook_event_name`; without it the
    // payload was not prepared and stays as sent, so conflicts fail closed.
    let event = root.get("hook_event_name")?.as_str()?;
    let mut view = root.clone();
    for key in EVENT_KEYS {
        let Some(label) = root.get(key).and_then(Value::as_str) else {
            continue;
        };
        if label != event && cline_event(label) == Some(event) {
            view.insert(key.to_owned(), Value::from(event));
        }
    }
    // Prepare reconciles only the pair for this event, `tool_call` with
    // `preToolUse` or `tool_result` with `postToolUse`, and refuses a pair
    // that disagrees. A copy is dropped only when both present copies of that
    // pair name the tool prepare recorded as `cline_tool_name`. Any other
    // copy, including one from the other phase, stays and the extractor still
    // refuses the conflict. Prepare keeps a `cline_tool_name` the tool input
    // already carried; such a value names either the pair's own tool, which
    // prepare reconciled, or another tool, which drops nothing.
    let pair: [(&str, &str); 2] = match event {
        "PreToolUse" => [("tool_call", "name"), ("preToolUse", "toolName")],
        "PostToolUse" => [("tool_result", "name"), ("postToolUse", "toolName")],
        _ => return finished(view, root),
    };
    let reconciled = root
        .get("tool_input")
        .and_then(Value::as_object)
        .and_then(|input| input.get("cline_tool_name"))
        .and_then(Value::as_str);
    let present: Vec<(&str, Option<&str>)> = pair
        .iter()
        .filter_map(|(key, name_key)| {
            let copy = root.get(*key)?;
            let name = copy
                .as_object()
                .and_then(|copy| copy.get(*name_key))
                .and_then(Value::as_str)
                .map(str::trim);
            Some((*key, name))
        })
        .collect();
    if reconciled.is_some() && present.iter().all(|(_, name)| *name == reconciled) {
        for (key, _) in present {
            view.remove(key);
        }
    }
    finished(view, root)
}

fn finished(view: Map<String, Value>, root: &Map<String, Value>) -> Option<Value> {
    if view == *root {
        None
    } else {
        Some(Value::Object(view))
    }
}

fn cline_event(label: &str) -> Option<&'static str> {
    let lookup = label.to_ascii_lowercase().replace('-', "_");
    EVENT_NAMES
        .iter()
        .find(|(alias, _)| *alias == lookup)
        .map(|(_, canonical)| *canonical)
}
