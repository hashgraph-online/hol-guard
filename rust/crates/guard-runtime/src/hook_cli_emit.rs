//! `emit_hook_review` from `commands_hook_native_authority.py`: how the
//! `hol-guard hook` command reads the daemon's answer to one hook.
//!
//! A harness whose bounded bridge prints this command's output as is gets
//! the answer reshaped into its own wire format, the stdout, stderr and exit
//! status the bridge would write. Every other harness gets the daemon's
//! document unchanged from the caller, so the resident names only the policy
//! action that decides its exit status. Nothing here decides a verdict: the
//! daemon already did, and this reads which one it gave.

use std::path::Path;

use guard_command::hook_responses::Object;
use serde_json::{json, Value};

use crate::bounded_hook_bridge_render::{
    canonical_event_token, consistent_native_response, daemon_response_to_native,
    is_permission_event, member, policy_action_from_daemon, rendered, Rendered,
};
use crate::claude_hook_bridge_render::py_strip;
use crate::pyjson::{self, PyVal};

/// `_BRIDGE_RENDERED_HARNESSES`.
const BRIDGE_RENDERED_HARNESSES: [&str; 8] = [
    "cline", "copilot", "devin", "grok", "hermes", "kimi", "openclaw", "zcode",
];

/// The compact spellings `is_grok_observe_only_event` reads as an event
/// Grok reports but cannot reject.
const GROK_OBSERVE_ONLY_EVENTS: [&str; 8] = [
    "sessionstart",
    "sessionend",
    "subagentstart",
    "subagentstop",
    "subagentend",
    "posttooluse",
    "posttoolusefailure",
    "permissiondenied",
];

fn grok_observe_only(event_name: &str) -> bool {
    let compact = py_strip(event_name)
        .chars()
        .filter(|character| *character != '_' && *character != '-')
        .collect::<String>()
        .to_lowercase();
    GROK_OBSERVE_ONLY_EVENTS.contains(&compact.as_str())
}

fn has_key(entries: &[(String, PyVal)], key: &str) -> bool {
    member(entries, key).is_some()
}

/// What a bridge-rendered harness reads: `None` when the answer carries a
/// value Python would render through `repr`, which the caller fails closed.
/// `bridge` is the Python bounded bridge printing the daemon's hook answer,
/// which writes Copilot's answer through the generic renderer as the native
/// bridge does.
fn bridge_output(
    harness: &str,
    event_name: &str,
    response: &[(String, PyVal)],
    unmap: bool,
    guard_home: Option<&Path>,
    bridge: bool,
) -> Option<Rendered> {
    if !bridge
        && harness == "copilot"
        && has_key(response, "behavior")
        && is_permission_event(event_name)
    {
        // Already Copilot's permission wire document (its fail-safe deny
        // among them); the generic renderer would drop the fields it reads.
        return Some(rendered(response, String::new(), 0, unmap));
    }
    if harness == "grok" && response.is_empty() {
        // An empty answer to an event Grok cannot reject, or to a prompt,
        // carries no decision; an empty object lets the turn go on.
        let event = canonical_event_token(event_name).unwrap_or_else(|| event_name.to_owned());
        if grok_observe_only(&event) || event == "UserPromptSubmit" {
            return Some(Rendered {
                stdout: "{}".to_owned(),
                stderr: String::new(),
                exit_code: 0,
            });
        }
    }
    daemon_response_to_native(response, harness, event_name, unmap, guard_home)
}

/// The policy action a non-bridge harness's exit status follows. A notice
/// or dialog answer names no policy action; its envelope's own decision is
/// the verdict, so context alone never reads as a block.
fn exit_policy_action(harness: &str, event_name: &str, response: &[(String, PyVal)]) -> String {
    let envelope = has_key(response, "hookSpecificOutput") || has_key(response, "decision");
    if !has_key(response, "policy_action") && envelope {
        consistent_native_response(response, harness, event_name).1
    } else {
        policy_action_from_daemon(response, event_name)
    }
}

/// The `cli_hook_emit` document for `harness` (canonical) and the daemon's
/// answer as compact JSON text. `None` for text that is not one JSON object
/// or an answer the bridge renderer cannot reproduce. `guard_home` is the
/// store the caller's command names, so an authority block's recovery line
/// names that store too; `None` leaves the bare command the default home
/// already answers. `bridge` asks for the bounded bridge's own output for
/// any harness: that bridge prints what the harness reads, whichever
/// harness it is.
pub(crate) fn cli_hook_emit_document(
    harness: &str,
    event_name: &str,
    response_json: &str,
    guard_home: Option<&Path>,
    bridge: bool,
) -> Option<Object> {
    let parsed = pyjson::parse_mapping_lone_surrogates(response_json).ok()?;
    if parsed.mapped && parsed.collision {
        return None;
    }
    let response = parsed.value.as_dict()?;
    let mut document = Object::new();
    if !bridge && !BRIDGE_RENDERED_HARNESSES.contains(&harness) {
        let action = exit_policy_action(harness, event_name, response);
        document.insert("policy_action".into(), Value::String(action));
        return Some(document);
    }
    let output = bridge_output(
        harness,
        event_name,
        response,
        parsed.mapped,
        guard_home,
        bridge,
    )?;
    document.insert("stdout".into(), Value::String(output.stdout));
    document.insert("stderr".into(), Value::String(output.stderr));
    document.insert("exit_code".into(), json!(output.exit_code));
    Some(document)
}

#[cfg(test)]
#[path = "hook_cli_emit_tests.rs"]
mod tests;
