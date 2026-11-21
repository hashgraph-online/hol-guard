//! `emit_hook_review` from `commands_hook_native_authority.py`: how the
//! `hol-guard hook` command reads the daemon's answer to one hook.
//!
//! A harness whose bounded bridge prints this command's output as is gets
//! the answer reshaped into its own wire format, the stdout, stderr and exit
//! status the bridge would write. Every other harness reads the daemon's
//! document itself: the resident names the policy action that decides its
//! exit status and, when the caller asks for it, prints that document with
//! secrets masked and the signed approval link intact, with the exit status
//! the harness expects. Nothing here decides a verdict: the daemon already
//! did, and this reads which one it gave.

use std::path::Path;

use guard_command::hook_responses::Object;
use serde_json::{json, Value};

use crate::bounded_hook_bridge_render::{
    canonical_event_token, consistent_native_response, daemon_response_to_native,
    is_permission_event, member, policy_action_from_daemon, rendered, Rendered,
};
use crate::claude_hook_bridge_render::py_strip;
use crate::hook_cli_emit_redaction::redacted_hook_document;
use crate::pyjson::{self, PyVal};

/// `_BRIDGE_RENDERED_HARNESSES`.
const BRIDGE_RENDERED_HARNESSES: [&str; 8] = [
    "cline", "copilot", "devin", "grok", "hermes", "kimi", "openclaw", "zcode",
];

/// `native_hook_exit_code._BLOCKING_ACTIONS`.
const BLOCKING_ACTIONS: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];
/// `native_hook_exit_code._PREEMPTIVE_EVENTS`: an envelope harness reads a
/// blocking answer to these from its JSON, so the status stays 0.
const PREEMPTIVE_EVENTS: [&str; 3] = ["PreToolUse", "UserPromptSubmit", "PermissionRequest"];

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

/// `native_hook_verdict_exit_code` for a harness that reads the printed
/// document, with `emit_hook_review`'s Claude rule first: Claude reads a
/// hook's JSON only on exit 0, so any other status would discard the
/// document, a block and its reason included.
fn document_exit_code(harness: &str, policy_action: &str, event_name: &str) -> i32 {
    if harness == "claude-code" {
        return 0;
    }
    let blocking = BLOCKING_ACTIONS.contains(&policy_action);
    match harness {
        "cursor" | "devin" | "kimi" | "hermes" => {
            if blocking {
                2
            } else {
                0
            }
        }
        "codex" | "copilot" | "pi" | "omp" => {
            i32::from(blocking && !PREEMPTIVE_EVENTS.contains(&event_name))
        }
        // opencode and superagent, and any harness without a contract of its
        // own: a blocking verdict exits 1.
        _ => i32::from(blocking),
    }
}

/// What the caller prints for a harness that reads the daemon's document.
pub(crate) struct PrintedDocument<'a> {
    /// The caller's `Path.home()`, whose prefix the document shortens to
    /// `~`; `None` when the caller has no home.
    pub(crate) home_dir: Option<&'a str>,
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
    cli_hook_emit(harness, event_name, response_json, guard_home, bridge, None)
}

/// `cli_hook_emit_document`, plus, for a harness that reads the daemon's
/// document, the redacted `stdout` the command prints and the `exit_code`
/// it returns. A bridge-rendered harness, or a `bridge` reading, answers as
/// `cli_hook_emit_document` does.
pub(crate) fn cli_hook_emit_printed_document(
    harness: &str,
    event_name: &str,
    response_json: &str,
    guard_home: Option<&Path>,
    bridge: bool,
    printed: &PrintedDocument<'_>,
) -> Option<Object> {
    cli_hook_emit(
        harness,
        event_name,
        response_json,
        guard_home,
        bridge,
        Some(printed),
    )
}

fn cli_hook_emit(
    harness: &str,
    event_name: &str,
    response_json: &str,
    guard_home: Option<&Path>,
    bridge: bool,
    printed: Option<&PrintedDocument<'_>>,
) -> Option<Object> {
    let parsed = pyjson::parse_mapping_lone_surrogates(response_json).ok()?;
    if parsed.mapped && parsed.collision {
        return None;
    }
    let response = parsed.value.as_dict()?;
    let mut document = Object::new();
    if !bridge && !BRIDGE_RENDERED_HARNESSES.contains(&harness) {
        let action = exit_policy_action(harness, event_name, response);
        if let Some(printed) = printed {
            let stdout = redacted_hook_document(response, printed.home_dir, parsed.mapped);
            let exit_code = document_exit_code(harness, &action, event_name);
            document.insert("stdout".into(), Value::String(stdout));
            document.insert("exit_code".into(), json!(exit_code));
        }
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
