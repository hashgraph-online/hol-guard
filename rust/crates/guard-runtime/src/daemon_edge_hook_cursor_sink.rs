//! Cursor's `beforeShellExecution` for the contained sink a route probe
//! wrote. The daemon admits that exact command itself; a probe still takes
//! the library's edge review, and any other call the ordinary review.

use serde_json::{json, Map, Value};

use super::Hook;

const SOURCE_HOOK_FIELD: &str = "cursor_source_hook_event";
const BEFORE_SHELL: &str = "beforeShellExecution";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";
const SINK_VERB: &str = "execute-contained-test";
/// The runtime's own workspace sandbox sink, which a probe may name instead.
const NATIVE_SINK_VERB: &str = "contained-workspace-sink";
const EXECUTION_ENVIRONMENT_KEY: &str = "guard_execution_environment";

/// Whether `payload` is a sink call the daemon admits here.
pub(super) fn names_sink(harness: &str, event: &str, payload: &Map<String, Value>) -> bool {
    if cfg!(windows) || harness != "cursor" || event != "PreToolUse" {
        return false;
    }
    if payload
        .get(RECEIPT_ONLY_FIELD)
        .is_some_and(|value| !value.is_null())
    {
        return false;
    }
    payload.get(SOURCE_HOOK_FIELD).and_then(Value::as_str) == Some(BEFORE_SHELL)
        && payload
            .get("tool_input")
            .and_then(Value::as_object)
            .and_then(|input| input.get("command"))
            .and_then(Value::as_str)
            .is_some_and(|command| {
                command.contains(SINK_VERB) || command.contains(NATIVE_SINK_VERB)
            })
}

/// The resident's `cursor_shell_route` params for a sink call.
pub(super) fn params(
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
    guard_home: &str,
    sink_command: &Value,
) -> Map<String, Value> {
    let mut payload = payload.clone();
    // The worker keeps a caller with no stamped context unstamped.
    payload
        .entry(EXECUTION_ENVIRONMENT_KEY)
        .or_insert(Value::Null);
    let params = json!({
        "payload": payload,
        "workspace": workspace,
        "home_dir": home_dir,
        "guard_home": guard_home,
        "sink_command": sink_command,
        // This daemon admits the runtime's own sink command too.
        "native_sink": true,
    });
    match params {
        Value::Object(params) => params,
        _ => Map::new(),
    }
}

impl Hook<'_> {
    /// The routed allow for a sink call the probe wrote, or `None` to review
    /// the call as usual, so a sink it does not admit runs nowhere.
    pub(super) fn cursor_sink(
        &self,
        harness: &str,
        event: &str,
        payload: &Map<String, Value>,
        directories: (Option<&str>, Option<&str>, Option<&str>),
        expires: f64,
    ) -> Option<Value> {
        let (workspace, home_dir, guard_home) = directories;
        let (workspace, home_dir, guard_home) = (workspace?, home_dir?, guard_home?);
        if !names_sink(harness, event, payload) {
            return None;
        }
        let prefix = self.call_by("hook.sink_command", json!({}), expires)?;
        let sink_command = prefix
            .get("sink_command")
            .filter(|value| value.is_array())?;
        let params = params(payload, workspace, home_dir, guard_home, sink_command);
        crate::hook_direct::cursor::daemon_answer(&params)
            .ok()
            .flatten()
            .filter(Value::is_object)
    }
}

#[cfg(test)]
#[path = "daemon_edge_hook_cursor_sink_tests.rs"]
mod tests;
