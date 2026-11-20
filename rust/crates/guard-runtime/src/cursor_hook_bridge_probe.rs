//! Cursor's `preToolUse` hook for `Shell`: the silent route probe.
//!
//! Cursor applies a `preToolUse` answer's `updated_input` before it runs
//! `beforeShellExecution`, which cannot rewrite a call. The probe asks the
//! daemon whether the call would run in Guard's contained sink and, when it
//! would, answers with the rewritten command; everything else is a plain
//! allow, because `beforeShellExecution` reviews the call that runs. The
//! daemon records nothing for a probe, so the review the user sees is the
//! one `beforeShellExecution` asks for.
//!
//! Matching the client, an answer the probe cannot read is a plain allow
//! and the daemon is never restarted for it.

use std::path::Path;

use serde_json::{Map, Value};

use super::{Client, Request, DAEMON_HARNESS};
use crate::bounded_hook_bridge::daemon_target;
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::cursor_hook_bridge_response::ALLOW_STDOUT;
use crate::guard_store_json::dumps_default;

/// The reason the daemon names a call it rewrote into the contained sink.
const ROUTED_REASON: &str = "native_contained_execution_routed";

/// The client's stdout and exit code for a probe, given what a live
/// resident answered or why it did not.
pub(super) fn reply(
    client: &Client,
    request: &Request,
    resident: Result<String, DirectMiss>,
) -> (String, i32) {
    let body = match resident {
        Ok(body) => Some(body),
        Err(miss) => {
            daemon_target(Path::new(&client.guard_home), DAEMON_HARNESS).and_then(|target| {
                let deadline = super::daemon::request_deadline(client, request)?;
                super::daemon::post(&target, request, deadline, miss).ok()
            })
        }
    };
    let stdout = body
        .as_deref()
        .and_then(rewritten)
        .unwrap_or_else(|| ALLOW_STDOUT.to_owned());
    (stdout, 0)
}

/// `json.dumps({"permission": "allow", "updated_input": ...}, sort_keys=True)`
/// for a daemon body that routed the call, or `None` for any other body.
/// A body `json.loads` reads with a non-finite number or a lone surrogate
/// is refused here as the client refuses it.
fn rewritten(body: &str) -> Option<String> {
    let response: Value = serde_json::from_str(py_strip(body)).ok()?;
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    if text("policy_action") != Some("allow") || text("reason_code") != Some(ROUTED_REASON) {
        return None;
    }
    let updated = response.get("hookSpecificOutput")?.get("updatedInput")?;
    updated.as_object()?.get("command")?.as_str()?;
    let mut answer = Map::new();
    answer.insert("permission".to_owned(), Value::from("allow"));
    answer.insert("updated_input".to_owned(), updated.clone());
    Some(format!("{}\n", dumps_default(&Value::Object(answer))?))
}

#[cfg(all(test, unix))]
#[path = "cursor_hook_bridge_probe_tests.rs"]
mod tests;
