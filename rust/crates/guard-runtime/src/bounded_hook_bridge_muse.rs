//! The Muse answer of the bounded hook bridge: `_rendered_bridge_answer`
//! for Muse in `bounded_cli_hook_daemon.py`, with the approval wait of
//! `muse_hook_render.py`.
//!
//! A `PreToolUse` review the daemon queued waits inside the hook for the
//! approvals it names, read back from the daemon: an approval lets the
//! identical call through and a denial keeps it blocked, so the user
//! approves once and the work continues without a manual retry. The
//! one-time approval binding still rejects a call whose arguments changed
//! while it waited. `hook_approval_wait` plans and settles the wait and
//! `hook_responses::muse` renders the document, so nothing here reads a
//! verdict.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_command::hook_responses::muse;
use serde_json::{json, Map, Value};

use super::DaemonTarget;
use crate::bounded_hook_bridge_grok_render::quote_component;
use crate::bounded_hook_bridge_render::Rendered;
use crate::claude_hook_bridge_http::remaining;
use crate::cloud_request_text::py_truthy;
use crate::guard_config_load::approval_wait_timeout_seconds;
use crate::hook_env_stamp::dumps;
use crate::pyjson::{self, PyVal};

/// `_RENDER_RESERVE_SECONDS`: the time a wait leaves the render.
const RENDER_RESERVE_SECONDS: u64 = 2;
/// The longest one status read may take.
const POLL_TIMEOUT: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Only these events decide whether something runs. The rest report on work
/// that already happened or on the session, so an answer that cannot be
/// read leaves them silent: exit 2 on `Stop` would keep the agent running.
const DECIDING_EVENTS: [&str; 3] = ["pretooluse", "permissionrequest", "userpromptsubmit"];
const UNAVAILABLE_REASON: &str = "HOL Guard blocked this action.";

/// What Muse reads for the daemon's `response`: the document on stdout,
/// empty for an allow, and its exit status. `daemon` is where the approvals
/// a review names are read back while the hook waits for them.
pub(super) fn muse_answer(
    response: &[(String, PyVal)],
    event_name: &str,
    unmap: bool,
    guard_home: &Path,
    daemon: Option<&DaemonTarget>,
    deadline: Instant,
) -> Rendered {
    let Some(Value::Object(parsed)) = PyVal::Dict(response.to_vec()).to_json() else {
        return unavailable(event_name);
    };
    let answer = daemon
        .and_then(|daemon| waited(&parsed, event_name, guard_home, daemon, deadline))
        .unwrap_or(parsed);
    let (document, exit_code) = muse::bridge_response(&answer, event_name);
    let exit_code = i32::try_from(exit_code).unwrap_or(2);
    let Some(document) = document else {
        return Rendered {
            stdout: String::new(),
            stderr: String::new(),
            exit_code,
        };
    };
    let Some(stdout) = ascii_json(&document, unmap) else {
        return unavailable(event_name);
    };
    Rendered {
        stdout,
        stderr: String::new(),
        exit_code,
    }
}

/// `muse_bridge_response` when the answer cannot be read: a deciding call
/// is refused with the reason on stderr, which Muse reads on exit 2.
fn unavailable(event_name: &str) -> Rendered {
    let compact = muse::compact_event(event_name);
    if !DECIDING_EVENTS.contains(&compact.as_str()) {
        return Rendered {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: 0,
        };
    }
    Rendered {
        stdout: String::new(),
        stderr: UNAVAILABLE_REASON.to_owned(),
        exit_code: 2,
    }
}

/// `json.dumps(document, ensure_ascii=True, separators=(",", ":"))`.
fn ascii_json(document: &Map<String, Value>, unmap: bool) -> Option<String> {
    let text = serde_json::to_string(document).ok()?;
    let value = pyjson::parse(&text).ok()?;
    let mut rendered = String::new();
    dumps(&value, true, unmap, &mut rendered);
    Some(rendered)
}

/// `apply_muse_pretool_approval_wait`: the answer rewritten to how the
/// approvals it names were resolved, or `None` when it does not wait. A wait
/// that runs out leaves the review as the daemon gave it, so the saved
/// approval answers the retry.
fn waited(
    response: &Map<String, Value>,
    event_name: &str,
    guard_home: &Path,
    daemon: &DaemonTarget,
    deadline: Instant,
) -> Option<Map<String, Value>> {
    let configured = approval_wait_timeout_seconds(guard_home, None).ok()?;
    let left = remaining(deadline)
        .as_secs()
        .saturating_sub(RENDER_RESERVE_SECONDS);
    let timeout = configured.min(i64::try_from(left).unwrap_or(i64::MAX));
    if timeout <= 0 {
        return None;
    }
    let policy_action = response
        .get("policy_action")
        .and_then(Value::as_str)
        .unwrap_or("");
    let plan = crate::hook_approval_wait::dispatch(&json!({
        "op": "plan",
        "harness": "muse",
        "event": event_name,
        "policy_action": policy_action,
        "timeout": timeout,
        "response": response,
    }))
    .ok()?;
    let request_ids: Vec<&str> = plan
        .get("request_ids")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let seconds = plan.get("seconds").and_then(Value::as_u64).unwrap_or(0);
    let first = *request_ids.first()?;
    if seconds == 0 {
        return None;
    }
    let wait_deadline = deadline.min(Instant::now() + Duration::from_secs(seconds));
    let (resolved, rows) = wait_for_requests(daemon, &request_ids, wait_deadline);
    let settled = crate::hook_approval_wait::dispatch(&json!({
        "op": "settle",
        "harness": "muse",
        "resolved": resolved,
        "rows": rows,
        "request_id": first,
    }))
    .ok()?;
    let mut answer = response.clone();
    if matches!(
        settled.get("decision").and_then(Value::as_str),
        Some("allow" | "block")
    ) {
        if let Some(edits) = settled.get("edits").and_then(Value::as_object) {
            apply_edits(&mut answer, edits);
        }
    }
    for pair in settled
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some([Value::String(key), value]) = pair.as_array().map(Vec::as_slice) {
            answer.insert(key.clone(), value.clone());
        }
    }
    Some(answer)
}

/// `wait_for_approval_requests`: whether every request was resolved before
/// `deadline`, and the resolution of each resolved one.
fn wait_for_requests(
    daemon: &DaemonTarget,
    request_ids: &[&str],
    deadline: Instant,
) -> (bool, Vec<Value>) {
    let mut actions: Vec<Option<Value>> = vec![None; request_ids.len()];
    loop {
        for (request_id, action) in request_ids.iter().zip(actions.iter_mut()) {
            if action.is_some() {
                continue;
            }
            let read_deadline = deadline.min(Instant::now() + POLL_TIMEOUT);
            let path = format!("/v1/requests/{}", quote_component(request_id));
            let Some(status) = daemon.get_object(&path, read_deadline) else {
                continue;
            };
            if status.get("status").and_then(Value::as_str) == Some("resolved") {
                let resolution = status
                    .get("resolution_action")
                    .cloned()
                    .unwrap_or(Value::Null);
                // `_leaf`: a string stays, anything else only by its truthiness.
                *action = Some(match resolution {
                    Value::String(_) => resolution,
                    other => Value::Bool(py_truthy(&other)),
                });
            }
        }
        let resolved: Vec<Value> = actions
            .iter()
            .flatten()
            .map(|action| json!({ "action": action }))
            .collect();
        if resolved.len() == request_ids.len() {
            return (true, resolved);
        }
        let now = Instant::now();
        if now >= deadline {
            return (false, resolved);
        }
        std::thread::sleep(POLL_INTERVAL.min(deadline - now));
    }
}

/// `rewrite_answer`: `set` and `drop` on the answer, `hook_set` and
/// `hook_drop` on its `hookSpecificOutput`.
fn apply_edits(answer: &mut Map<String, Value>, edits: &Map<String, Value>) {
    edited(answer, edits.get("set"), edits.get("drop"));
    if let Some(Value::Object(hook_specific)) = answer.get_mut("hookSpecificOutput") {
        edited(hook_specific, edits.get("hook_set"), edits.get("hook_drop"));
    }
}

fn edited(target: &mut Map<String, Value>, sets: Option<&Value>, drops: Option<&Value>) {
    for pair in sets.and_then(Value::as_array).into_iter().flatten() {
        if let Some([Value::String(key), value]) = pair.as_array().map(Vec::as_slice) {
            target.insert(key.clone(), value.clone());
        }
    }
    for key in drops.and_then(Value::as_array).into_iter().flatten() {
        if let Some(key) = key.as_str() {
            target.remove(key);
        }
    }
}
