//! Cursor shell probe review and sink admission for the daemon.
//! The resident selects the route, requests a workspace policy binding when
//! needed, and renders the response returned to Cursor.

use serde_json::{json, Map, Value};

use super::cursor::{daemon_answer, route, Route, ROUTED_REASON};
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA;

const SINK_ROUTE: &str = "sink";
const INVALID: &str = "native_hook_render_invalid";

/// The daemon's native shell route. Ask for the acknowledged policy binding
/// only when a probe needs it. The first answer already carries the response
/// a probe gets if the binding cannot be obtained.
pub(crate) fn answer(
    params: &Map<String, Value>,
    request_id: &str,
    store: Option<&PolicySnapshotStore>,
) -> Result<Map<String, Value>, &'static str> {
    let payload = params
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let guard_home = params
        .get("guard_home")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let store = store.ok_or(INVALID)?;
    store.require_guard_home(guard_home).map_err(|_| INVALID)?;
    let workspace = params.get("workspace").and_then(Value::as_str);
    let (value, needs) = match route(payload) {
        Ok(Route::Probe) => {
            let needs = (workspace.is_some() && !params.contains_key("snapshot"))
                .then_some("probe_binding");
            let edge = if let Some(workspace) = workspace {
                review_probe(params, workspace, payload, request_id, store)
            } else {
                None
            };
            (probe_response(edge.as_ref()), needs)
        }
        Ok(Route::Sink) if workspace.is_some() && !params.contains_key("sink_command") => {
            (Value::Null, Some("sink_command"))
        }
        Ok(Route::Sink) if workspace.is_some() => (
            daemon_answer(params).ok().flatten().unwrap_or(Value::Null),
            None,
        ),
        _ => (Value::Null, None),
    };
    Ok(Map::from_iter([
        ("value".to_owned(), value),
        ("needs".to_owned(), json!(needs)),
    ]))
}

fn review_probe(
    params: &Map<String, Value>,
    workspace: &str,
    payload: &Map<String, Value>,
    request_id: &str,
    store: &PolicySnapshotStore,
) -> Option<Value> {
    let snapshot = params.get("snapshot")?.as_object()?;
    let budget = params.get("probe_budget_ms")?.as_u64()?.clamp(1, 9_000);
    let sink_command = params.get("sink_command")?.as_array()?;
    let mut payload = payload.clone();
    let environment = payload.remove("guard_execution_environment");
    let envelope = crate::strict_json::from_value(json!({
        "schema": GUARD_HOOK_ENVELOPE_V2_SCHEMA,
        "request_id": request_id,
        "harness": "cursor",
        "event": "PreToolUse",
        "raw_payload": payload,
        "deadline_budget_ms": budget,
        "policy_generation": snapshot.get("generation")?,
        "policy_snapshot": snapshot,
        "source": {
            "cwd": workspace,
            "home_dir": params.get("home_dir")?,
            "guard_home": params.get("guard_home")?,
            "execution_environment": environment,
        },
        "containment_sink": {"sink_command": sink_command, "native_sink": true},
    }))
    .ok()?;
    let bytes = crate::edge::evaluate_cursor_probe(envelope, store, params.get("harness_postures"))
        .ok()
        .flatten()?;
    serde_json::from_slice(&bytes).ok()
}

/// `probe`, `sink` or `review`: the route Cursor's `PreToolUse` takes. A call
/// the daemon must review as usual, whatever the reason, is `review`.
pub(crate) fn route_name(payload: &Map<String, Value>) -> &'static str {
    match route(payload) {
        Ok(Route::Probe) => "probe",
        Ok(Route::Sink) => "sink",
        Ok(Route::Review) | Err(_) => "review",
    }
}

/// The probe's answer to Cursor. The edge's own probe answer when it routes the
/// call to the sink and its rewrite wrote the snapshot, and a plain allow for
/// everything else, including an edge that gave no answer: `beforeShellExecution`
/// still reviews the call that runs. The edge falls back to the generic rewrite,
/// which keeps the receipt rather than the probe's allow, when its probe answer
/// failed, so only a probe answer counts.
pub(crate) fn probe_response(edge: Option<&Value>) -> Value {
    let allow = json!({ "policy_action": "allow" });
    let Some(edge) = edge else {
        return allow;
    };
    if edge.get("containment_route").and_then(Value::as_str) != Some(SINK_ROUTE) {
        return allow;
    }
    let Some(response) = edge
        .get("harness_response")
        .filter(|value| value.is_object())
    else {
        return allow;
    };
    let mark = edge.get("containment_rewrite").and_then(Value::as_str);
    let kept = mark == Some("kept") && *response == allow;
    let routed = mark == Some("routed")
        && response.get("reason_code").and_then(Value::as_str) == Some(ROUTED_REASON);
    let allows = response.get("policy_action").and_then(Value::as_str) == Some("allow");
    if (kept || routed) && allows {
        response.clone()
    } else {
        allow
    }
}

#[cfg(test)]
#[path = "hook_direct_cursor_route_ops_tests.rs"]
mod tests;
