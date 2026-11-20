//! What a Cursor `PreToolUse` is to the daemon, and what the edge's answer to
//! a route probe means.
//!
//! The daemon asks the resident two questions around its own edge review:
//! which route a call takes (`route_name`), and, for a probe, what the answer
//! to Cursor is once the edge has reviewed it (`probe_response`). Reading
//! either is the resident's, as on the direct lane.

use serde_json::{json, Map, Value};

use super::cursor::{route, Route, ROUTED_REASON};

const SINK_ROUTE: &str = "sink";

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
