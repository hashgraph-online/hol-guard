//! Control routes whose work is one Guard library call that also shapes the
//! reply: policy writes and lookups, bulk allow-once and the resume retry.
//!
//! The route, the caller check and the body read are the daemon's. The call
//! answers `{"status", "body", "no_store"}` and the daemon writes exactly
//! that; see `control_route_calls.py`.

use serde_json::{Map, Value};

use super::super::super::library::{self, CallError};
use super::DROPPED;

/// The library call that answers `POST path`, with its path arguments.
pub(in crate::daemon_edge) fn route(path: &str) -> Option<(&'static str, Map<String, Value>)> {
    let name = match path {
        "/v1/policy/clear" => "route.policy_clear",
        "/v1/policy/decisions" => "route.policy_upsert",
        "/v1/policy/resolve" => "route.policy_resolve",
        "/v1/policy/claim" => "route.policy_claim",
        "/v1/requests/bulk-allow-once" => "route.bulk_allow_once",
        "/v1/insights/share" => "route.insights_share",
        "/v1/policy/cloud-exception-requests" => "route.cloud_exception_request_create",
        _ => return segment_route(path),
    };
    Some((name, Map::new()))
}

/// Routes with path arguments, split as the daemon splits its path.
fn segment_route(path: &str) -> Option<(&'static str, Map<String, Value>)> {
    // The daemon answers its extension-control and local-CLI paths first.
    if crate::daemon_route_paths::route_class(path) != "none" {
        return None;
    }
    let parts = crate::daemon_route_paths::segments(path);
    let (name, fields) = match parts.as_slice() {
        ["v1", "requests", request_id, "resume"] => (
            "route.request_resume_retry",
            vec![("request_id", *request_id)],
        ),
        ["v1", "harnesses", harness, action] => (
            "route.harness_action",
            vec![("harness", *harness), ("action", *action)],
        ),
        _ => return None,
    };
    let args = fields
        .into_iter()
        .map(|(key, value)| (key.to_owned(), Value::String(value.to_owned())))
        .collect();
    Some((name, args))
}

/// The reply: status, body and whether it must not be cached. `None` when
/// the library could not be reached, so the request is relayed untouched.
pub(in crate::daemon_edge) fn respond(
    mut args: Map<String, Value>,
    payload: &Map<String, Value>,
    call: impl FnOnce(Value) -> Result<Value, CallError>,
) -> Option<(u16, Value, bool)> {
    args.insert("payload".to_owned(), Value::Object(payload.clone()));
    match call(Value::Object(args)) {
        Ok(answer) => Some(reply(answer)),
        Err(CallError::Unavailable) => None,
        // The daemon's handler raised: the connection closes unanswered.
        Err(CallError::Raised(_)) => Some((DROPPED, Value::Null, false)),
    }
}

fn reply(answer: Value) -> (u16, Value, bool) {
    let status = answer
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .filter(|status| (100..600).contains(status));
    let no_store = answer.get("no_store").and_then(Value::as_bool);
    match (status, answer.get("body"), no_store) {
        (Some(status), Some(body @ Value::Object(_)), Some(no_store)) => {
            (status, body.clone(), no_store)
        }
        _ => (DROPPED, Value::Null, false),
    }
}

/// Runs `name` through the Guard CLI.
pub(in crate::daemon_edge) fn call_library<'a>(
    config: &'a super::super::ReadConfig,
    name: &'a str,
) -> impl FnOnce(Value) -> Result<Value, CallError> + 'a {
    move |args| library::call(config, name, args)
}

#[cfg(test)]
#[path = "daemon_edge_route_calls_tests.rs"]
mod tests;
