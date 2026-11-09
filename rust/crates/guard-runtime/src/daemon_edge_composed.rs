//! `GET` routes the daemon composes from Guard library reads: the harness
//! list, the dashboard capabilities, the policy list and the Cloud review and
//! Cloud actions status.
//!
//! The route, the caller check and the reply shape are the daemon's. Work
//! that still lives in the Guard library (harness detection, managed policy
//! annotation, the Cloud status reads) is one `read.*` library call; the
//! Cloud exceptions come from the store.

use serde_json::{json, Map, Value};

use super::super::http::{query_value, Request};
use super::super::library::{self, CallError};
use super::writes::DROPPED;
use super::{dispatch, NativeReads, ReadConfig};
use crate::daemon_handler_headless::detection_statuses;

/// `GUARD_DAEMON_COMPATIBILITY_VERSION`.
const COMPATIBILITY_VERSION: i64 = 2;
/// `_HEADLESS_OPERATIONS`; each harness lists all but the last.
const HEADLESS_OPERATIONS: [&str; 6] = [
    "install",
    "repair",
    "remove",
    "status",
    "scan",
    "policy_sync",
];
const PACKAGE_FIREWALL_OPERATIONS: [&str; 8] = [
    "status", "connect", "install", "repair", "test", "audit", "sync", "remove",
];

/// `GET` paths whose Guard library handler writes the whole reply.
const HANDLER_READS: [&str; 11] = [
    "/v1/context-assistance",
    "/v1/context-assistance/installations",
    "/v1/context-assistance/codex-lean",
    "/v1/context-assistance/usage",
    "/v1/context-assistance/versions",
    "/v1/context-assistance/jobs",
    "/v1/context-assistance/interpreters",
    "/v1/context-assistance/catalog",
    "/v1/policy/cloud-exception-requests",
    "/v1/supply-chain/workspace-assessments",
    "/v1/supply-chain/workspace-findings",
];
/// `GET` on this path lists the workspace fix proposals.
const FIX_PROPOSALS: &str = "/v1/supply-chain/workspace-fix-proposals";

/// Whether the daemon composes `path` itself.
pub(super) fn routed(path: &str) -> bool {
    HANDLER_READS.contains(&path)
        || path == FIX_PROPOSALS
        || matches!(
            path,
            "/v1/harnesses"
                | "/v1/capabilities"
                | "/v1/policy"
                | "/v1/cloud-review"
                | "/v1/cloud-actions/status"
        )
}

/// The reply for `request`, or `None` when the library could not answer and
/// the request is relayed.
pub(super) fn respond(
    request: &Request<'_>,
    config: &ReadConfig,
    reads: &NativeReads,
    dashboard_session: bool,
) -> Option<(u16, Value, bool)> {
    let call = |name: &str, args: Value| library::call(config, name, args);
    match request.path {
        "/v1/harnesses" => {
            let setup = match call("read.harness_setup", json!({})) {
                Ok(setup) => setup,
                Err(error) => return raised(error),
            };
            let items = setup.get("items").filter(|items| items.is_array())?;
            Some((200, json!({ "items": items }), false))
        }
        "/v1/capabilities" => {
            let setup = match call("read.harness_setup", json!({})) {
                Ok(setup) => setup,
                Err(error) => return raised(error),
            };
            Some((200, capabilities(&setup, dashboard_session)?, false))
        }
        "/v1/policy" => {
            let harness = query_value(request.query, "harness").ok()?;
            let items = match call("read.managed_policy_rows", json!({ "harness": harness })) {
                Ok(items) if items.is_array() => items,
                Ok(_) => return Some((DROPPED, Value::Null, false)),
                Err(error) => return raised(error),
            };
            let exceptions = reads.store_call(
                config,
                "list_cloud_exceptions",
                json!({ "harness": harness }),
            )?;
            exceptions.is_array().then(|| {
                (
                    200,
                    json!({ "items": items, "cloud_exceptions": exceptions }),
                    false,
                )
            })
        }
        "/v1/cloud-review" => whole_reply(call("read.cloud_review_status", json!({}))),
        "/v1/cloud-actions/status" => whole_reply(call("read.cloud_actions_status", json!({}))),
        path if HANDLER_READS.contains(&path) || path == FIX_PROPOSALS => whole_reply(call(
            "route.handler_get",
            json!({ "path": path, "query": request.query }),
        )),
        _ => None,
    }
}

/// `GET /v1/capabilities` from the harness setup items.
pub(super) fn capabilities(setup: &Value, dashboard_session: bool) -> Option<Value> {
    let items = setup.get("items")?.as_array()?;
    let package_version = setup.get("package_version").cloned().unwrap_or(Value::Null);
    let listed: Vec<&Map<String, Value>> = items
        .iter()
        .filter_map(Value::as_object)
        .filter(|item| item.get("harness").is_some_and(Value::is_string))
        .collect();
    let statuses: Vec<String> = listed
        .iter()
        .map(|item| python_str(item.get("status")))
        .collect();
    let (_, _, _, fields) = detection_statuses(&statuses).into_parts();
    let app_statuses = fields.get("app_statuses")?.as_array()?.clone();
    if app_statuses.len() != listed.len() {
        return None;
    }
    let failure_reasons = safe_failure_reasons();
    let harness_operations = &HEADLESS_OPERATIONS[..HEADLESS_OPERATIONS.len() - 1];
    let supported: Vec<Value> = listed
        .iter()
        .zip(app_statuses)
        .map(|(item, status)| {
            json!({
                "display_name": item.get("display_name").cloned().unwrap_or(Value::Null),
                "harness": item["harness"],
                "status": status,
                "command_available": truthy(item.get("command_available")),
                "headless_actions": harness_operations,
                "safe_failure_reasons": failure_reasons,
            })
        })
        .collect();
    let mut harnesses: Vec<&str> = supported
        .iter()
        .filter_map(|item| item["harness"].as_str())
        .collect();
    harnesses.sort_unstable();
    let command_available = items
        .iter()
        .any(|item| truthy(item.get("command_available")));
    Some(json!({
        "auth_state": if dashboard_session { "dashboard_session" } else { "local_token" },
        "command_available": command_available,
        "daemon": {
            "compatibility_version": COMPATIBILITY_VERSION,
            "package_version": package_version,
            "platform": platform(),
        },
        "headless_api": {
            "execution_mode": "guard_cloud_command_queue",
            "operations": HEADLESS_OPERATIONS,
        },
        "package_firewall_api": {
            "execution_mode": "guard_cloud_command_queue",
            "operations": PACKAGE_FIREWALL_OPERATIONS,
        },
        "safe_failure_reasons": failure_reasons,
        "supported_harnesses": harnesses,
        "items": supported,
    }))
}

/// `_headless_safe_failure_reasons()`.
fn safe_failure_reasons() -> Value {
    json!({
        "offline": "Local Guard daemon is unavailable.",
        "timeout": "Local Guard daemon did not answer before the browser timeout.",
        "unauthorized": "Dashboard session is missing or stale.",
        "unsupported": "Harness is not supported by this daemon.",
        "confirmation_required": "Remove actions need the harness confirmation phrase.",
    })
}

/// `platform.system().lower()`.
fn platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "" => "unknown",
        other => other,
    }
}

/// Python's `bool(value)` for a JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(fields)) => !fields.is_empty(),
    }
}

/// Python's `str(value)` for the status values detection reports.
fn python_str(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Bool(true)) => "True".to_owned(),
        Some(Value::Bool(false)) => "False".to_owned(),
        Some(other) => other.to_string(),
    }
}

/// The reply a call that shapes the whole reply returned.
fn whole_reply(answer: Result<Value, CallError>) -> Option<(u16, Value, bool)> {
    match answer {
        Ok(answer) => Some(dispatch::reply(&answer)),
        Err(error) => raised(error),
    }
}

/// A library call that raised drops the connection, as the daemon's handler
/// did; one that could not run relays the request.
fn raised(error: CallError) -> Option<(u16, Value, bool)> {
    match error {
        CallError::Unavailable => None,
        CallError::Raised(_) => Some((DROPPED, Value::Null, false)),
    }
}

#[cfg(test)]
#[path = "daemon_edge_composed_tests.rs"]
mod tests;
