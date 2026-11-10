//! Routes the daemon answers by running its own dispatch once behind
//! `desktop library-call` (`routes/offline.py`): reads and writes whose
//! handlers need only the Guard store.
//!
//! The call answers `{"status", "body", "no_store"}`, or `{"relay": true}`
//! when the handler reached for state only a running daemon holds.

use serde_json::{Map, Value};

use super::super::library::{self, CallError};
use super::writes::DROPPED;
use super::ReadConfig;

const GET_ROUTES: [&str; 20] = [
    "/v1/command-activity",
    "/v1/command-activity/analytics",
    "/v1/command-activity/diagnostics",
    "/v1/connect/state",
    "/v1/events",
    "/v1/evidence",
    "/v1/inventory",
    "/v1/policy/cloud-exceptions",
    "/v1/receipts/analytics",
    "/v1/receipts/latest",
    "/v1/sessions",
    "/v1/settings/export",
    "/v1/supply-chain/bundle",
    "/v1/receipts",
    "/v1/requests",
    "/v1/read-state",
    "/v1/settings",
    "/v1/plugins/updates",
    "/v1/network/status",
    "/v1/runtime/containment-health",
];

/// `GET` paths whose reply forbids revalidation as well as storage.
pub(super) const MAX_AGE_ZERO_READS: [&str; 1] = ["/v1/update/status"];

const POST_ROUTES: [&str; 4] = [
    "/v1/policy/sync",
    "/v1/protection/repair/approval-gate/setup",
    "/v1/update/channel",
    "/v1/daemon/repair",
];

/// Whether `GET path` runs the daemon's dispatch when no native read answers it.
pub(super) fn get_routed(path: &str) -> bool {
    GET_ROUTES.contains(&path)
        || matches!(
            crate::daemon_route_paths::segments(path).as_slice(),
            ["v1", "operations", _]
                | ["v1", "mcp-policy", "requests", _]
                | ["v1", "receipts", _]
                | ["v1", "sessions", _, "resume"]
        )
}

/// Whether `POST path` runs the daemon's dispatch.
pub(super) fn post_routed(path: &str) -> bool {
    POST_ROUTES.contains(&path)
}

/// The reply, or `None` to relay the request untouched.
pub(super) fn answer(
    method: &str,
    path: &str,
    query: &str,
    payload: &Map<String, Value>,
    call: impl FnOnce(Value) -> Result<Value, CallError>,
) -> Option<(u16, Value, bool)> {
    let mut args = Map::new();
    args.insert("method".to_owned(), Value::String(method.to_owned()));
    args.insert("path".to_owned(), Value::String(path.to_owned()));
    args.insert("query".to_owned(), Value::String(query.to_owned()));
    args.insert("payload".to_owned(), Value::Object(payload.clone()));
    match call(Value::Object(args)) {
        Ok(answer) if answer.get("relay") == Some(&Value::Bool(true)) => None,
        Ok(answer) => Some(reply(&answer)),
        Err(CallError::Unavailable) => None,
        // The daemon's handler raised: the connection closes unanswered.
        Err(CallError::Raised(_)) => Some((DROPPED, Value::Null, false)),
    }
}

pub(super) fn reply(answer: &Value) -> (u16, Value, bool) {
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

/// Runs `route.dispatch` through the Guard CLI.
pub(super) fn call_library(
    config: &ReadConfig,
) -> impl FnOnce(Value) -> Result<Value, CallError> + '_ {
    move |args| library::call(config, "route.dispatch", args)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn store_only_routes_run_the_dispatch() {
        assert!(!get_routed("/v1/policy"));
        assert!(get_routed("/v1/operations/op-1"));
        assert!(get_routed("/v1/mcp-policy/requests/r1"));
        assert!(!get_routed("/v1/mcp-policy/requests"));
        assert!(!get_routed("/v1/local-clis"));
        assert!(!get_routed("/v1/apps/codex/cloud"));
        assert!(get_routed("/v1/sessions/s1/resume"));
        assert!(!get_routed("/v1/sessions/s1/other"));
        assert!(post_routed("/v1/policy/sync"));
        assert!(!post_routed("/v1/operations/block"));
        assert!(!post_routed("/v1/update"));
    }

    #[test]
    fn replies_relays_and_raised_handlers() {
        let ok = |value: Value| move |_args: Value| Ok::<Value, CallError>(value);
        let payload = Map::new();
        assert_eq!(
            answer(
                "GET",
                "/v1/policy",
                "",
                &payload,
                ok(json!({"status": 200, "body": {"a": 1}, "no_store": true}))
            ),
            Some((200, json!({"a": 1}), true))
        );
        assert_eq!(
            answer(
                "GET",
                "/v1/policy",
                "",
                &payload,
                ok(json!({"relay": true}))
            ),
            None
        );
        assert_eq!(
            answer(
                "GET",
                "/v1/policy",
                "",
                &payload,
                ok(json!({"status": 200, "body": []}))
            ),
            Some((DROPPED, Value::Null, false))
        );
        assert_eq!(
            answer("GET", "/v1/policy", "", &payload, |_| Err(
                CallError::Unavailable
            )),
            None
        );
        assert_eq!(
            answer("POST", "/v1/policy/sync", "", &payload, |_| Err(
                CallError::Raised(Map::new())
            )),
            Some((DROPPED, Value::Null, false))
        );
        let mut seen = Value::Null;
        answer("GET", "/v1/policy", "a=1", &payload, |args| {
            seen = args;
            Err(CallError::Unavailable)
        });
        assert_eq!(
            seen,
            json!({"method": "GET", "path": "/v1/policy", "query": "a=1", "payload": {}})
        );
    }
}
