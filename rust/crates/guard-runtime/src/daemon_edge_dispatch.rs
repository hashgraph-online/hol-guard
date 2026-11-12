//! Store reads the edge answers natively, and the reply shape the Guard
//! library's route calls answer: `{"status", "body", "no_store"}`.
//!
//! A read on one of these paths that the edge could not answer is a store
//! outage, answered `503`, never handed to another process.

use serde_json::Value;

use super::writes::DROPPED;

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

/// Paths whose reply forbids revalidation as well as storage.
pub(super) const MAX_AGE_ZERO_PATHS: [&str; 2] = ["/v1/update/status", "/v1/update/channel"];

/// Whether `GET path` is a store read the edge owns: one it cannot answer is `503`.
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

/// `(status, body, no_store)` from a route call's answer, or a dropped
/// connection when the answer is malformed.
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn store_reads_are_owned_by_the_edge() {
        assert!(!get_routed("/v1/policy"));
        assert!(get_routed("/v1/operations/op-1"));
        assert!(get_routed("/v1/mcp-policy/requests/r1"));
        assert!(!get_routed("/v1/mcp-policy/requests"));
        assert!(!get_routed("/v1/local-clis"));
        assert!(!get_routed("/v1/apps/codex/cloud"));
        assert!(get_routed("/v1/sessions/s1/resume"));
        assert!(!get_routed("/v1/sessions/s1/other"));
    }

    #[test]
    fn replies_keep_well_formed_answers_only() {
        assert_eq!(
            reply(&json!({"status": 200, "body": {"a": 1}, "no_store": true})),
            (200, json!({"a": 1}), true)
        );
        assert_eq!(
            reply(&json!({"status": 200, "body": []})),
            (DROPPED, Value::Null, false)
        );
        assert_eq!(
            reply(&json!({"status": 700, "body": {}, "no_store": false})),
            (DROPPED, Value::Null, false)
        );
    }
}
