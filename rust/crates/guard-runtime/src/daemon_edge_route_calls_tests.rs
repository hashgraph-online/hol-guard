use serde_json::{json, Map, Value};

use super::*;

fn payload(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

#[test]
fn routes_name_their_library_calls() {
    for (path, name) in [
        ("/v1/policy/clear", "route.policy_clear"),
        ("/v1/policy/decisions", "route.policy_upsert"),
        ("/v1/policy/resolve", "route.policy_resolve"),
        ("/v1/policy/claim", "route.policy_claim"),
        ("/v1/requests/bulk-allow-once", "route.bulk_allow_once"),
        ("/v1/insights/share", "route.insights_share"),
        (
            "/v1/policy/cloud-exception-requests",
            "route.cloud_exception_request_create",
        ),
    ] {
        assert_eq!(route(path), Some((name, Map::new())), "{path}");
    }
    let (name, args) = route("/v1/requests/r-1/resume").unwrap_or_else(|| unreachable!());
    assert_eq!(name, "route.request_resume_retry");
    assert_eq!(args["request_id"], "r-1");
    // The daemon drops empty segments before it matches.
    assert_eq!(
        route("/v1//requests/r-2/resume/").map(|(_, args)| args["request_id"].clone()),
        Some(json!("r-2"))
    );
    let (name, args) = route("/v1/harnesses/codex/repair").unwrap_or_else(|| unreachable!());
    assert_eq!(name, "route.harness_action");
    assert_eq!(args["harness"], "codex");
    assert_eq!(args["action"], "repair");
    for path in [
        "/v1/harnesses/codex",
        "/v1/policy",
        "/v1/requests/r-1/approve",
        "/v1/requests/resume",
        "/v1/requests/a/b/resume",
    ] {
        assert_eq!(route(path), None, "{path}");
    }
}

#[test]
fn the_call_receives_path_arguments_and_the_body() {
    let mut args = Map::new();
    args.insert("request_id".to_owned(), json!("r-1"));
    let body = payload(json!({"decision": {"a": 1}}));
    let mut seen = Value::Null;
    let reply = respond(args, &body, |value| {
        seen = value;
        Ok(json!({"status": 409, "body": {"claimed": false}, "no_store": false}))
    });
    assert_eq!(reply, Some((409, json!({"claimed": false}), false)));
    assert_eq!(
        seen,
        json!({"request_id": "r-1", "payload": {"decision": {"a": 1}}})
    );
}

#[test]
fn malformed_answers_and_raised_calls_close_the_connection() {
    let body = Map::new();
    for answer in [
        json!({"status": 200, "body": [], "no_store": false}),
        json!({"status": 99, "body": {}, "no_store": false}),
        json!({"status": 200, "body": {}}),
        json!(null),
    ] {
        assert_eq!(
            respond(Map::new(), &body, |_| Ok(answer.clone())),
            Some((DROPPED, Value::Null, false)),
            "{answer}"
        );
    }
    assert_eq!(
        respond(Map::new(), &body, |_| Err(CallError::Raised(Map::new()))),
        Some((DROPPED, Value::Null, false))
    );
    assert_eq!(
        respond(Map::new(), &body, |_| Err(CallError::Unavailable)),
        None
    );
    assert_eq!(
        respond(Map::new(), &body, |_| Ok(
            json!({"status": 200, "body": {"x": 1}, "no_store": true})
        )),
        Some((200, json!({"x": 1}), true))
    );
}

#[test]
fn daemon_handlers_run_behind_one_call() {
    for path in [
        "/v1/context-assistance/workspace-grant",
        "/v1/context-assistance/codex-lean",
        "/v1/harness-versions/acknowledge",
        "/v1/supply-chain/workspace-assessments",
        "/v1/supply-chain/workspace-assessments/pause",
        "/v1/supply-chain/workspace-fix-proposals/p-1/apply",
        "/v1/mcp-policy/requests/r-1/decision",
    ] {
        let (name, args) = route(path).unwrap_or_else(|| unreachable!());
        assert_eq!(name, "route.handler_post", "{path}");
        assert_eq!(args["path"], path);
    }
    for path in [
        "/v1/context-assistance",
        "/v1/harness-versions",
        "/v1/supply-chain/workspace-assessments/delete",
        "/v1/supply-chain/workspace-fix-proposals/p-1",
        "/v1/mcp-policy/requests/r-1",
    ] {
        assert_eq!(route(path), None, "{path}");
    }
}

#[test]
fn repair_and_hook_removal_name_their_route() {
    for path in ["/v1/repair", "/v1/protection/remove-hooks"] {
        let (name, args) = route(path).unwrap_or_else(|| unreachable!());
        assert_eq!(name, "route.repair");
        assert_eq!(args["path"], path);
    }
}
