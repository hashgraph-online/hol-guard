use std::cell::RefCell;
use std::net::SocketAddr;

use serde_json::{json, Map, Value};

use super::*;

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn local() -> SocketAddr {
    "127.0.0.1:5474".parse().unwrap_or_else(|_| unreachable!())
}

fn payload(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn raised(value: Value) -> Result<Value, CallError> {
    Err(CallError::Raised(payload(value)))
}

#[test]
fn owns_only_the_resolution_routes() {
    for path in [
        "/v1/requests/r1/approve",
        "/v1/requests/r1/block",
        "/approvals/r1/decision",
        "/v1/approvals/r1/decision",
    ] {
        assert!(owns(path), "{path}");
    }
    for path in [
        "/v1/requests/r1/resume",
        "/v1/requests/clear",
        "/v1/settings",
    ] {
        assert!(!owns(path), "{path}");
    }
}

#[test]
fn invalid_fields_answer_before_the_library_runs() {
    let cases = [
        (
            "/v1/requests/r1/approve",
            json!({}),
            "missing_required_fields",
        ),
        (
            "/v1/requests/r1/approve",
            json!({"scope": "artifact", "scope_contract_version": "v9"}),
            "invalid_scope_contract_version",
        ),
        (
            "/v1/requests/r1/approve",
            json!({"scope": "artifact", "scope_contract_digest": "ABC"}),
            "invalid_scope_contract_digest",
        ),
        (
            "/approvals/r1/decision",
            json!({"scope": "artifact"}),
            "missing_required_fields",
        ),
    ];
    for (path, body, error) in cases {
        let reply = respond(path, &payload(body), local(), true, |_| {
            panic!("not called")
        });
        assert_eq!(
            reply,
            Some((400, json!({"resolved": false, "error": error}), false)),
            "{path}"
        );
    }
}

#[test]
fn library_receives_the_resolved_request() {
    let seen = RefCell::new(Value::Null);
    let body = json!({
        "scope": " artifact ",
        "scope_contract_version": "guard.approval-scopes.v7",
        "scope_contract_digest": DIGEST,
        "remember": "yes",
    });
    let reply = respond(
        "/v1/requests/r1/block",
        &payload(body.clone()),
        local(),
        true,
        |args| {
            *seen.borrow_mut() = args;
            Ok(json!({"updated": {"resolved": true, "copy": {"title": "t", "body": "b"}}}))
        },
    );
    assert_eq!(
        reply,
        Some((
            200,
            json!({"resolved": true, "copy": {"title": "t", "body": "b"}}),
            false
        ))
    );
    let args = seen.into_inner();
    assert_eq!(args["request_id"], "r1");
    assert_eq!(args["action"], "block");
    assert_eq!(args["scope"], "artifact");
    assert_eq!(args["scope_contract_version"], "guard.approval-scopes.v7");
    assert_eq!(args["scope_contract_digest"], DIGEST);
    assert_eq!(args["payload"], body);
    assert_eq!(args["resolve_scope_matches"], true);
    assert_eq!(args["copy"], copy_table("block"));
}

#[test]
fn copy_names_each_harness() {
    let table = copy_table("allow");
    assert_eq!(
        table["codex"],
        json!({"title": "Approved. Retry in chat.", "body": "Return to Codex and retry"})
    );
    assert_eq!(table["omp"]["body"], "Return to Oh My Pi and retry");
    assert_eq!(
        copy_table("block")[""],
        json!({"title": "Blocked. Decision saved.", "body": "Return to your AI assistant and retry"})
    );
}

#[test]
fn library_answers_map_to_daemon_replies() {
    let path = "/v1/requests/r1/approve";
    let body = payload(json!({"scope": "artifact"}));
    let reply = |answer: Result<Value, CallError>| respond(path, &body, local(), true, |_| answer);
    assert_eq!(
        reply(Ok(
            json!({"idempotent": {"resolved": true, "idempotent": true}})
        )),
        Some((200, json!({"resolved": true, "idempotent": true}), false))
    );
    let (status, conflict, _) =
        reply(Ok(json!({"already_resolved": true}))).unwrap_or_else(|| unreachable!());
    assert_eq!(status, 409);
    assert_eq!(conflict["error"], "already_resolved");
    assert_eq!(
        conflict["recovery"]["queue_url"],
        "http://127.0.0.1:5474/#/inbox"
    );
    assert_eq!(
        conflict["recovery"]["body"],
        "If the action is blocked and you believe it should be allowed, you can re-submit from your AI assistant."
    );
    let (status, missing, _) = reply(raised(json!({"kind": "not_found", "message": "Unknown"})))
        .unwrap_or_else(|| unreachable!());
    assert_eq!(status, 404);
    assert_eq!(missing["recovery"]["code"], "request_unknown");
    assert_eq!(
        reply(raised(
            json!({"kind": "stale_scope_contract", "message": "stale_scope_contract", "contract": {"scope_contract_digest": "d"}})
        )),
        Some((
            409,
            json!({"resolved": false, "error": "stale_scope_contract", "scope_contract_digest": "d"}),
            false
        ))
    );
    assert_eq!(
        reply(raised(
            json!({"kind": "ineligible_scope", "message": "m", "action": "allow", "requested_scope": "global", "contract": {"x": 1}})
        )),
        Some((
            422,
            json!({"resolved": false, "error": "m", "action": "allow", "requested_scope": "global", "x": 1}),
            false
        ))
    );
    assert_eq!(
        reply(raised(json!({"kind": "scope_unavailable", "message": ""}))),
        Some((
            503,
            json!({"resolved": false, "error": "native_approval_scope_unavailable"}),
            true
        ))
    );
    assert_eq!(
        reply(raised(
            json!({"kind": "local_tool_grant_unavailable", "message": "gone"})
        )),
        Some((503, json!({"resolved": false, "error": "gone"}), true))
    );
    assert_eq!(
        reply(raised(
            json!({"kind": "value", "message": "invalid boolean value"})
        )),
        Some((
            400,
            json!({"resolved": false, "error": "invalid boolean value"}),
            false
        ))
    );
    assert_eq!(
        reply(raised(
            json!({"kind": "approval_gate", "message": "m", "status": 403, "payload": {"error": "approval_gate_required"}})
        )),
        Some((
            403,
            json!({"error": "approval_gate_required", "resolved": false}),
            false
        ))
    );
    assert_eq!(
        reply(raised(json!({"kind": "unexpected", "message": "boom"}))),
        Some((DROPPED, Value::Null, false))
    );
    assert_eq!(reply(Err(CallError::Unavailable)), None);
}

#[test]
fn ipv6_queue_links_are_bracketed() {
    let local: SocketAddr = "[::1]:9".parse().unwrap_or_else(|_| unreachable!());
    let reply = respond(
        "/v1/requests/r1/approve",
        &payload(json!({"scope": "artifact"})),
        local,
        true,
        |_| raised(json!({"kind": "not_found", "message": ""})),
    );
    assert_eq!(
        reply.map(|(_, body, _)| body["recovery"]["queue_url"].clone()),
        Some(json!("http://[::1]:9/#/inbox"))
    );
}
