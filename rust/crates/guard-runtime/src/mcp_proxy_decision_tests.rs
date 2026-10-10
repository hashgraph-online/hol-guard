//! Envelope and fail-closed behavior of the MCP proxy decision op.

use guard_contracts::{McpProxyDecisionRequestV1, MCP_PROXY_DECISION_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::mcp_proxy_decision_op::evaluate_mcp_proxy_decision;

fn request(schema: &str, query: Value) -> McpProxyDecisionRequestV1 {
    serde_json::from_value(json!({
        "schema": schema,
        "request_id": "req-1",
        "query": query,
    }))
    .unwrap()
}

fn reply(request: &McpProxyDecisionRequestV1) -> Value {
    serde_json::from_slice(&evaluate_mcp_proxy_decision(request).unwrap()).unwrap()
}

fn precheck() -> Value {
    json!({
        "check": "package_precheck",
        "mode": "enforce",
        "saved_policy_blocks": false,
        "policy_action": "block",
    })
}

#[test]
fn the_reply_is_bound_to_the_request() {
    let first = reply(&request(MCP_PROXY_DECISION_REQUEST_SCHEMA, precheck()));
    assert_eq!(first["status"], "ok");
    assert_eq!(first["request_id"], "req-1");
    assert_eq!(first["payload"]["kind"], "terminal");
    let mut other = precheck();
    other["policy_action"] = json!("allow");
    let second = reply(&request(MCP_PROXY_DECISION_REQUEST_SCHEMA, other));
    assert_ne!(first["request_sha256"], second["request_sha256"]);
    assert!(first["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn a_foreign_schema_is_an_error_without_a_payload() {
    let reply = reply(&request("guard-other.v1", precheck()));
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_mcp_proxy_decision_schema_mismatch");
    assert_eq!(reply["payload"], Value::Null);
}

#[test]
fn unknown_fields_and_checks_do_not_deserialize() {
    let mut extra = precheck();
    extra["unexpected"] = json!(true);
    let envelope = |query: Value| {
        serde_json::from_value::<McpProxyDecisionRequestV1>(json!({
            "schema": MCP_PROXY_DECISION_REQUEST_SCHEMA,
            "request_id": "r",
            "query": query,
        }))
    };
    assert!(envelope(extra).is_err());
    assert!(envelope(json!({ "check": "invented" })).is_err());
}

#[test]
fn an_unknown_action_never_authorizes_execution() {
    let mut unknown = precheck();
    unknown["policy_action"] = json!("monitor");
    unknown["mode"] = json!("enforce");
    let reply = reply(&request(MCP_PROXY_DECISION_REQUEST_SCHEMA, unknown));
    assert_eq!(reply["payload"]["kind"], "queue");
    assert_eq!(reply["payload"]["policy_action"], "review");
}

#[test]
fn a_capture_for_a_stale_generation_leaves_a_poisoned_catalog_alone() {
    let state = json!({
        "state": "error", "generation": 3, "inflight": false,
        "inflight_cursor": null, "expected_cursor": null,
        "catalog_names": [], "pending_names": null,
    });
    let capture = json!({
        "check": "catalog_event", "state": state,
        "event": {
            "kind": "capture", "cursor": {"kind": "none"}, "request_generation": 2,
            "response": {"result": {"tools": [{"name": "a"}]}},
        },
    });
    let reply = reply(&request(MCP_PROXY_DECISION_REQUEST_SCHEMA, capture));
    assert_eq!(reply["payload"]["state"]["state"], "error");
    assert_eq!(reply["payload"]["catalog_names"], json!([]));
}

#[test]
fn sandbox_required_is_never_downgraded_and_unknown_actions_floor_at_review() {
    use crate::mcp_proxy_actions::{most_restrictive, norm};
    use guard_contracts::GuardAction;

    for weaker in ["allow", "warn", "review", "require-reapproval"] {
        let weaker = norm(weaker, GuardAction::Review);
        assert_eq!(
            most_restrictive(GuardAction::SandboxRequired, weaker),
            GuardAction::SandboxRequired
        );
        assert_eq!(
            most_restrictive(weaker, GuardAction::SandboxRequired),
            GuardAction::SandboxRequired
        );
    }
    let unknown = norm("future-action", GuardAction::Review);
    assert_eq!(
        most_restrictive(GuardAction::Allow, unknown),
        GuardAction::Review
    );
    assert_eq!(
        most_restrictive(unknown, GuardAction::Warn),
        GuardAction::Review
    );
}
