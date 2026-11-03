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

/// Every payload that rewrites a tool decision also names the action the
/// rewritten decision enforces; the caller copies it instead of keeping the
/// pre-rewrite one.
#[test]
fn a_rewritten_decision_carries_the_action_it_enforces() {
    let facts = |action: &str, current: Value| {
        json!({
            "action": action,
            "source": "policy",
            "current_action": current,
            "saved_action": null,
            "approval_reuse_status": null,
            "approval_reuse_reason_code": null,
            "has_pending": true,
        })
    };
    let gate = |decision: Value| {
        reply(&request(
            MCP_PROXY_DECISION_REQUEST_SCHEMA,
            json!({
                "check": "saved_allow_gate",
                "catalog_state": "unobserved",
                "decision": decision,
            }),
        ))["payload"]
            .clone()
    };

    // The gate rejects the saved authority, so a review becomes a fresh
    // approval boundary while an executable action stays itself.
    let stale = gate(facts("review", Value::Null));
    assert_eq!(stale["action"], "review");
    assert_eq!(stale["policy_action"], "require-reapproval");
    let warn = gate(facts("warn", Value::Null));
    assert_eq!(warn["action"], "warn");
    assert_eq!(warn["policy_action"], "warn");

    let mut rejected = facts("allow", json!("review"));
    rejected["approval_reuse_status"] = json!("rejected");
    rejected["approval_reuse_reason_code"] = json!("approval_reuse_tool_catalog_incomplete");
    let observed = reply(&request(
        MCP_PROXY_DECISION_REQUEST_SCHEMA,
        json!({
            "check": "route_tool_call",
            "mode": "observe",
            "package_present": false,
            "asks_for_approval": false,
            "inline_available": false,
            "tool_name": "demo",
            "decision": rejected,
        }),
    ))["payload"]
        .clone();
    assert_eq!(observed["decision_override"]["action"], "review");
    assert_eq!(
        observed["decision_override"]["policy_action"],
        "require-reapproval"
    );

    let packaged = reply(&request(
        MCP_PROXY_DECISION_REQUEST_SCHEMA,
        json!({
            "check": "route_tool_call",
            "mode": "enforce",
            "package_present": true,
            "asks_for_approval": true,
            "inline_available": false,
            "tool_name": "demo",
            "decision": facts("review", Value::Null),
            "package_saved_policy_blocks": false,
            "native_prompt_allows": true,
        }),
    ))["payload"]
        .clone();
    assert_eq!(packaged["route"]["tool_source"], "native-approved");
    assert_eq!(packaged["route"]["decision_policy_action"], "allow");
}

#[test]
fn an_inline_approval_answer_reaches_the_classifier_over_the_op() {
    let answered = reply(&request(
        MCP_PROXY_DECISION_REQUEST_SCHEMA,
        json!({
            "check": "inline_approval_reply",
            "payload": {"action": "accept", "content": {"decision": "deny"}},
            "tool_name": "demo",
            "server_name": "files",
        }),
    ));
    assert_eq!(answered["status"], "ok");
    assert_eq!(answered["payload"]["inline_approval"], "denied");
    assert_eq!(
        answered["payload"]["block"]["decision_source"],
        "inline-denied"
    );
}

fn binding_required(evaluation: Value) -> Value {
    reply(&request(
        MCP_PROXY_DECISION_REQUEST_SCHEMA,
        json!({"check": "external_archive_binding_required", "evaluation": evaluation}),
    ))["payload"]["required"]
        .clone()
}

#[test]
fn an_evaluation_that_resolved_a_tarball_demands_its_binding() {
    // Any of the three places the evaluator records it answers for the whole
    // evaluation: the source hashes it verified, its own reasons, or the
    // reasons of one package inside it.
    assert_eq!(binding_required(json!({})), json!(false));
    assert_eq!(
        binding_required(json!({"external_archive_source_hashes": ["a".repeat(64)]})),
        json!(true)
    );
    assert_eq!(
        binding_required(json!({"external_archive_source_hashes": ["a".repeat(63)]})),
        json!(false)
    );
    assert_eq!(
        binding_required(json!({"reasons": [{"code": "external_tarball_source"}]})),
        json!(true)
    );
    assert_eq!(
        binding_required(json!({"reasons": [{"code": "other"}]})),
        json!(false)
    );
    assert_eq!(
        binding_required(json!({"packages": [{"reasons": [{"code": "external_tarball_source"}]}]})),
        json!(true)
    );
    // Entries of the wrong shape are not reasons, and must not read as one.
    assert_eq!(
        binding_required(json!({"reasons": "external_tarball_source", "packages": ["x"]})),
        json!(false)
    );
}

#[test]
fn a_source_hash_is_measured_in_characters() {
    // Python counts characters, so a 64-character hash stays one here however
    // many bytes it encodes to, and a 64-byte string that is shorter than 64
    // characters is not one. The second case is where counting bytes used to
    // demand a binding Python never demanded; these assertions pin the lane to
    // Python's answer in both directions rather than to a stricter rule.
    assert_eq!(
        binding_required(json!({"external_archive_source_hashes": ["é".repeat(64)]})),
        json!(true)
    );
    assert_eq!(
        binding_required(json!({"external_archive_source_hashes": ["é".repeat(32)]})),
        json!(false)
    );
}
