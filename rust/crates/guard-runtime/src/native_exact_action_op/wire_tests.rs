//! The resident wire reply for native exact-action queries: what it binds,
//! and what it never anchors to.

use serde_json::{json, Value};

fn resident(request: &Value) -> Value {
    let wrapped = json!({"operation": "native_exact_action", "request": request});
    let bytes =
        crate::resident_protocol::evaluate_resident_bytes(wrapped.to_string().as_bytes(), None)
            .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn binding_request(schema: &str) -> Value {
    json!({
        "schema": schema,
        "request_id": "req-binding",
        "query": {
            "kind": "review_binding", "harness": "codex", "command": "cat notes", "workspace_bound": true,
            "facts": {"decision": "ask", "minimum_action": "review", "policy_action": "review", "reason_code": "r"},
            "receipt": {
                "schema": "guard-native-hook-decision-receipt.v1", "version": 1, "authority": "rust",
                "harness": "codex", "event_name": "PreToolUse", "workspace_bound": true,
                "request_digest": "ab".repeat(32), "review_anchor_digest": "cd".repeat(32),
                "decision": "ask", "policy_action": "review", "reason_code": "r"
            },
            "policy_binding": {"state": "unbound"}
        }
    })
}

#[test]
fn wire_reply_is_bound_to_the_request() {
    let reply = resident(&binding_request("guard-native-exact-action-request.v1"));
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["schema"], "guard-native-exact-action-result.v1");
    assert_eq!(reply["request_id"], "req-binding");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let binding = reply["payload"]["binding"].as_str().unwrap();
    assert_eq!(
        binding,
        format!("native-review-v4:{}:ask:review:review:r", "cd".repeat(32))
    );
}

fn binding_for(receipt_fields: Value, policy_binding: Value) -> Option<String> {
    let mut request = binding_request("guard-native-exact-action-request.v1");
    for (key, value) in receipt_fields.as_object().unwrap() {
        request["query"]["receipt"][key] = value.clone();
    }
    request["query"]["policy_binding"] = policy_binding;
    let reply = resident(&request);
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"]["binding"].as_str().map(str::to_owned)
}

/// The retry the user already approved must still match after the publisher
/// republishes the snapshot. `request_digest` folds in the generation and the
/// snapshot digest, which both move on a republish that decided nothing; the
/// anchor does not, so the binding stays put.
#[test]
fn wire_reply_binding_survives_a_republished_request_digest() {
    let anchor = "cd".repeat(32);
    let before = binding_for(
        json!({"request_digest": "ab".repeat(32)}),
        json!({"state": "unbound"}),
    );
    let after = binding_for(
        json!({"request_digest": "ef".repeat(32)}),
        json!({"state": "unbound"}),
    );
    assert_eq!(before, after);
    assert_eq!(
        before.as_deref(),
        Some(format!("native-review-v4:{anchor}:ask:review:review:r").as_str())
    );
    let other_action = binding_for(
        json!({"review_anchor_digest": "12".repeat(32)}),
        json!({"state": "unbound"}),
    );
    assert_ne!(before, other_action);
}

/// An anchor that is not a digest produces no binding at all, so the retry is
/// reviewed again rather than matched on evidence the runtime never proved.
#[test]
fn wire_reply_is_unbound_by_a_malformed_review_anchor() {
    for anchor in [
        json!("short"),
        json!("not-a-digest"),
        json!("AB".repeat(32)),
        json!(7),
    ] {
        assert_eq!(
            binding_for(
                json!({"review_anchor_digest": anchor}),
                json!({"state": "unbound"})
            ),
            None
        );
    }
}

/// A receipt from a runtime that anchors neither keeps the request digest: the
/// republish still moves the binding, but the review is queued as before.
#[test]
fn wire_reply_falls_back_to_the_request_digest_without_an_anchor() {
    let mut request = binding_request("guard-native-exact-action-request.v1");
    request["query"]["receipt"]
        .as_object_mut()
        .unwrap()
        .remove("review_anchor_digest");
    let binding = resident(&request)["payload"]["binding"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        binding,
        format!("native-review-v4:{}:ask:review:review:r", "ab".repeat(32))
    );
}

/// The execution intent never anchors a binding: it drops `guard_home`,
/// `home_dir` and `source_ref_external_allowed`, so an approval anchored to it
/// could be consumed under another guard home. With an anchor beside it the
/// anchor wins; alone it is ignored and the request digest is kept.
#[test]
fn the_execution_intent_never_anchors_the_wire_reply() {
    let beside_the_anchor = binding_for(
        json!({"execution_intent_digest": "12".repeat(32)}),
        json!({"state": "unbound"}),
    );
    assert_eq!(
        beside_the_anchor.as_deref(),
        Some(format!("native-review-v4:{}:ask:review:review:r", "cd".repeat(32)).as_str())
    );
    let mut request = binding_request("guard-native-exact-action-request.v1");
    let receipt = request["query"]["receipt"].as_object_mut().unwrap();
    receipt.remove("review_anchor_digest");
    receipt.insert("execution_intent_digest".into(), json!("12".repeat(32)));
    let intent_only = resident(&request)["payload"]["binding"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        intent_only,
        format!("native-review-v4:{}:ask:review:review:r", "ab".repeat(32))
    );
}

/// A policy binding still sent in the v1 shape keeps its `policy_digest` out
/// of the suffix, while the rules it carries still change the binding.
#[test]
fn the_policy_suffix_ignores_the_snapshot_digest_but_not_the_rules() {
    let bound = |policy_digest: &str, rule_digest: &str| {
        json!({"state": "bound", "value": {
            "schema": "guard-native-review-policy-binding.v1",
            "policy_digest": policy_digest,
            "rule_digest": rule_digest,
            "runtime_identity": "runtime-1",
            "command_extensions": {"uncertainty_count": 0}
        }})
    };
    let first = binding_for(json!({}), bound(&"1".repeat(64), &"a".repeat(64)));
    let republished = binding_for(json!({}), bound(&"2".repeat(64), &"a".repeat(64)));
    let new_rules = binding_for(json!({}), bound(&"2".repeat(64), &"b".repeat(64)));
    assert!(first.is_some());
    assert_eq!(first, republished);
    assert_ne!(first, new_rules);
}

#[test]
fn wire_schema_mismatch_is_an_error_without_payload() {
    let reply = resident(&binding_request("guard-native-exact-action-request.v0"));
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_exact_action_schema_mismatch");
    assert!(reply["payload"].is_null());
}

#[test]
fn wire_exact_action_with_real_engines_answers_a_domain_outcome() {
    let root = std::env::temp_dir().to_string_lossy().into_owned();
    let request = json!({
        "schema": "guard-native-exact-action-request.v1",
        "request_id": "req-exact",
        "query": {
            "kind": "exact_action", "harness": "codex", "tool_name": "Bash", "command": "echo hi",
            "tool_input": [["command", "echo hi"]], "payload_cwd": root, "workspace": root, "home_dir": root,
            "environment": {"PATH": "/usr/bin:/bin"},
            "facts": {"decision": "ask", "minimum_action": "review", "policy_action": "review", "reason_code": "first_seen", "action_type": "shell"},
            "policy_binding": {"state": "unbound"},
            "extension_control_digest": "e".repeat(64), "budget_ms": 20000
        }
    });
    let reply = resident(&request);
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["payload"]["kind"], "exact_action");
    // Whether or not the launch is proven, the review can always be approved.
    assert!(reply["payload"]["once_only_reason"].is_null());
    assert!(reply["payload"]["token"].as_str().is_some());
}
