//! Language-neutral vectors and transport binding checks for `HookDecide`.

use guard_contracts::HOOK_DECISION_REQUEST_SCHEMA;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../tests/fixtures/hook_decision_vectors.json");

fn try_resident(query: &Value) -> Result<Value, String> {
    let request = json!({
        "operation": "hook_decide",
        "request": {
            "schema": HOOK_DECISION_REQUEST_SCHEMA,
            "request_id": "req-hook",
            "query": query,
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)?;
    Ok(serde_json::from_slice(&out).unwrap())
}

fn resident(query: &Value) -> Value {
    try_resident(query).expect("hook decision op should answer")
}

/// The reply's error code, whether the resident raised it or bound it in an
/// `error` result.
fn rejection(query: &Value) -> Option<String> {
    match try_resident(query) {
        Err(code) => Some(code),
        Ok(reply) if reply["status"] == "error" => reply["code"].as_str().map(str::to_owned),
        Ok(_) => None,
    }
}

/// `expected` is a recursive subset of `actual`: objects match by the keys
/// listed, everything else (arrays, scalars) must be equal.
fn subset(expected: &Value, actual: &Value, path: &str) -> Result<(), String> {
    match (expected, actual) {
        (Value::Object(want), Value::Object(have)) => {
            for (key, value) in want {
                let found = have
                    .get(key)
                    .ok_or_else(|| format!("{path}.{key}: missing"))?;
                subset(value, found, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        _ if expected == actual => Ok(()),
        _ => Err(format!("{path}: expected {expected}, got {actual}")),
    }
}

#[test]
fn matches_language_neutral_vectors() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 80);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        // The native tool-action classifier is a unix-only module.
        if cfg!(not(unix)) && vector.get("requires_unix") == Some(&json!(true)) {
            continue;
        }
        if let Some(code) = vector.get("error") {
            assert_eq!(
                rejection(&vector["query"]).as_deref(),
                code.as_str(),
                "{name}"
            );
            continue;
        }
        let reply = try_resident(&vector["query"]).unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(reply["status"], "ok", "{name}: {reply}");
        let payload = &reply["payload"];
        if let Err(message) = subset(&vector["expect"], payload, "payload") {
            panic!("{name}: {message}\nactual: {payload:#}");
        }
    }
}

#[test]
fn resident_transport_binds_request_and_digest() {
    let query = json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": "allow",
        "post_claim_refresh_failed": false, "context_changed": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }});
    let reply = resident(&query);
    assert_eq!(reply["schema"], "guard-hook-decision-result.v1");
    assert_eq!(reply["request_id"], "req-hook");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["kind"], "post_claim_reuse");
    let again = resident(&query);
    assert_eq!(reply["request_sha256"], again["request_sha256"]);
    let other = resident(&json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "block", "reuse_action": "block", "reuse_saved_action": null,
        "post_claim_refresh_failed": false, "context_changed": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }}));
    assert_ne!(reply["request_sha256"], other["request_sha256"]);
}

#[test]
fn schema_mismatch_is_an_error_not_a_decision() {
    let request = json!({
        "operation": "hook_decide",
        "request": {"schema": "other.v1", "request_id": "r", "query": {
            "kind": "post_claim_reuse", "inputs": {
                "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": null,
                "post_claim_refresh_failed": false, "context_changed": false,
                "has_ignored_integrity": false, "claim_row_invalid": false}}}
    });
    let outcome =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None);
    assert_eq!(outcome.unwrap_err(), "native_hook_decision_schema_mismatch");
}

#[test]
fn unknown_query_fields_are_rejected() {
    let outcome = try_resident(&json!({"kind": "post_claim_reuse", "inputs": {}, "extra": 1}));
    assert!(outcome.is_err());
}

#[test]
fn rejected_query_is_a_bound_error_reply_with_its_code() {
    let reply = resident(&json!({
        "kind": "post_claim_reuse", "inputs": {
            "current_policy_action": "bogus", "reuse_action": "allow", "reuse_saved_action": null,
            "post_claim_refresh_failed": false, "context_changed": false,
            "has_ignored_integrity": false, "claim_row_invalid": false}}));
    assert_eq!(reply["status"], "error");
    assert!(reply["payload"].is_null());
    assert!(reply["code"]
        .as_str()
        .is_some_and(|code| code.starts_with("native_hook_decision_")));
    assert_eq!(reply["request_id"], "req-hook");
    assert!(reply["request_sha256"].as_str().is_some());
}

const SAVED_TOKEN: &str = concat!(
    "guard-approval-context:v1:",
    "eyJjYXBhYmlsaXRpZXMiOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiY29udGVudCI6ImJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIiLCJpZGVudGl0eSI6ImNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJwb2xpY3kiOiJkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIiwic2FuZGJveCI6ImVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWUiLCJ2ZXJzaW9uIjoxfQ"
);
const MOVED_TOKEN: &str = concat!(
    "guard-approval-context:v1:",
    "eyJjYXBhYmlsaXRpZXMiOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiY29udGVudCI6ImZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmYiLCJpZGVudGl0eSI6ImNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJwb2xpY3kiOiJkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkIiwic2FuZGJveCI6ImVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWUiLCJ2ZXJzaW9uIjoxfQ"
);

/// A post-claim request that names both context tokens, so the resident
/// compares them and composes the reuse decision itself.
fn claim_with_tokens(saved: Value, current: Value) -> Value {
    json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": "allow",
        "post_claim_refresh_failed": false,
        "claimed_context_token": saved, "current_context_token": current,
        "fresh_local_approval": true, "durable_exact_approval": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }})
}

#[test]
fn a_caller_that_compares_the_tokens_itself_gets_no_composition() {
    let payload = &resident(&json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": "allow",
        "post_claim_refresh_failed": false, "context_changed": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }}))["payload"];
    assert_eq!(payload["current_action"], "allow");
    assert!(payload["validation_reason"].is_null());
    assert!(payload.get("reuse").is_none());
}

#[test]
fn a_request_that_settles_the_context_neither_way_is_refused() {
    let code = rejection(&json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": "allow",
        "post_claim_refresh_failed": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }}));
    assert_eq!(code.as_deref(), Some("native_hook_decision_facts_missing"));
}

#[test]
fn an_unmoved_context_keeps_the_claimed_allow() {
    let payload = &resident(&claim_with_tokens(
        Value::from(SAVED_TOKEN),
        Value::from(SAVED_TOKEN),
    ))["payload"];
    assert_eq!(payload["current_action"], "allow");
    assert!(payload["validation_reason"].is_null());
    assert_eq!(payload["reuse"]["action"], "allow");
    assert_eq!(payload["reuse"]["saved_action"], "allow");
    assert_eq!(
        payload["reuse"]["saved_artifact_hash_is_context_token"],
        true
    );
}

#[test]
fn a_moved_context_never_reuses_the_claimed_allow() {
    let payload = &resident(&claim_with_tokens(
        Value::from(SAVED_TOKEN),
        Value::from(MOVED_TOKEN),
    ))["payload"];
    assert_eq!(payload["current_action"], "require-reapproval");
    assert_eq!(
        payload["validation_reason"],
        "approval_reuse_context_changed_after_claim"
    );
    assert_eq!(payload["reuse"]["action"], "require-reapproval");
    assert_eq!(payload["reuse"]["status"], "rejected");
    assert_eq!(
        payload["reuse"]["saved_artifact_hash_is_context_token"],
        true
    );
}

#[test]
fn a_legacy_stored_hash_is_named_as_one_and_cannot_prove_the_context() {
    let payload = &resident(&claim_with_tokens(
        Value::from("sha256:legacy"),
        Value::from(SAVED_TOKEN),
    ))["payload"];
    assert_eq!(payload["current_action"], "require-reapproval");
    assert_eq!(
        payload["reuse"]["saved_artifact_hash_is_context_token"],
        false
    );
}

/// The digest of the request exactly as the caller wrote it on the wire.
fn sent_digest(query: &Value) -> String {
    let material = json!({
        "schema": HOOK_DECISION_REQUEST_SCHEMA,
        "request_id": "req-hook",
        "query": query,
    });
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .unwrap();
    format!("sha256:{}", guard_policy_snapshot::digest_bytes(&bytes))
}

/// The transport rejects a reply whose `request_sha256` does not match the
/// digest the caller computed over its own wire form, so a field the resident
/// re-serializes into a shape the caller never wrote unbinds every call that
/// omits it. Both the request that names the local-approval flags and the one
/// that leaves them out have to come back bound.
#[test]
fn the_reply_digest_matches_the_request_the_caller_sent() {
    let unnamed = json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": "allow",
        "post_claim_refresh_failed": false, "context_changed": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }});
    assert_eq!(
        resident(&unnamed)["request_sha256"].as_str().unwrap(),
        sent_digest(&unnamed)
    );
    let named = json!({"kind": "post_claim_reuse", "inputs": {
        "current_policy_action": "allow", "reuse_action": "allow", "reuse_saved_action": "allow",
        "post_claim_refresh_failed": false, "context_changed": false,
        "fresh_local_approval": false, "durable_exact_approval": false,
        "has_ignored_integrity": false, "claim_row_invalid": false,
    }});
    assert_eq!(
        resident(&named)["request_sha256"].as_str().unwrap(),
        sent_digest(&named)
    );
    assert_ne!(sent_digest(&unnamed), sent_digest(&named));
}
