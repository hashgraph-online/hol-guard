//! Vectors recorded from the retired Python daemon handlers, plus transport
//! binding checks for `DaemonHandler`.

use guard_contracts::{DAEMON_HANDLER_MAX_BYTES, DAEMON_HANDLER_REQUEST_SCHEMA};
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../tests/fixtures/daemon_handler_vectors.json");

fn request_with(schema: &str, query: &Value) -> Value {
    json!({
        "operation": "daemon_handler",
        "request": {"schema": schema, "request_id": "req-handler", "query": query}
    })
}

fn try_resident(query: &Value) -> Result<Value, String> {
    let request = request_with(DAEMON_HANDLER_REQUEST_SCHEMA, query);
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)?;
    Ok(serde_json::from_slice(&out).unwrap())
}

fn payload(query: &Value) -> Value {
    let reply = try_resident(query).expect("daemon handler op should answer");
    assert_eq!(reply["status"], "ok", "{query}");
    reply["payload"].clone()
}

fn without_cleared(body: &Value) -> Value {
    let mut body = body.clone();
    body.as_object_mut().unwrap().remove("cleared");
    body
}

#[test]
fn matches_vectors_recorded_from_python() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 1000, "{} vectors", vectors.len());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let expected = &vector["expected"];
        let kind = vector["query"]["kind"].as_str().unwrap();
        let answer = payload(&vector["query"]);
        assert_eq!(answer["kind"], kind, "vector {name}");
        assert_eq!(answer["outcome"], expected["outcome"], "vector {name}");
        assert_eq!(answer["status"], expected["status"], "vector {name}");
        if expected["outcome"] == "reject" {
            assert_eq!(answer["body"], expected["body"], "vector {name}");
            continue;
        }
        assert_eq!(answer["fields"], expected["fields"], "vector {name}");
        // The success body the caller completes with store facts.
        match kind {
            "policy_upsert" => assert_eq!(answer["body"], expected["body"], "vector {name}"),
            "policy_clear" | "requests_clear" => assert_eq!(
                answer["body"],
                without_cleared(&expected["body"]),
                "vector {name}"
            ),
            _ => {}
        }
    }
}

#[test]
fn vectors_cover_every_query_kind_and_rejection_branch() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    for kind in [
        "policy_upsert",
        "policy_clear",
        "requests_clear",
        "bulk_allow",
        "requests_list",
        "harness_action",
        "events_cursor",
    ] {
        for outcome in ["proceed", "reject"] {
            if kind == "events_cursor" && outcome == "reject" {
                continue;
            }
            assert!(
                vectors.iter().any(|vector| vector["query"]["kind"] == kind
                    && vector["expected"]["outcome"] == outcome),
                "no {outcome} vectors for {kind}"
            );
        }
    }
    let errors: std::collections::BTreeSet<&str> = vectors
        .iter()
        .filter_map(|vector| vector["expected"]["body"]["error"].as_str())
        .collect();
    for code in [
        "missing_required_fields",
        "unsupported_policy_value",
        "broad_allow_requires_narrow_scope",
        "missing_scope_target",
        "invalid_clear_payload",
        "invalid_scope",
        "choose_all_or_harness",
        "missing_harness_or_all",
        "invalid_status",
        "missing_request_ids",
        "invalid_limit",
        "not_found",
        "invalid_dry_run",
    ] {
        assert!(errors.contains(code), "no vector for {code}");
    }
}

#[test]
fn reply_is_bound_to_the_request_digest() {
    let query = json!({"kind": "requests_list", "query": "limit=5"});
    let request = request_with(DAEMON_HANDLER_REQUEST_SCHEMA, &query);
    let reply: Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["request_id"], "req-handler");
    let digest = reply["request_sha256"].as_str().unwrap();
    assert!(digest.starts_with("sha256:") && digest.len() == 71);
    let other = request_with(
        DAEMON_HANDLER_REQUEST_SCHEMA,
        &json!({"kind": "requests_list", "query": "limit=6"}),
    );
    let other_reply: Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(other.to_string().as_bytes(), None)
            .unwrap(),
    )
    .unwrap();
    assert_ne!(other_reply["request_sha256"], reply["request_sha256"]);
}

#[test]
fn schema_mismatch_is_a_bound_error() {
    let query = json!({"kind": "events_cursor", "query": ""});
    let request = request_with("guard-daemon-handler-request.v0", &query);
    let reply: Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_daemon_handler_schema_mismatch");
    assert!(reply.get("payload").is_none());
}

#[test]
fn oversized_request_is_refused_before_any_decision() {
    // Each string is under the parser's per-string bound; together they pass the op's cap.
    let chunk = "a".repeat(1_000_000);
    let strings = vec![chunk; DAEMON_HANDLER_MAX_BYTES / 1_000_000 + 1];
    let query = json!({
        "kind": "bulk_allow",
        "request_ids": {"state": "list", "len": strings.len(), "strings": strings},
    });
    let error = try_resident(&query).unwrap_err();
    assert_eq!(error, "native_daemon_handler_too_large");
}

#[test]
fn unknown_fields_and_kinds_are_rejected() {
    for query in [
        json!({"kind": "requests_list", "query": "", "extra": 1}),
        json!({"kind": "no_such_handler"}),
        json!({"kind": "requests_clear", "status": {"state": "absent"}}),
        json!({"kind": "bulk_allow", "request_ids": {"state": "list", "len": 1}}),
        json!({"kind": "bulk_allow", "request_ids": {"state": "number"}}),
    ] {
        assert!(try_resident(&query).is_err(), "{query}");
    }
}

#[test]
fn large_bulk_lists_are_accepted_up_to_the_limit() {
    let ids: Vec<String> = (0..4000)
        .map(|index| format!("request-{index:08}"))
        .collect();
    let query = json!({
        "kind": "bulk_allow",
        "request_ids": {"state": "list", "len": ids.len(), "strings": ids},
    });
    let answer = payload(&query);
    assert_eq!(answer["outcome"], "proceed");
    assert_eq!(
        answer["fields"]["request_ids"].as_array().unwrap().len(),
        4000
    );
}

#[test]
fn a_list_longer_than_the_bound_is_rejected_by_length() {
    let query = json!({
        "kind": "bulk_allow",
        "request_ids": {"state": "list", "len": 4097, "strings": []},
    });
    let answer = payload(&query);
    assert_eq!(answer["outcome"], "reject");
    assert_eq!(answer["status"], 400);
    assert_eq!(answer["body"]["error"], "too_many_request_ids");
}
