//! Vectors recorded from the retired Python daemon handler, plus transport
//! binding checks for `DaemonRoute`.

use guard_contracts::{DAEMON_ROUTE_MAX_BYTES, DAEMON_ROUTE_REQUEST_SCHEMA};
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../tests/fixtures/daemon_route_vectors.json");

fn request_with(schema: &str, query: &Value) -> Value {
    json!({
        "operation": "daemon_route",
        "request": {"schema": schema, "request_id": "req-route", "query": query}
    })
}

fn try_resident(query: &Value) -> Result<Value, String> {
    let request = request_with(DAEMON_ROUTE_REQUEST_SCHEMA, query);
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)?;
    Ok(serde_json::from_slice(&out).unwrap())
}

fn payload(query: &Value) -> Value {
    let reply = try_resident(query).expect("daemon route op should answer");
    assert_eq!(reply["status"], "ok", "{query}");
    reply["payload"].clone()
}

#[test]
fn matches_vectors_recorded_from_python() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 250, "{} vectors", vectors.len());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let mut expected = vector["expected"].clone();
        let kind = vector["query"]["kind"].clone();
        expected["kind"] = kind;
        // Replaying a consumed nonce is the caller's state, checked in Python.
        expected.as_object_mut().unwrap().remove("replay_allowed");
        assert_eq!(payload(&vector["query"]), expected, "vector {name}");
    }
}

#[test]
fn vectors_cover_every_query_kind_and_rejection_branch() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let names: Vec<&str> = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| vector["name"].as_str().unwrap())
        .collect();
    for prefix in [
        "route.",
        "origin.",
        "strict_loopback.",
        "session.protection_repair.",
        "session.local_surface.",
        "session.scoped_read.",
        "session.cloud_app.",
        "session.supply_chain.",
        "resolve.",
    ] {
        assert!(
            names.iter().any(|name| name.starts_with(prefix)),
            "no vectors for {prefix}"
        );
    }
}

#[test]
fn reply_is_bound_to_the_request_digest() {
    let query = json!({"kind": "route", "method": "POST", "path": "/v1/hooks/codex/pre"});
    let request = request_with(DAEMON_ROUTE_REQUEST_SCHEMA, &query);
    let reply: Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["request_id"], "req-route");
    let digest = reply["request_sha256"].as_str().unwrap();
    assert!(digest.starts_with("sha256:") && digest.len() == 71);
    let other = request_with(
        DAEMON_ROUTE_REQUEST_SCHEMA,
        &json!({"kind": "route", "method": "GET", "path": "/v1/hooks/codex/pre"}),
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
    let query = json!({"kind": "route", "method": "GET", "path": "/v1/runtime"});
    let request = request_with("guard-daemon-route-request.v0", &query);
    let reply: Value = serde_json::from_slice(
        &crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_daemon_route_schema_mismatch");
    assert!(reply.get("payload").is_none());
}

#[test]
fn oversized_request_is_refused_before_any_decision() {
    let query = json!({
        "kind": "route",
        "method": "GET",
        "path": format!("/{}", "a".repeat(DAEMON_ROUTE_MAX_BYTES)),
    });
    let request = request_with(DAEMON_ROUTE_REQUEST_SCHEMA, &query);
    let error =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .unwrap_err();
    assert_eq!(error, "native_daemon_route_too_large");
}

#[test]
fn unknown_fields_and_kinds_are_rejected() {
    for query in [
        json!({"kind": "route", "method": "GET", "path": "/v1/runtime", "extra": 1}),
        json!({"kind": "no_such_query"}),
        json!({"kind": "origin", "origin": "http://localhost"}),
        json!({"kind": "resolve_request", "path": "/", "action": {"state": "text"},
               "scope": {"state": "absent"}, "scope_contract_version": {"state": "absent"},
               "scope_contract_digest": {"state": "absent"}}),
    ] {
        assert!(try_resident(&query).is_err(), "{query}");
    }
}

#[test]
fn nonce_is_named_only_when_the_claim_scopes_the_action() {
    let claims = |action_path: &str| {
        json!({"surface": null, "action_path": action_path, "nonce": "n-1",
               "allowed_action_paths": ["package_shims_repair"]})
    };
    let query = |action_path: &str, path: &str| {
        json!({"kind": "session_authorize", "method": "POST", "path": path,
               "claims": claims(action_path), "payload": null})
    };
    let scoped = payload(&query(
        "package_shims_status",
        "/v1/supply-chain/package-shims",
    ));
    assert_eq!(scoped["consume_nonce"], "n-1");
    let unscoped = payload(&query(
        "package_shims_test",
        "/v1/supply-chain/package-shims",
    ));
    assert_eq!(unscoped["consume_nonce"], Value::Null);
    assert_eq!(unscoped["allowed"], false);
    let listed = payload(&query(
        "package_shims_test",
        "/v1/supply-chain/package-shims/repair",
    ));
    assert_eq!(listed["consume_nonce"], "n-1");
}
