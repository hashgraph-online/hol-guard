use super::*;
use guard_contracts::ConsumerRuntimeDecisionQueryV1;

const VECTORS: &str = include_str!("../tests/fixtures/consumer_artifact_compose_vectors.json");

#[test]
fn matches_recorded_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 700);
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let query: ConsumerArtifactComposeQueryV1 = serde_json::from_value(vector["query"].clone())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(compose(&query).unwrap(), vector["expected"], "{name}");
    }
}

#[test]
fn fused_authoritative_decision_preserves_recorded_runtime_composition() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/decision_authority_vectors.json"
    ))
    .unwrap();
    let mut checked = 0;
    let mut refused = 0;
    for vector in reference["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| !v["consumer_runtime_query"].is_null())
    {
        let mut runtime = vector["consumer_runtime_query"].clone();
        runtime.as_object_mut().unwrap().remove("kind");
        let query = serde_json::from_value(json!({
            "kind": "runtime_authoritative", "runtime": runtime, "signals": [],
        }))
        .unwrap();
        let outcome = compose(&query);
        if vector["expected"]["status"] == "error" {
            assert_eq!(vector["expected"]["error_type"], "ValueError");
            assert_eq!(
                outcome.unwrap_err(),
                vector["expected"]["message"].as_str().unwrap()
            );
            refused += 1;
            continue;
        }
        let mut actual = outcome.unwrap();
        let decision = actual
            .as_object_mut()
            .unwrap()
            .remove("authoritative_decision")
            .unwrap();
        assert_eq!(actual, vector["consumer_runtime_expected"]);
        assert_eq!(decision, vector["expected"]["value"]);
        assert_eq!(decision["action"], actual["policy_action"]);
        assert_eq!(decision["reason"], actual["decision_reason"]);
        assert_eq!(decision["composition_trace"], actual["policy_composition"]);
        assert_eq!(
            decision["enforcement"]["authority_finalized"],
            actual["authority_finalized"]
        );
        checked += 1;
    }
    assert_eq!(checked, 514);
    assert_eq!(refused, 2);
}

fn resident(request: Value) -> Result<Value, String> {
    crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn envelope(schema: &str, query: Value) -> Value {
    json!({
        "operation": "consumer_artifact_compose",
        "request": {"schema": schema, "request_id": "req-consumer", "query": query},
    })
}

fn current_fields() -> Value {
    let mut query = serde_json::to_value(current_query(json!({}))).unwrap();
    query["kind"] = json!("current_action");
    query
}

#[test]
fn resident_transport_binds_request_and_composes() {
    let reply = resident(envelope(
        CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
        current_fields(),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert_eq!(reply["schema"], CONSUMER_ARTIFACT_COMPOSE_RESULT_SCHEMA);
    assert_eq!(reply["request_id"], "req-consumer");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["current_action"], "warn");
}

#[test]
fn semantic_refusals_remain_bound_resident_answers() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/decision_authority_vectors.json"
    ))
    .unwrap();
    let mut checked = 0;
    for vector in
        reference["vectors"].as_array().unwrap().iter().filter(|v| {
            !v["consumer_runtime_query"].is_null() && v["expected"]["status"] == "error"
        })
    {
        let mut runtime = vector["consumer_runtime_query"].clone();
        runtime.as_object_mut().unwrap().remove("kind");
        let reply = resident(envelope(
            CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA,
            json!({
                "kind": "runtime_authoritative", "runtime": runtime, "signals": []
            }),
        ))
        .unwrap();
        assert_eq!(reply["schema"], CONSUMER_ARTIFACT_COMPOSE_RESULT_SCHEMA);
        assert_eq!(reply["request_id"], "req-consumer");
        assert!(reply["request_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        assert_eq!(reply["status"], "error");
        assert_eq!(
            reply["code"],
            "native_consumer_artifact_compose_validation_refused"
        );
        assert_eq!(reply["payload"]["error_type"], "ValueError");
        assert_eq!(reply["payload"]["message"], vector["expected"]["message"]);
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[test]
fn rejects_wrong_schema_unknown_fields_and_missing_fields() {
    let err = resident(envelope("bogus", current_fields())).unwrap_err();
    assert_eq!(err, "native_consumer_artifact_compose_schema_mismatch");

    let mut surprise = current_fields();
    surprise["surprise"] = json!(true);
    assert!(resident(envelope(CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA, surprise)).is_err());

    let mut missing = current_fields();
    missing.as_object_mut().unwrap().remove("signals");
    assert!(resident(envelope(CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA, missing)).is_err());

    let unknown = json!({"kind": "not_a_query"});
    assert!(resident(envelope(CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA, unknown)).is_err());
}

fn current_query(overrides: Value) -> ConsumerCurrentActionQueryV1 {
    let mut base = json!({
        "removed": false,
        "artifact_type": "mcp_server",
        "configured_action": null,
        "guard_default_action": null,
        "first_seen": false,
        "changed": false,
        "effective_default_action": null,
        "config_changed_hash_action": "require-reapproval",
        "config_default_action": "warn",
        "skill_directory_identity_reusable": null,
        "signals": [],
        "deltas": [],
        "provenance_source_kind": "none",
        "publisher_trust": "unknown",
        "prior_approvals": 0,
        "prior_incidents": 0,
    });
    for (key, value) in overrides.as_object().expect("object") {
        base[key] = value.clone();
    }
    serde_json::from_value(base).expect("query")
}

fn runtime_query(overrides: Value) -> ConsumerRuntimeDecisionQueryV1 {
    let mut base = json!({
        "current_action": "review",
        "configured_action": null,
        "scanner_action": "allow",
        "raw_scoring_recommendation": "allow",
        "skill_directory_identity_reusable": null,
        "approval_context_hash": "ctx",
        "saved_decision": null,
        "ignored_local_integrity": false,
        "diagnosed_reason": null,
        "trusted_request_override_hash": null,
        "claimed_saved_approval_hash": null,
        "retained_saved_approval_hash": null,
        "saved_approval_qualification": null,
        "runtime_detector_composition": null,
        "runtime_detector_block_reason": null,
        "runtime_signals": [],
    });
    for (key, value) in overrides.as_object().expect("object") {
        base[key] = value.clone();
    }
    serde_json::from_value(base).expect("query")
}

#[test]
fn python_round3_rounds_exact_ties_half_even() {
    assert_eq!(python_round3(0.5625), 0.562);
    assert_eq!(python_round3(0.6875), 0.688);
    assert_eq!(python_round3(0.74 + 0.05), 0.79);
    assert_eq!(python_round3(0.98), 0.98);
}

#[test]
fn unscored_artifact_keeps_the_configured_default() {
    let answer = current_action(&current_query(json!({})));
    assert_eq!(answer["current_action"], "warn");
    assert_eq!(answer["scanner_action"], "allow");
    assert_eq!(answer["verdict"]["confidence"], json!(0.55));
    assert_eq!(answer["verdict"]["evidence_sources"], json!(["artifact"]));
}

#[test]
fn low_trust_raises_a_fresh_unconfigured_artifact() {
    let changed = json!({"changed": true, "config_changed_hash_action": "allow"});
    for fresh in [json!({"first_seen": true}), changed] {
        let mut overrides = fresh.clone();
        overrides["low_trust_action"] = json!("require-reapproval");
        let answer = current_action(&current_query(overrides));
        assert_eq!(answer["current_action"], "require-reapproval", "{fresh}");
    }
}

#[test]
fn low_trust_leaves_settled_or_configured_artifacts_alone() {
    let settled = current_action(&current_query(json!({"low_trust_action": "block"})));
    assert_eq!(settled["current_action"], "warn");
    let configured = current_action(&current_query(json!({
        "first_seen": true,
        "configured_action": "allow",
        "low_trust_action": "block",
    })));
    assert_eq!(configured["current_action"], "allow");
}

#[test]
fn omitted_low_trust_action_keeps_the_request_shape() {
    let encoded = serde_json::to_value(current_query(json!({}))).expect("encode");
    assert!(encoded.get("low_trust_action").is_none());
}

#[test]
fn removed_artifact_uses_changed_hash_action_without_scoring() {
    let answer = current_action(&current_query(json!({
        "removed": true,
        "skill_directory_identity_reusable": false,
        "config_changed_hash_action": "allow",
    })));
    assert_eq!(answer["current_action"], "require-reapproval");
    assert_eq!(answer["scanner_action"], Value::Null);
    assert_eq!(answer["verdict"], Value::Null);
}

#[test]
fn flagged_publisher_blocks() {
    let answer = current_action(&current_query(json!({
        "publisher_trust": "flagged",
        "provenance_source_kind": "curated",
    })));
    assert_eq!(answer["verdict"]["action"], "block");
    assert_eq!(answer["current_action"], "block");
    assert_eq!(answer["verdict"]["suppressible"], false);
}

#[test]
fn trusted_request_override_settles_review_for_exact_context() {
    let answer = runtime_decision(&runtime_query(json!({
        "trusted_request_override_hash": "ctx",
    })));
    assert_eq!(answer["policy_action"], "allow");
    assert_eq!(answer["trusted_request_override"], true);
    assert_eq!(answer["approval_source"], "fresh-approval");
    assert_eq!(
        answer["decision_reason"],
        "trusted_request_override_exact_context"
    );
}

#[test]
fn runtime_detector_block_reason_is_terminal() {
    let answer = runtime_decision(&runtime_query(json!({
        "trusted_request_override_hash": "ctx",
        "runtime_detector_block_reason": "detector says no",
    })));
    assert_eq!(answer["policy_action"], "block");
    assert_eq!(answer["approval_source"], "runtime-detector");
    assert_eq!(
        answer["policy_composition"]["runtime_detector_reason"],
        "detector says no"
    );
}

#[test]
fn integrity_failure_without_row_requires_reapproval() {
    let answer = runtime_decision(&runtime_query(json!({
        "current_action": "allow",
        "ignored_local_integrity": true,
    })));
    assert_eq!(answer["policy_action"], "require-reapproval");
    assert_eq!(answer["saved_state_present"], true);
    assert_eq!(
        answer["decision_reason"],
        "approval_reuse_integrity_failure"
    );
}
