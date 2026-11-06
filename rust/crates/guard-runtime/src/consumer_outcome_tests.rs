//! What a composed (or missing) consumer decision means for the evaluation.
//!
//! These cases pin the decisions `evaluate_detection` used to make in Python:
//! the fail-closed refusal shown when nothing was composed, the blocking and
//! snapshot bits, the risk copy, the receipt fields and the change event.

use super::*;
use crate::store_vectors_support_tests::gunzip_json;
use guard_command::decisions::build_authoritative_decision;
use guard_contracts::GuardAction;
use serde_json::Map;

const VECTORS: &[u8] =
    include_bytes!("../tests/fixtures/consumer_artifact_project_vectors.json.gz");

/// A recorded detected-artifact query, for a realistic artifact and evidence.
fn recorded_artifact_query() -> Value {
    let vectors = gunzip_json(VECTORS);
    vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["query"]["kind"] == "artifact_result")
        .unwrap()["query"]
        .clone()
}

fn signal(plain_reason: &str) -> Value {
    json!({
        "signal_id": "runtime:test",
        "category": "bypass",
        "severity": "high",
        "confidence": "likely",
        "detector": "test-detector",
        "title": "Detector signal",
        "plain_reason": plain_reason,
        "technical_detail": null,
        "evidence_ref": null,
        "redaction_level": "summary",
        "false_positive_hint": null,
        "advisory_id": null,
    })
}

fn decision(action: GuardAction, finalized: bool, signals: &[Value]) -> AuthoritativeGuardDecision {
    let parsed = parse_signals(&json!(signals)).unwrap();
    build_authoritative_decision(
        action,
        "saved_approval_reused",
        &Map::new(),
        &parsed,
        finalized,
        "composed-consumer-policy",
    )
    .unwrap()
}

fn runtime_answer(decision: &AuthoritativeGuardDecision, trusted_override: bool) -> Value {
    json!({
        "approval_claim": null,
        "approval_reuse": {"status": "accepted", "reason_code": "approval_reuse_exact_context"},
        "approval_source": "saved-decision",
        "append_pending_claim": false,
        "authority_finalized": decision.enforcement.authority_finalized,
        "decision_reason": decision.reason,
        "policy_action": decision.action.as_str(),
        "policy_composition": decision.composition_trace,
        "saved_state_present": true,
        "scanner_evidence": [{"source": "scanner"}],
        "trusted_request_override": trusted_override,
        "authoritative_decision": decision.to_value(),
    })
}

fn detected(runtime: Value, compose_error: Value) -> Value {
    let recorded = recorded_artifact_query();
    let verdict = if runtime.is_null() && compose_error.is_string() {
        Value::Null
    } else {
        recorded["verdict"].clone()
    };
    json!({
        "harness": recorded["harness"],
        "artifact": recorded["artifact"],
        "evidence": recorded["evidence"],
        "verdict": verdict,
        "scanner_action": if verdict.is_null() { Value::Null } else { recorded["scanner_action"].clone() },
        "configured_action": null,
        "runtime": runtime,
        "compose_error": compose_error,
        "signals": recorded["signals"],
        "decision_signals": [signal("Static reason.")],
        "static_risk_summary": "Static summary.",
        "runtime_signals_present": false,
        "user_override": "trusted request",
        "approval_context_hash": "context-hash",
        "effective_workspace": "/workspace",
    })
}

fn removed(runtime: Value, compose_error: Value, decision_signals: Value) -> Value {
    json!({
        "harness": "codex",
        "artifact_id": "codex:project:tool",
        "previous": {
            "name": "tool",
            "artifact_type": "mcp_server",
            "source_scope": "project",
            "config_path": "/workspace/.codex/config.toml",
        },
        "previous_hash": "sha256:previous",
        "configured_action": "warn",
        "runtime": runtime,
        "compose_error": compose_error,
        "decision_signals": decision_signals,
        "user_override": null,
        "approval_context_hash": "context-hash",
        "effective_workspace": "/workspace",
    })
}

#[test]
fn an_uncomposed_artifact_blocks_with_the_transport_error_and_no_authority() {
    let outcome = artifact_outcome(&detected(
        Value::Null,
        json!("native_consumer_artifact_compose_unavailable"),
    ))
    .unwrap();
    assert_eq!(outcome["policy_action"], "block");
    assert_eq!(outcome["blocking"], true);
    assert_eq!(outcome["snapshot_permitted"], false);
    let row = &outcome["result"];
    assert!(row.get("authoritative_decision").is_none());
    assert!(row.get("decision_v2_json").is_none());
    assert_eq!(row["policy_action"], "block");
    assert_eq!(row["decision_reason"], COMPOSE_UNAVAILABLE_REASON);
    assert_eq!(
        row["evaluation_error"],
        json!({
            "code": "native_consumer_artifact_compose_unavailable",
            "component": "consumer_artifact_compose",
        })
    );
    assert_eq!(
        row["approval_reuse_reason_code"],
        COMPOSE_UNAVAILABLE_REASON
    );
    assert_eq!(row["approval_reuse_status"], "not-applicable");
    assert_eq!(
        row["policy_composition"],
        json!({
            "configured_action": null,
            "current_action": "block",
            "final_action": "block",
            "native_compose_error": "native_consumer_artifact_compose_unavailable",
            "raw_scoring_recommendation": "block",
            "saved_action": null,
            "saved_state_present": false,
            "scanner_action": null,
            "scoring_recommendation_non_authoritative": true,
            "trusted_request_override": false,
        })
    );
    // The unscored verdict is what the person is told about scoring.
    assert_eq!(row["scoring_recommendation"]["action"], "block");
    assert_eq!(
        row["scoring_recommendation"]["reasons"],
        json!(["Guard could not score this artifact, so it stays blocked."])
    );
    assert_eq!(row["review_priority"], "critical");
    assert_eq!(row["remediation"], json!(["open_investigation"]));
    // Without a decision the risk signals are those it would have used.
    assert_eq!(row["risk_signals"], json!(["Static reason."]));
    assert_eq!(row["risk_summary"], "Static summary.");
    assert_eq!(outcome["receipt"]["approval_source"], "policy");
    assert_eq!(outcome["receipt"]["scanner_evidence"], json!([]));
    assert_eq!(outcome["receipt"]["user_override"], Value::Null);
}

#[test]
fn a_failed_runtime_query_keeps_the_real_scoring_verdict() {
    let recorded = recorded_artifact_query();
    let mut query = detected(
        Value::Null,
        json!("native_consumer_artifact_compose_timeout"),
    );
    query["verdict"] = recorded["verdict"].clone();
    let outcome = artifact_outcome(&query).unwrap();
    let row = &outcome["result"];
    assert_eq!(
        row["scoring_recommendation"]["action"],
        recorded["verdict"]["action"]
    );
    assert_eq!(
        row["policy_composition"]["raw_scoring_recommendation"],
        recorded["verdict"]["action"]
    );
    assert_eq!(outcome["blocking"], true);
}

#[test]
fn a_finalized_allow_permits_the_snapshot_and_projects_the_decision_as_sent() {
    let decision = decision(GuardAction::Allow, true, &[signal("Composed reason.")]);
    let answer = runtime_answer(&decision, false);
    let outcome = artifact_outcome(&detected(answer.clone(), Value::Null)).unwrap();
    assert_eq!(outcome["policy_action"], "allow");
    assert_eq!(outcome["blocking"], false);
    assert_eq!(outcome["snapshot_permitted"], true);
    let row = &outcome["result"];
    assert_eq!(
        row["authoritative_decision"],
        answer["authoritative_decision"]
    );
    assert_eq!(
        row["decision_v2_json"],
        answer["authoritative_decision"]["decision_v2"]
    );
    assert_eq!(
        row["policy_composition"],
        answer["authoritative_decision"]["composition_trace"]
    );
    assert_eq!(row["verdict_action"], "allow");
    assert_eq!(row["risk_signals"], json!(["Composed reason."]));
    // The runtime detector did not decide, so the static copy stays.
    assert_eq!(row["risk_summary"], "Static summary.");
    assert!(row.get("evaluation_error").is_none());
}

#[test]
fn an_unfinalized_allow_keeps_the_snapshot_and_a_block_blocks() {
    let pending = decision(GuardAction::Allow, false, &[]);
    let outcome =
        artifact_outcome(&detected(runtime_answer(&pending, false), Value::Null)).unwrap();
    assert_eq!(outcome["blocking"], false);
    assert_eq!(outcome["snapshot_permitted"], false);
    let blocked = decision(GuardAction::Block, true, &[]);
    let outcome =
        artifact_outcome(&detected(runtime_answer(&blocked, false), Value::Null)).unwrap();
    assert_eq!(outcome["policy_action"], "block");
    assert_eq!(outcome["blocking"], true);
    assert_eq!(outcome["snapshot_permitted"], false);
}

#[test]
fn runtime_detector_authority_shows_the_dashboard_detail() {
    let decision = decision(GuardAction::Review, true, &[signal("Detector reason.")]);
    let detail = decision.decision_v2.dashboard_primary_detail.clone();
    let mut query = detected(runtime_answer(&decision, false), Value::Null);
    query["runtime_signals_present"] = json!(true);
    let outcome = artifact_outcome(&query).unwrap();
    assert_eq!(outcome["result"]["risk_summary"], json!(detail));
    // A detector action in the composition also counts as its authority.
    let mut answer = runtime_answer(&decision, false);
    answer["policy_composition"]["runtime_detector_action"] = json!("review");
    let outcome = artifact_outcome(&detected(answer, Value::Null)).unwrap();
    assert_eq!(outcome["result"]["risk_summary"], json!(detail));
}

#[test]
fn the_receipt_carries_the_evidence_and_the_override_only_when_it_applied() {
    let decision = decision(GuardAction::Allow, true, &[]);
    let recorded = recorded_artifact_query();
    let evidence = &recorded["evidence"];
    let outcome =
        artifact_outcome(&detected(runtime_answer(&decision, true), Value::Null)).unwrap();
    assert_eq!(
        outcome["receipt"],
        json!({
            "artifact_hash": evidence["current_hash"],
            "policy_decision": "allow",
            "capabilities_summary": evidence["capabilities_summary"],
            "changed_capabilities": evidence["changed_capabilities"],
            "provenance_summary": evidence["provenance_summary"],
            "artifact_name": recorded["artifact"]["name"],
            "source_scope": recorded["artifact"]["source_scope"],
            "user_override": "trusted request",
            "diff_summary": evidence["diff_summary"],
            "approval_source": "saved-decision",
            "scanner_evidence": [{"source": "scanner"}],
        })
    );
    let outcome =
        artifact_outcome(&detected(runtime_answer(&decision, false), Value::Null)).unwrap();
    assert_eq!(outcome["receipt"]["user_override"], Value::Null);
}

#[test]
fn a_runtime_detector_block_records_no_override() {
    let decision = decision(GuardAction::Block, true, &[]);
    let mut runtime = runtime_answer(&decision, true);
    runtime["decision_reason"] = json!("runtime_detector_block");
    runtime["approval_source"] = json!("runtime-detector");
    let outcome = artifact_outcome(&detected(runtime.clone(), Value::Null)).unwrap();
    assert_eq!(outcome["receipt"]["user_override"], Value::Null);
    let mut query = removed(runtime, Value::Null, json!([]));
    query["user_override"] = json!("trusted request");
    let outcome = removed_outcome(&query).unwrap();
    assert_eq!(outcome["receipt"]["user_override"], Value::Null);
}

#[test]
fn only_a_change_to_a_known_artifact_raises_the_change_event() {
    let decision = decision(GuardAction::Review, true, &[]);
    let mut query = detected(runtime_answer(&decision, false), Value::Null);
    query["evidence"]["changed"] = json!(true);
    query["evidence"]["first_seen"] = json!(false);
    query["evidence"]["changed_fields"] = json!(["command"]);
    let outcome = artifact_outcome(&query).unwrap();
    assert_eq!(
        outcome["event"],
        json!({
            "harness": query["harness"],
            "artifact_id": query["artifact"]["artifact_id"],
            "artifact_name": query["artifact"]["name"],
            "policy_action": "review",
            "changed_fields": ["command"],
            "approval_reuse_status": "accepted",
            "approval_reuse_reason_code": "approval_reuse_exact_context",
        })
    );
    query["evidence"]["first_seen"] = json!(true);
    assert_eq!(artifact_outcome(&query).unwrap()["event"], Value::Null);
    query["evidence"]["first_seen"] = json!(false);
    query["evidence"]["changed"] = json!(false);
    assert_eq!(artifact_outcome(&query).unwrap()["event"], Value::Null);
}

#[test]
fn malformed_outcome_queries_are_refused() {
    // Neither an answer nor a reason there is none.
    assert_eq!(
        artifact_outcome(&detected(Value::Null, Value::Null)),
        Err(INVALID)
    );
    // An answer without its authoritative decision.
    let decision = decision(GuardAction::Allow, true, &[]);
    let mut answer = runtime_answer(&decision, false);
    answer
        .as_object_mut()
        .unwrap()
        .remove("authoritative_decision");
    assert_eq!(
        artifact_outcome(&detected(answer, Value::Null)),
        Err(INVALID)
    );
    // A composed answer always comes with its scoring verdict.
    let mut query = detected(runtime_answer(&decision, false), Value::Null);
    query["verdict"] = Value::Null;
    assert_eq!(artifact_outcome(&query), Err(INVALID));
    // Fallback signals must decode.
    let mut query = detected(
        Value::Null,
        json!("native_consumer_artifact_compose_unavailable"),
    );
    query["decision_signals"] = json!([{"signal_id": "x"}]);
    assert_eq!(artifact_outcome(&query), Err(INVALID));
}

#[test]
fn a_removed_artifact_always_raises_the_change_event_and_keeps_the_warn_recommendation() {
    let outcome = removed_outcome(&removed(
        Value::Null,
        json!("native_consumer_artifact_compose_unavailable"),
        json!([]),
    ))
    .unwrap();
    assert_eq!(outcome["policy_action"], "block");
    assert_eq!(outcome["blocking"], true);
    assert_eq!(outcome["snapshot_permitted"], false);
    let row = &outcome["result"];
    assert_eq!(row["removed"], true);
    assert_eq!(
        row["policy_composition"]["raw_scoring_recommendation"],
        "warn"
    );
    assert_eq!(row["policy_composition"]["scanner_action"], Value::Null);
    assert_eq!(row["policy_composition"]["configured_action"], "warn");
    assert_eq!(
        row["risk_summary"],
        "Artifact was removed from the harness configuration."
    );
    assert_eq!(
        outcome["receipt"],
        json!({
            "artifact_hash": "sha256:previous",
            "policy_decision": "block",
            "capabilities_summary": "mcp server \u{2022} project artifact",
            "changed_capabilities": ["removed"],
            "provenance_summary": "project artifact removed from /workspace/.codex/config.toml",
            "artifact_name": "tool",
            "source_scope": "project",
            "user_override": null,
            "diff_summary": "artifact removed",
            "approval_source": "policy",
            "scanner_evidence": [],
        })
    );
    assert_eq!(
        outcome["event"],
        json!({
            "harness": "codex",
            "artifact_id": "codex:project:tool",
            "artifact_name": "tool",
            "policy_action": "block",
            "changed_fields": ["removed"],
            "approval_reuse_status": "not-applicable",
            "approval_reuse_reason_code": COMPOSE_UNAVAILABLE_REASON,
        })
    );
}

#[test]
fn a_removed_artifact_with_detector_signals_shows_the_decision() {
    let detector = signal("Detector reason.");
    let decision = decision(GuardAction::Allow, true, std::slice::from_ref(&detector));
    let detail = decision.decision_v2.dashboard_primary_detail.clone();
    let answer = runtime_answer(&decision, false);
    let outcome =
        removed_outcome(&removed(answer.clone(), Value::Null, json!([detector]))).unwrap();
    assert_eq!(outcome["snapshot_permitted"], true);
    let row = &outcome["result"];
    assert_eq!(row["signals"], answer["authoritative_decision"]["signals"]);
    assert_eq!(row["risk_signals"], json!(["Detector reason."]));
    assert_eq!(row["risk_summary"], json!(detail));
    // Without detector authority the removal copy stays.
    let outcome = removed_outcome(&removed(answer, Value::Null, json!([]))).unwrap();
    assert_eq!(
        outcome["result"]["risk_summary"],
        "Artifact was removed from the harness configuration."
    );
}
