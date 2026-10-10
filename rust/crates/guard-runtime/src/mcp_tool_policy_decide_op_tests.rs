use super::*;
use guard_contracts::{McpToolPolicyObservationV1, McpToolPolicySubjectV1};
use serde_json::{json, Value};

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_tool_policy/parity_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("parity vectors parse")
}

fn request(subject: &Value, claim: bool, observations: &[Value]) -> McpToolPolicyDecideRequestV1 {
    McpToolPolicyDecideRequestV1 {
        schema: MCP_TOOL_POLICY_DECIDE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        claim_saved_approval: claim,
        subject: serde_json::from_value::<McpToolPolicySubjectV1>(subject.clone())
            .expect("subject parses"),
        observations: observations
            .iter()
            .map(|item| McpToolPolicyObservationV1 {
                need: item["need"].clone(),
                result: item["result"].clone(),
            })
            .collect(),
    }
}

fn run(request: &McpToolPolicyDecideRequestV1) -> Value {
    let bytes = evaluate_mcp_tool_policy_decide_request(request).expect("encodes");
    serde_json::from_slice(&bytes).expect("result json")
}

#[test]
fn every_python_recorded_vector_replays_exactly() {
    let doc = vectors();
    let subjects = &doc["subjects"];
    let all = doc["vectors"].as_array().expect("vectors");
    assert!(all.len() >= 500);
    for vector in all {
        let name = vector["name"].as_str().unwrap_or("?");
        let subject = &subjects[vector["subject"].as_str().expect("subject key")];
        let claim = vector["claim_saved_approval"]
            .as_bool()
            .expect("claim flag");
        let observed = vector["observations"].as_array().expect("observations");
        // Each prefix must ask for exactly the next recorded effect, in order.
        for (index, next) in observed.iter().enumerate() {
            let reply = run(&request(subject, claim, &observed[..index]));
            assert_eq!(reply["status"], "need", "{name} prefix {index}: {reply}");
            assert_eq!(reply["payload"], next["need"], "{name} prefix {index}");
        }
        let reply = run(&request(subject, claim, observed));
        assert_eq!(reply["status"], "ok", "{name}: {reply}");
        assert_eq!(reply["payload"], vector["expected"], "{name}");
    }
}

fn first_vector_with(kind: &str, result: Option<Value>) -> (Value, bool, Vec<Value>) {
    let doc = vectors();
    for vector in doc["vectors"].as_array().expect("vectors") {
        let observed = vector["observations"].as_array().expect("observations");
        if observed.iter().any(|item| {
            item["need"]["kind"] == kind && result.as_ref().is_none_or(|r| item["result"] == *r)
        }) {
            let subject = doc["subjects"][vector["subject"].as_str().expect("key")].clone();
            return (subject, true, observed.clone());
        }
    }
    panic!("no vector with {kind}");
}

fn with_claim_outcome(outcome: &str) -> Value {
    let (subject, claim, mut observed) = first_vector_with("claim", None);
    let at = observed
        .iter()
        .position(|item| item["need"]["kind"] == "claim")
        .expect("claim");
    observed.truncate(at + 1);
    observed[at]["result"] = json!({"outcome": outcome});
    run(&request(&subject, claim, &observed))
}

#[test]
fn uncertain_claim_floors_to_reapproval_and_never_asks_again() {
    let reply = with_claim_outcome("uncertain");
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["action"], "require-reapproval");
    assert_eq!(reply["payload"]["post_claim_revalidated"], false);
    assert_eq!(reply["payload"]["approval_reuse_status"], "rejected");
}

#[test]
fn lost_claim_race_is_declined_without_authority() {
    let reply = with_claim_outcome("declined");
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_ne!(reply["payload"]["action"], "allow");
    assert_eq!(reply["payload"]["post_claim_revalidated"], false);
}

#[test]
fn unknown_claim_outcome_fails_closed() {
    let reply = with_claim_outcome("claimed-twice");
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["payload"], Value::Null);
}

#[test]
fn authority_refresh_failure_floors_to_reapproval() {
    let (subject, claim, observed) =
        first_vector_with("fresh_authority", Some(json!({"status": "failed"})));
    let reply = run(&request(&subject, claim, &observed));
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"]["action"], "require-reapproval");
    assert_eq!(reply["payload"]["post_claim_revalidated"], true);
    assert_eq!(
        reply["payload"]["approval_reuse_reason_code"],
        "approval_reuse_context_changed_after_claim"
    );
}

#[test]
fn malformed_observation_results_fail_closed() {
    let doc = vectors();
    let vector = &doc["vectors"][0];
    let subject = &doc["subjects"][vector["subject"].as_str().expect("key")];
    let mut observed = vector["observations"].as_array().expect("obs").clone();
    for item in &mut observed {
        item["result"] = json!(["not", "valid"]);
    }
    let reply = run(&request(subject, true, &observed));
    assert_eq!(reply["status"], "error", "{reply}");
}

#[test]
fn schema_mismatch_and_oversized_observations_are_rejected() {
    let doc = vectors();
    let vector = &doc["vectors"][0];
    let subject = &doc["subjects"][vector["subject"].as_str().expect("key")];
    let mut bad = request(subject, true, &[]);
    bad.schema = "nope".to_owned();
    assert_eq!(run(&bad)["status"], "error");
    let filler = json!({"need": {"kind": "x"}, "result": null});
    let many = vec![filler; MCP_TOOL_POLICY_DECIDE_MAX_OBSERVATIONS + 1];
    assert_eq!(run(&request(subject, true, &many))["status"], "error");
}

#[test]
fn reply_binds_request_id_and_digest() {
    let doc = vectors();
    let vector = &doc["vectors"][0];
    let subject = &doc["subjects"][vector["subject"].as_str().expect("key")];
    let req = request(subject, true, &[]);
    let reply = run(&req);
    assert_eq!(reply["request_id"], "vector");
    assert_eq!(
        reply["request_sha256"],
        request_digest(&req).expect("digest")
    );
}
