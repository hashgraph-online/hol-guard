//! Parity vectors recorded from the retired Python sensitive-read helpers.
//!
//! Each vector drove the pre-change Python (the current-action and context
//! helpers directly, the reuse composition through the stdio proxy with a
//! scripted store) and recorded the resulting action, token, receipt evidence
//! and response. The expected value is a subset of the resident payload; a recorded null
//! matches an omitted key.

use guard_contracts::McpProxyQueryV1;
use serde_json::Value;

use crate::mcp_proxy_decision_op::decide;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_sensitive_read/parity_vectors.json");

fn is_subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(want), Value::Object(have)) => {
            want.iter().all(|(key, value)| match have.get(key) {
                Some(got) => is_subset(value, got),
                None => value.is_null(),
            })
        }
        (Value::Array(want), Value::Array(have)) => {
            want.len() == have.len()
                && want
                    .iter()
                    .zip(have)
                    .all(|(left, right)| is_subset(left, right))
        }
        _ => expected == actual,
    }
}

fn corpus() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    document["vectors"].as_array().unwrap().clone()
}

#[test]
fn resident_matches_every_recorded_vector() {
    let vectors = corpus();
    assert!(vectors.len() > 800, "corpus unexpectedly small");
    for vector in &vectors {
        let query: McpProxyQueryV1 =
            serde_json::from_value(vector["request"].clone()).expect("vector must deserialize");
        let actual = decide(&query);
        assert!(
            is_subset(&vector["expected"], &actual),
            "vector {} diverged\nexpected {}\nactual   {}",
            vector["id"],
            vector["expected"],
            actual
        );
    }
}

#[test]
fn every_check_and_stage_is_recorded() {
    let vectors = corpus();
    for check in [
        "sensitive_read_context",
        "sensitive_read_reuse",
        "sensitive_read_hint",
    ] {
        assert!(
            vectors.iter().any(|vector| vector["check"] == check),
            "missing {check}"
        );
    }
    for stage in ["initial", "claim_failed", "postclaim", "refresh_failed"] {
        assert!(
            vectors
                .iter()
                .any(|vector| vector["request"]["stage"] == stage),
            "missing stage {stage}"
        );
    }
}
