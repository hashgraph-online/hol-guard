//! Parity vectors recorded from the retired Python proxy decision methods.
//!
//! Each vector drove the pre-change Python with stubbed collaborators and
//! recorded the branch taken plus the facts it consulted. The expected value
//! is a subset of the resident payload: every recorded key must match, and
//! the resident may report more. Lazily supplied facts appear in a vector only
//! when the Python consulted them, so removing one must make the resident ask.

use guard_contracts::McpProxyQueryV1;
use serde_json::{json, Value};

use crate::mcp_proxy_decision_op::decide;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_proxy_decision/parity_vectors.json");

fn is_subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(want), Value::Object(have)) => want
            .iter()
            .all(|(key, value)| have.get(key).is_some_and(|got| is_subset(value, got))),
        _ => expected == actual,
    }
}

fn query(request: &Value) -> McpProxyQueryV1 {
    serde_json::from_value(request.clone()).expect("vector request must deserialize")
}

fn corpus() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    document["vectors"].as_array().unwrap().clone()
}

#[test]
fn resident_matches_every_recorded_vector() {
    let vectors = corpus();
    assert!(vectors.len() > 2000, "corpus unexpectedly small");
    for vector in &vectors {
        let actual = decide(&query(&vector["request"]));
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
fn every_check_family_is_recorded() {
    let vectors = corpus();
    for check in [
        "catalog_event",
        "saved_allow_gate",
        "boundary_failure",
        "tool_postclaim",
        "package_postclaim",
        "package_precheck",
        "package_compose",
        "route_tool_call",
        "observe_tool_forward",
        "evidence_item",
    ] {
        assert!(
            vectors.iter().any(|vector| vector["check"] == check),
            "no vectors for {check}"
        );
    }
}

fn need_of(request: &Value) -> Option<String> {
    decide(&query(request))["need"].as_str().map(str::to_owned)
}

#[test]
fn removing_a_consulted_fact_makes_the_resident_ask_for_it() {
    let lazy = [
        (
            "route_tool_call",
            "package_saved_policy_blocks",
            "package_policy",
        ),
        ("route_tool_call", "native_prompt_allows", "native_prompt"),
        ("route_tool_call", "inline_approval", "inline_approval"),
        (
            "tool_postclaim",
            "fresh_claim_allows_reapproval",
            "fresh_claim_allows_reapproval",
        ),
        ("package_postclaim", "package", "postclaim_package"),
    ];
    let mut checked = 0;
    for vector in corpus() {
        for (check, key, name) in lazy {
            if vector["check"] != check || vector["request"].get(key).is_none() {
                continue;
            }
            let mut request = vector["request"].clone();
            request.as_object_mut().unwrap().remove(key);
            assert_eq!(need_of(&request).as_deref(), Some(name), "{}", vector["id"]);
            // The complete request never asks.
            assert_eq!(need_of(&vector["request"]), None, "{}", vector["id"]);
            checked += 1;
        }
    }
    assert!(checked > 200, "too few lazy-fact vectors: {checked}");
}

#[test]
fn a_fact_the_python_never_consulted_is_not_requested() {
    let mut checked = 0;
    for vector in corpus() {
        if vector["check"] == "route_tool_call" || vector["check"] == "tool_postclaim" {
            assert_eq!(need_of(&vector["request"]), None, "{}", vector["id"]);
            checked += 1;
        }
    }
    assert!(checked > 500);
    let _ = json!(null);
}
