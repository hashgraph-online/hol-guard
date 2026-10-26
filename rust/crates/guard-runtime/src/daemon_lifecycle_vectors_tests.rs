//! Parity vectors recorded from the retired Python daemon manager functions.
//!
//! Each vector drove the unmodified Python with scripted collaborators (path
//! resolution, pid probes, frozen-payload decoding, Windows argv) and recorded
//! the result plus the facts it consulted. The resident starts with no facts,
//! is answered from the vector's fact universe, and must reach the recorded
//! result while asking for every fact the Python consulted.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{DaemonLifecycleDecisionRequestV1, DAEMON_LIFECYCLE_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::daemon_lifecycle_decision_op::decide;

const VECTORS: &str = include_str!("../tests/fixtures/daemon_lifecycle_vectors.json");
const MAX_ROUNDS: usize = 12;

/// The recorder's defaults for facts a scenario left unscripted.
///
/// The live-state gate vectors were recorded up to the pid probe (the point the
/// Python reached before it consulted `_guard_daemon_pid_is_running`), so a
/// running pid is supplied for them; the not-running branch is unit tested.
fn supply(universe: &Value, key: &str, check: &str) -> Value {
    if check == "live_state_gate" && key.starts_with("pid_running:") {
        return json!(true);
    }
    if let Some(value) = universe.get(key) {
        return value.clone();
    }
    match key.split_once(':') {
        Some(("resolve", path)) => json!(path),
        Some(("pid_running" | "matches_command", _)) => json!(false),
        _ => Value::Null,
    }
}

fn run(vector: &Value) -> (Value, BTreeSet<String>) {
    let mut facts: BTreeMap<String, Value> = BTreeMap::new();
    let mut requested = BTreeSet::new();
    for _ in 0..MAX_ROUNDS {
        let request: DaemonLifecycleDecisionRequestV1 = serde_json::from_value(json!({
            "schema": DAEMON_LIFECYCLE_REQUEST_SCHEMA,
            "request_id": "vector",
            "platform": vector["platform"],
            "facts": facts,
            "query": vector["query"],
        }))
        .expect("vector request must deserialize");
        let payload = decide(&request);
        if payload["need"] != "facts" {
            return (payload, requested);
        }
        for key in payload["keys"].as_array().unwrap() {
            let key = key.as_str().unwrap().to_owned();
            facts.insert(
                key.clone(),
                supply(&vector["universe"], &key, vector["check"].as_str().unwrap()),
            );
            requested.insert(key);
        }
    }
    panic!(
        "vector {} did not settle in {MAX_ROUNDS} rounds",
        vector["id"]
    );
}

#[test]
fn resident_matches_every_recorded_vector() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 8000, "corpus unexpectedly small");
    let mut failures: Vec<String> = Vec::new();
    for vector in vectors {
        let (actual, requested) = run(vector);
        if actual != vector["expected"] {
            failures.push(format!(
                "vector {} diverged\nquery {}\n  actual   {actual}\n  expected {}",
                vector["id"], vector["query"], vector["expected"]
            ));
            continue;
        }
        for consulted in vector["consulted"].as_array().unwrap() {
            let consulted = consulted.as_str().unwrap();
            if !requested.contains(consulted) {
                failures.push(format!(
                    "vector {} never asked for {consulted}\nquery {}",
                    vector["id"], vector["query"]
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} vectors failed; first:\n{}",
        failures.len(),
        vectors.len(),
        failures
            .iter()
            .take(6)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_check_is_covered_by_the_corpus() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let counts = document["counts"].as_object().unwrap();
    assert_eq!(counts.len(), 25);
    assert!(counts.values().all(|count| count.as_u64().unwrap() >= 14));
}
