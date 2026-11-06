//! Replays single-request and duplicate-group approval resolution vectors
//! recorded from the original Python implementation (see
//! `testdata/guard_store/record_approval_resolution_vectors.py`). Seeds,
//! results, resolved rows and errors all come from Python, never from Rust
//! output.

use serde_json::{json, Value};

use crate::guard_store_approval_reads::tests::{seed, store_call};
use crate::guard_store_approval_sweep::tests::states;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_resolution_vectors.json");

#[test]
fn replays_every_recorded_approval_resolution() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-approval-resolution-vectors.v1"
    );
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let method = call["method"].as_str().unwrap();
            let label = format!("{name}#{index} {method}");
            let home = temp_home(&format!("approval-resolution-{name}-{index}"));
            let path = home.join("guard.db");
            seed(&path, &vectors, scenario);
            let before = states(&path);
            let actual = store_call(
                &home,
                call["source"].as_str().unwrap(),
                method,
                call["args"].clone(),
            );
            match &call["error"] {
                Value::Null => assert_eq!(actual, Ok(call["result"].clone()), "{label}"),
                error => assert_eq!(
                    actual.map_err(|(_, message)| message),
                    Err(error["message"].as_str().unwrap().to_owned()),
                    "{label}"
                ),
            }
            let changed: Vec<Value> = states(&path)
                .into_iter()
                .filter(|(id, state)| before[id] != *state)
                .map(|(id, state)| json!([id, state[0], state[1], state[2], state[3], state[4]]))
                .collect();
            assert_eq!(Value::Array(changed), call["changed"], "{label}");
            let _ = std::fs::remove_dir_all(&home);
            replayed += 1;
        }
    }
    assert!(replayed >= 80, "replayed {replayed} calls");
}

#[test]
fn refuses_a_duplicate_group_too_large_to_report_before_writing() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let (mut scenario, call) = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|scenario| {
            scenario["calls"]
                .as_array()
                .unwrap()
                .iter()
                .find_map(|call| {
                    (call["method"] == "resolve_matching_duplicate_requests"
                        && call["result"].as_array().is_some_and(|ids| !ids.is_empty()))
                    .then(|| (scenario.clone(), call.clone()))
                })
        })
        .unwrap();
    let resolvable = call["result"][0].as_str().unwrap();
    let rows = scenario["rows"].as_array_mut().unwrap();
    let template = rows
        .iter()
        .find(|row| row["request_id"] == resolvable)
        .unwrap()
        .clone();
    for index in 0..600 {
        let mut row = template.clone();
        row["request_id"] = json!(format!("{index:04}-{}", "x".repeat(4096)));
        rows.push(row);
    }
    let home = temp_home("approval-resolution-oversized-group");
    let path = home.join("guard.db");
    seed(&path, &vectors, &scenario);
    let before = states(&path);
    let actual = store_call(
        &home,
        call["source"].as_str().unwrap(),
        "resolve_matching_duplicate_requests",
        call["args"].clone(),
    );
    assert_eq!(
        actual.map_err(|(_, message)| message),
        Err("approval_duplicate_group_too_large".to_owned())
    );
    assert_eq!(states(&path), before);
    let _ = std::fs::remove_dir_all(&home);
}
