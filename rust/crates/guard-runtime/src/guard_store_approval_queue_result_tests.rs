//! Replays queue-result and native workspace-review resolution vectors
//! recorded from the original Python implementation (see
//! `testdata/guard_store/record_approval_queue_result_vectors.py`). Seeds,
//! results, resolved rows, receipts and errors all come from Python, never
//! from Rust output.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_approval_reads::tests::{expected, seed, store_call};
use crate::guard_store_approval_sweep::tests::states;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/guard_store/approval_queue_result_vectors.json");

fn sync_state(path: &std::path::Path) -> BTreeMap<String, Value> {
    let connection = Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("select state_key, payload_json, updated_at from sync_state")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            let key: String = row.get(0)?;
            let payload: String = row.get(1)?;
            let updated: String = row.get(2)?;
            Ok((key.clone(), json!([key, payload, updated])))
        })
        .unwrap();
    rows.collect::<Result<_, _>>().unwrap()
}

fn seed_sync_state(path: &std::path::Path, entries: &Value) {
    let connection = Connection::open(path).unwrap();
    for entry in entries.as_array().unwrap() {
        connection
            .execute(
                "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
                [
                    entry[0].as_str().unwrap(),
                    entry[1].as_str().unwrap(),
                    entry[2].as_str().unwrap(),
                ],
            )
            .unwrap();
    }
}

#[test]
fn replays_every_recorded_queue_result_resolution() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-approval-queue-result-vectors.v1"
    );
    let mut replayed = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        for (index, call) in scenario["calls"].as_array().unwrap().iter().enumerate() {
            let method = call["method"].as_str().unwrap();
            let label = format!("{name}#{index} {method}");
            let home = temp_home(&format!("approval-queue-result-{name}-{index}"));
            let path = home.join("guard.db");
            seed(&path, &vectors, scenario);
            seed_sync_state(&path, &scenario["sync_state"]);
            let before = states(&path);
            let state_before = sync_state(&path);
            let actual = store_call(
                &home,
                call["source"].as_str().unwrap(),
                method,
                call["args"].clone(),
            );
            assert_eq!(actual, expected(call, usize::MAX), "{label}");
            let changed: Vec<Value> = states(&path)
                .into_iter()
                .filter(|(id, state)| before[id] != *state)
                .map(|(id, state)| json!([id, state[0], state[1], state[2], state[3], state[4]]))
                .collect();
            assert_eq!(Value::Array(changed), call["changed"], "{label}");
            let written: Vec<Value> = sync_state(&path)
                .into_iter()
                .filter(|(key, entry)| state_before.get(key) != Some(entry))
                .map(|(_, entry)| entry)
                .collect();
            assert_eq!(Value::Array(written), call["sync_state_changed"], "{label}");
            let _ = std::fs::remove_dir_all(&home);
            replayed += 1;
        }
    }
    assert!(replayed >= 100, "replayed {replayed} calls");
}

#[test]
fn a_reply_too_large_to_send_fails_before_the_commit() {
    let small = json!({"resolved": true, "item": {"request_id": "req-1"}});
    assert_eq!(super::fits(small.clone()).unwrap(), small);
    let large =
        json!({"resolved": true, "item": {"preview": "x".repeat(super::REPLY_LIMIT_BYTES)}});
    assert!(super::fits(large).is_err());
}
