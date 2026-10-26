//! Replays custom-extension grant read vectors recorded from the original
//! Python store (see `testdata/guard_store/record_local_cli_grant_vectors.py`).
//! Seeds, SQL steps, payloads and errors all come from Python, never from
//! Rust output.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_cmd_vectors_tests::{apply_sql, error_code, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/local_cli_grant_vectors.json");

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        insert_rows(&connection, table, rows);
    }
}

fn run_step(home: &Path, source: &str, step: &Value) -> Value {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: step["method"].as_str().unwrap().to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args: step["wire_args"].as_object().unwrap().clone(),
    };
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn replays_every_recorded_local_cli_grant_read() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-local-cli-grant-vectors.v1");
    let source = vectors["source"].as_str().unwrap();
    let mut compared_steps = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {} {}", step["method"], step["label"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
                continue;
            }
            let reply = run_step(&home, source, step);
            match step["error"].as_object() {
                None => {
                    assert_eq!(reply["status"], "ok", "{label}: {reply}");
                    assert_eq!(reply["payload"], step["native_payload"], "{label}");
                }
                Some(error) => {
                    assert_eq!(reply["status"], "error", "{label}: {reply}");
                    assert_eq!(
                        reply["code"],
                        error_code(error["type"].as_str().unwrap()),
                        "{label}"
                    );
                    assert_eq!(reply["payload"]["message"], error["message"], "{label}");
                }
            }
            compared_steps += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_steps >= 13, "only {compared_steps} recorded steps");
}
