//! Replays local CLI inventory read vectors recorded from the original Python
//! store (see `testdata/guard_store/record_local_cli_inventory_vectors.py`).
//! Seeds, SQL steps and payloads all come from Python, never from Rust output.
//!
//! The recorder had no native resident, so Python left `suggestion_score`,
//! `suggestable` and every command's `classification` at their defaults while
//! Rust evaluates them in process. Those three fields are dropped from both
//! sides here and covered by the ranker's and the classifier's own tests; the
//! replay still holds Rust to Python on every row, merge, order and shape.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_cmd_vectors_tests::{apply_sql, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/local_cli_inventory_vectors.json");

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

/// Drop the fields the recorder could not produce without a native resident.
fn without_native_fields(payload: &Value) -> Value {
    let mut payload = payload.clone();
    let Some(items) = payload.as_array_mut() else {
        return payload;
    };
    for item in items {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        item.remove("suggestion_score");
        item.remove("suggestable");
        let Some(commands) = item.get_mut("commands").and_then(Value::as_array_mut) else {
            continue;
        };
        for command in commands {
            if let Some(command) = command.as_object_mut() {
                command.remove("classification");
            }
        }
    }
    payload
}

/// Every item carries both ranking fields, so the replay's normalization
/// cannot hide a missing call into the ranker.
fn assert_ranked(payload: &Value, label: &str) {
    for item in payload.as_array().expect(label) {
        assert!(item.get("suggestion_score").is_some(), "{label}: {item}");
        assert!(item["suggestable"].is_boolean(), "{label}: {item}");
    }
}

#[test]
fn replays_every_recorded_local_cli_inventory_read() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-local-cli-inventory-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let mut compared_items = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {}", step["label"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
                continue;
            }
            let reply = run_step(&home, source, step);
            assert_eq!(reply["status"], "ok", "{label}: {reply}");
            assert_ranked(&reply["payload"], &label);
            assert_eq!(
                without_native_fields(&reply["payload"]),
                without_native_fields(&step["native_payload"]),
                "{label}"
            );
            compared_items += step["native_payload"].as_array().unwrap().len();
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_items >= 9, "only {compared_items} recorded items");
}
