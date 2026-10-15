//! Replays guard session, operation, item, client-attachment and surface-open
//! vectors recorded from the original Python store (see
//! `testdata/guard_store/record_guard_sessions_vectors.py`). Seeds, payloads,
//! errors and post-step table state all come from Python, never from Rust
//! output. Structured `*_json` columns compare by decoded value because the
//! resident re-serializes merged metadata compactly.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_vectors_tests::{apply_sql, dump, error_code, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/guard_sessions_vectors.json");

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

/// Decode every `*_json` text column so formatting differences do not matter.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let decoded = match (key.ends_with("_json"), item) {
                        (true, Value::String(text)) => {
                            serde_json::from_str(text).unwrap_or_else(|_| item.clone())
                        }
                        _ => item.clone(),
                    };
                    (key.clone(), decoded)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn run_step(home: &Path, source: &str, now: &str, step: &Value) -> Value {
    let mut args: Map<String, Value> = step["wire_args"].as_object().unwrap().clone();
    if args.get("now") == Some(&Value::from("<NOW>")) {
        args.insert("now".to_owned(), Value::from(now));
    }
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: step["method"].as_str().unwrap().to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn replays_every_recorded_guard_session_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-guard-sessions-vectors.v1");
    let (source, now) = (
        vectors["source"].as_str().unwrap(),
        vectors["now"].as_str().unwrap(),
    );
    let order_by = vectors["order_by"].as_object().unwrap();
    let mut compared_steps = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {} {}", step["method"], step["label"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
            } else {
                let reply = run_step(&home, source, now, step);
                match step["error"].as_object() {
                    None => {
                        assert_eq!(reply["status"], "ok", "{label}: {reply}");
                        assert_eq!(
                            normalize(&reply["payload"]),
                            normalize(&step["native_payload"]),
                            "{label}"
                        );
                    }
                    Some(error) => {
                        assert_eq!(reply["status"], "error", "{label}: {reply}");
                        assert_eq!(
                            reply["code"],
                            error_code(error["type"].as_str().unwrap()),
                            "{label}"
                        );
                        if error["message_exact"] == true {
                            assert_eq!(reply["payload"]["message"], error["message"], "{label}");
                        }
                    }
                }
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, key) in order_by {
                assert_eq!(
                    normalize(&dump(&connection, table, key.as_str().unwrap())),
                    normalize(&expected[table]),
                    "{label}: {table}"
                );
            }
            compared_steps += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_steps >= 70, "only {compared_steps} recorded steps");
}
