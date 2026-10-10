//! Replays parity vectors recorded from the original Python `GuardStore`
//! (see `testdata/guard_store/record_vectors.py`) through the `guard_store`
//! op: the schema, seed rows, results, errors and post-step table state all
//! come from Python, never from Rust output.

use std::path::{Path, PathBuf};

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_db::{exec, query_all};
use crate::guard_store_op::evaluate_guard_store_request;
use crate::guard_store_outbox_append::TEST_EVENT_ID_COUNTER;

const VECTORS: &str = include_str!("../testdata/guard_store/vectors.json");

fn temp_home(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "hol-guard-store-vectors-{tag}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::canonicalize(home).unwrap()
}

fn insert_rows(connection: &Connection, table: &str, rows: &Value) {
    for row in rows.as_array().unwrap() {
        let row = row.as_object().unwrap();
        let columns: Vec<&str> = row.keys().map(String::as_str).collect();
        let values: Vec<Value> = row.values().cloned().collect();
        let sql = format!(
            "insert into {table} ({}) values ({})",
            columns.join(","),
            vec!["?"; columns.len()].join(",")
        );
        exec(connection, &sql, &values).unwrap();
    }
}

fn dump(connection: &Connection, table: &str) -> Value {
    let rows = query_all(
        connection,
        &format!("select * from {table} order by rowid"),
        &[],
    )
    .unwrap();
    Value::Array(rows.into_iter().map(Value::Object).collect())
}

/// Equality where a recorded `"<random>"` matches any trigger-drawn event id.
fn same(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(id), Value::String(mask)) if mask == "<random>" => {
            id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(a, b)| same(a, b))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && right
                    .iter()
                    .all(|(key, value)| left.get(key).is_some_and(|actual| same(actual, value)))
        }
        _ => actual == expected,
    }
}

/// Row-by-row comparison that names the first differing columns.
fn assert_rows(actual: &Value, expected: &Value, label: &str) {
    let (actual, expected) = (actual.as_array().unwrap(), expected.as_array().unwrap());
    for (index, (left, right)) in actual.iter().zip(expected).enumerate() {
        let (left, right) = (left.as_object().unwrap(), right.as_object().unwrap());
        for (column, value) in right {
            assert!(
                left.get(column).is_some_and(|actual| same(actual, value)),
                "{label}: row {index} column {column}: {:?} != {value}",
                left.get(column)
            );
        }
    }
    assert_eq!(actual.len(), expected.len(), "{label}: row count");
}

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        connection
            .execute_batch(&format!("delete from {table}"))
            .unwrap();
        insert_rows(&connection, table, rows);
    }
}

fn run_step(home: &Path, source: &str, step: &Value) -> Value {
    let args: Map<String, Value> = step["wire_args"].as_object().unwrap().clone();
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
    TEST_EVENT_ID_COUNTER.with(|counter| {
        counter.set(Some(u128::from(step["uuid_start"].as_u64().unwrap())));
    });
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn error_code(python_type: &str) -> &'static str {
    match python_type {
        "ValueError" => "native_guard_store_value_error",
        "IntegrityError" => "native_guard_store_integrity_error",
        other => panic!("unmapped recorded error type {other}"),
    }
}

#[test]
fn replays_every_recorded_scenario_against_python_written_state() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-parity-vectors.v1");
    let source = vectors["source"].as_str().unwrap();
    let tables: Vec<&str> = vectors["tracked_tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|table| table.as_str().unwrap())
        .collect();
    let scenarios = vectors["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 10);
    let mut compared_steps = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {}", step["method"]);
            let reply = run_step(&home, source, step);
            match step["error"].as_object() {
                None => {
                    assert_eq!(reply["status"], "ok", "{label}: {reply}");
                    let payload = if step["method"] == "list_review_event_snapshots" {
                        // The resident pages this read; the Python original returned the
                        // whole history, so a recorded history must arrive as one final page.
                        assert!(reply["payload"]["next"].is_null(), "{label}: paged");
                        &reply["payload"]["snapshots"]
                    } else {
                        &reply["payload"]
                    };
                    assert!(same(payload, &step["result"]), "{label}: {payload}");
                }
                Some(error) => {
                    assert_eq!(reply["status"], "error", "{label}");
                    assert_eq!(
                        reply["code"],
                        error_code(error["type"].as_str().unwrap()),
                        "{label}"
                    );
                    assert_eq!(reply["payload"]["message"], error["message"], "{label}");
                }
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for table in &tables {
                assert_rows(
                    &dump(&connection, table),
                    &expected[*table],
                    &format!("{label}: {table}"),
                );
            }
            if !step["post_changed"].as_object().unwrap().is_empty() {
                let wake = &expected["guard_review_outbox_wake_state"][0]["generation"];
                assert_eq!(reply["outbox_generation"], *wake, "{label}: generation");
            }
            compared_steps += 1;
        }
        let user_version: i64 = Connection::open(home.join("guard.db"))
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(user_version, 0, "{name}: user_version must stay untouched");
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_steps >= 60, "only {compared_steps} recorded steps");
}
