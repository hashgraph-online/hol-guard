//! Replays command-activity parity vectors recorded from the original Python
//! store (see `testdata/guard_store/record_command_activity_vectors.py`): the
//! schema, seed rows, results, errors and post-step table state all come from
//! Python, never from Rust output.

use std::path::{Path, PathBuf};

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_db::{exec, query_all};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/command_activity_vectors.json");

pub(crate) fn temp_home(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "hol-guard-cmd-vectors-{tag}-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::canonicalize(home).unwrap()
}

pub(crate) fn insert_rows(connection: &Connection, table: &str, rows: &Value) {
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

pub(crate) fn dump(connection: &Connection, table: &str, order_by: &str) -> Value {
    let rows = query_all(
        connection,
        &format!("select * from {table} order by {order_by}"),
        &[],
    )
    .unwrap();
    Value::Array(rows.into_iter().map(Value::Object).collect())
}

pub(crate) fn assert_rows(actual: &Value, expected: &Value, label: &str) {
    let (actual, expected) = (actual.as_array().unwrap(), expected.as_array().unwrap());
    assert_eq!(actual.len(), expected.len(), "{label}: row count");
    for (index, (left, right)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(left, right, "{label}: row {index}");
    }
}

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    // Command activity never writes the review outbox, but every write finalizes
    // pending outbox digests, so the table the resident probes must exist.
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
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

fn native_method(python_method: &str) -> &str {
    match python_method {
        "get_command_activity_by_request_correlation" => "command_activity_by_request_correlation",
        other => other,
    }
}

fn run_step(home: &Path, source: &str, step: &Value) -> Value {
    let args: Map<String, Value> = step["wire_args"].as_object().unwrap().clone();
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: native_method(step["method"].as_str().unwrap()).to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

pub(crate) fn apply_sql(home: &Path, step: &Value) {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    for pair in step["sql"].as_array().unwrap() {
        let params: Vec<Value> = pair[1].as_array().unwrap().clone();
        exec(&connection, pair[0].as_str().unwrap(), &params).unwrap();
    }
}

pub(crate) fn error_code(python_type: &str) -> &'static str {
    match python_type {
        "ValueError" => "native_guard_store_value_error",
        "IntegrityError" => "native_guard_store_integrity_error",
        "RuntimeError" => "native_guard_store_runtime_error",
        other => panic!("unmapped recorded error type {other}"),
    }
}

#[test]
fn replays_every_recorded_command_activity_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-command-activity-vectors.v1");
    let source = vectors["source"].as_str().unwrap();
    let order_by = vectors["order_by"].as_object().unwrap();
    let scenarios = vectors["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 8);
    let mut compared_steps = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {}", step["method"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
            } else if step["python_side"] == true {
                // Rejected in Python before any native call; table state must be unchanged.
            } else {
                let reply = run_step(&home, source, step);
                match step["error"].as_object() {
                    None => {
                        assert_eq!(reply["status"], "ok", "{label}: {reply}");
                        assert_eq!(reply["payload"], step["result"], "{label}");
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
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, key) in order_by {
                assert_rows(
                    &dump(&connection, table, key.as_str().unwrap()),
                    &expected[table],
                    &format!("{label}: {table}"),
                );
            }
            compared_steps += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_steps >= 60, "only {compared_steps} recorded steps");
}
