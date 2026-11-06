//! Replays command-activity read, feedback and privacy vectors recorded from
//! the original Python store (see
//! `testdata/guard_store/record_command_activity_read_vectors.py`). Seeds,
//! results, errors and post-step table state all come from Python, never from
//! Rust output.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::{
    apply_sql, assert_rows, dump, error_code, insert_rows, temp_home,
};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/command_activity_read_vectors.json");

fn is_trigger(statement: &str) -> bool {
    statement
        .trim_start()
        .to_lowercase()
        .starts_with("create trigger")
}

/// Tables and indexes, then the Python-dumped seed (foreign keys off so row
/// order is free), then triggers, so seeding never re-derives rows.
fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    let schema = vectors["schema_sql"].as_array().unwrap();
    for statement in schema
        .iter()
        .filter(|item| !is_trigger(item.as_str().unwrap()))
    {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    connection.execute_batch("pragma foreign_keys=off").unwrap();
    for (table, rows) in scenario["seed"].as_object().unwrap() {
        connection
            .execute_batch(&format!("delete from {table}"))
            .unwrap();
        insert_rows(&connection, table, rows);
    }
    connection.execute_batch("pragma foreign_keys=on").unwrap();
    for statement in schema
        .iter()
        .filter(|item| is_trigger(item.as_str().unwrap()))
    {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
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
    let bytes = evaluate_guard_store_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn check_reply(reply: &Value, step: &Value, label: &str) {
    match step["error"].as_object() {
        None => {
            assert_eq!(reply["status"], "ok", "{label}: {reply}");
            assert_eq!(reply["payload"], step["native_payload"], "{label}");
        }
        Some(error) if error["type"] == "CommandActivityNotFoundError" => {
            assert_eq!(reply["status"], "ok", "{label}: {reply}");
            assert_eq!(reply["payload"], json!({ "not_found": true }), "{label}");
        }
        Some(error) => {
            assert_eq!(reply["status"], "error", "{label}: {reply}");
            assert_eq!(
                reply["code"],
                error_code(error["type"].as_str().unwrap()),
                "{label}"
            );
        }
    }
}

#[test]
fn replays_every_recorded_command_activity_read_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-command-activity-read-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let order_by = vectors["order_by"].as_object().unwrap();
    let scenarios = vectors["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 5);
    let mut native_steps = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {} {}", step["method"], step["label"]);
            if step["method"] == "sql" {
                apply_sql(&home, step);
            } else if step["python_side"] != true {
                check_reply(&run_step(&home, source, step), step, &label);
                native_steps += 1;
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
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(
        native_steps >= 60,
        "only {native_steps} native steps replayed"
    );
}

fn plan(connection: &Connection, filters: Value) -> String {
    let (sql, params) =
        crate::guard_store_cmd_api::page_query(filters.as_object().unwrap(), None, 10).unwrap();
    let rows =
        crate::guard_store_db::query_all(connection, &format!("explain query plan {sql}"), &params)
            .unwrap();
    rows.iter()
        .map(|row| row["detail"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn filtered_page_query_plans_are_index_driven() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let connection = Connection::open_in_memory().unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    let status = plan(
        &connection,
        json!({ "execution_status": "confirmed_failure" }),
    );
    let rule = plan(&connection, json!({ "rule_id": "command.git.missing" }));
    assert!(
        status.contains("idx_command_activity_execution_status_occurred_at"),
        "{status}"
    );
    assert!(rule.contains("idx_command_activity_match_rule"), "{rule}");
    let bare = "SCAN activity USING INDEX idx_command_activity_occurred_at";
    assert!(!status.contains(bare), "{status}");
    assert!(!rule.contains(bare), "{rule}");
}
