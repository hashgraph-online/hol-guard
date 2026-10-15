//! Replays storage-maintenance vectors recorded from the original Python store
//! (see `testdata/guard_store/record_storage_maintenance_vectors.py`). Seeds,
//! results and post-step table state all come from Python, never from Rust
//! output. Free-page counts depend on file layout, so the scenarios that
//! exercise them check the documented reclaim rule instead of a recorded count.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_vectors_tests::{apply_sql, dump, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/storage_maintenance_vectors.json");
const PAGE_FIELDS: [&str; 2] = ["pages_reclaimed", "last_pages_reclaimed"];

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(&format!(
            "pragma auto_vacuum={}",
            scenario["auto_vacuum"].as_i64().unwrap()
        ))
        .unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    // Python seeded these rows with foreign keys off; replay them the same way.
    connection.execute_batch("pragma foreign_keys=off").unwrap();
    // Maintenance never writes the review outbox, but every write probes it.
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
    for statement in vectors["trigger_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
}

fn run_step(home: &Path, source: &str, step: &Value) -> Value {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "maintain_storage".to_owned(),
        source: source.to_owned(),
        busy_timeout_ms: 5000,
        args: step["wire_args"].as_object().unwrap().clone(),
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

fn strip_pages(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(strip_pages).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| !PAGE_FIELDS.contains(&key.as_str()))
                .map(|(key, item)| (key.clone(), item.clone()))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn freelist(home: &Path) -> i64 {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection
        .pragma_query_value(None, "freelist_count", |row| row.get(0))
        .unwrap()
}

#[test]
fn replays_every_recorded_storage_maintenance_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(
        vectors["schema"],
        "guard-store-storage-maintenance-vectors.v1"
    );
    let source = vectors["source"].as_str().unwrap();
    let order_by = vectors["order_by"].as_object().unwrap();
    let mut compared_steps = 0;
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let page_dependent = name.contains("vacuum");
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, scenario);
        let mut expected: Map<String, Value> = scenario["seed"].as_object().unwrap().clone();
        for (index, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            let label = format!("{name}#{index} {}", step["label"]);
            if step["kind"] == "sql" {
                apply_sql(&home, step);
            } else {
                let batch = step["wire_args"]["batch_size"].as_i64().unwrap();
                let before_free = freelist(&home);
                let reply = run_step(&home, source, step);
                assert_eq!(reply["status"], "ok", "{label}: {reply}");
                let recorded = &step["result"];
                let payload = &reply["payload"];
                for field in [
                    "completed",
                    "receipts_archived",
                    "native_decision_receipts_deleted",
                    "guard_events_deleted",
                    "cloud_events_deleted",
                ] {
                    assert_eq!(payload[field], recorded[field], "{label}: {field}");
                }
                if page_dependent {
                    let pages = payload["pages_reclaimed"].as_i64().unwrap();
                    let after = freelist(&home);
                    if scenario["auto_vacuum"] == 0 {
                        assert_eq!(pages, 0, "{label}");
                        assert!(after >= before_free, "{label}");
                    } else {
                        // Free pages after the deletes, before the vacuum, is
                        // `after + pages`; the vacuum releases at most `batch`.
                        assert_eq!(pages, (after + pages).min(batch), "{label}");
                    }
                } else {
                    assert_eq!(
                        payload["pages_reclaimed"], recorded["pages_reclaimed"],
                        "{label}"
                    );
                }
            }
            for (table, rows) in step["post_changed"].as_object().unwrap() {
                expected.insert(table.clone(), rows.clone());
            }
            let connection = Connection::open(home.join("guard.db")).unwrap();
            for (table, key) in order_by {
                let (actual, want) = (
                    dump(&connection, table, key.as_str().unwrap()),
                    expected[table].clone(),
                );
                if page_dependent {
                    assert_eq!(strip_pages(&actual), strip_pages(&want), "{label}: {table}");
                } else {
                    assert_eq!(actual, want, "{label}: {table}");
                }
            }
            compared_steps += 1;
        }
        let _ = std::fs::remove_dir_all(&home);
    }
    assert!(compared_steps >= 25, "only {compared_steps} recorded steps");
}

#[test]
fn housekeeping_runs_outside_a_transaction() {
    let home = temp_home("housekeeping");
    let connection = Connection::open(home.join("guard.db")).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table t (a integer); insert into t values (1); create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    drop(connection);
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "housekeeping".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "run_storage_housekeeping".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 1,
        args: Map::new(),
    };
    let reply: Value =
        serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], Value::Null);
    let _ = std::fs::remove_dir_all(&home);
}
