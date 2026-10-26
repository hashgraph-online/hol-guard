//! Replays receipt write, read, rollup and analytics vectors recorded from the original Python store (see
//! `testdata/guard_store/record_receipts_vectors.py`). Seeds, payloads,
//! errors and post-step table state all come from Python, never from Rust
//! output. Structured `*_json` columns compare by decoded value because the
//! resident re-serializes merged metadata compactly.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_cmd_vectors_tests::{apply_sql, dump, error_code, insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/receipts_vectors.json");

fn build_database(path: &Path, vectors: &Value, scenario: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        let sql = statement.as_str().unwrap();
        // The review-outbox triggers feed tables this resident op never reads here.
        if sql.contains("TRIGGER guard_review_outbox_after_") {
            continue;
        }
        connection.execute_batch(sql).unwrap();
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
fn replays_every_recorded_receipt_scenario() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-store-receipts-vectors.v1");
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
    assert!(
        compared_steps >= 100,
        "only {compared_steps} recorded steps"
    );
}

#[test]
fn listing_queries_use_ordered_indexes() {
    use crate::guard_store_receipt_reads::BASE_QUERY;
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    let home = temp_home("receipt-plans");
    build_database(&home.join("guard.db"), &vectors, scenario);
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let plan = |clause: &str, params: &[&str]| -> String {
        let mut statement = connection
            .prepare(&format!("explain query plan {BASE_QUERY} {clause}"))
            .unwrap();
        let details: Vec<String> = statement
            .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                row.get::<_, String>("detail")
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        details.join(" ")
    };
    let by_harness = plan(
        "where r.harness = ? order by r.timestamp desc limit ?",
        &["codex", "200"],
    );
    let by_artifact = plan(
        "where r.harness = ? and r.artifact_id = ? order by r.timestamp desc limit 1",
        &["codex", "a"],
    );
    assert!(
        by_harness.contains("idx_receipts_harness_timestamp_desc"),
        "{by_harness}"
    );
    assert!(
        by_artifact.contains("idx_receipts_harness_artifact_timestamp_desc"),
        "{by_artifact}"
    );
    assert!(!by_harness.contains("USE TEMP B-TREE"), "{by_harness}");
    assert!(!by_artifact.contains("USE TEMP B-TREE"), "{by_artifact}");
    let _ = std::fs::remove_dir_all(&home);
}

/// A migration-requested rebuild keeps the archived totals and runs before the
/// first incremental delta or direct total read.
#[test]
fn pending_rebuild_runs_before_deltas_and_total_reads() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = &vectors["scenarios"][0];
    let home = temp_home("receipt-rebuild");
    build_database(&home.join("guard.db"), &vectors, scenario);
    let prepare = || {
        let connection = Connection::open(home.join("guard.db")).unwrap();
        connection
            .execute_batch(
                "update guard_storage_maintenance set archived_receipts = 7 where singleton = 1; \
                 update receipt_aggregate_totals set total = 7, allowed = 5, blocked = 2 \
                   where totals_key = 'global'; \
                 insert or replace into sync_state (state_key, payload_json, updated_at) \
                   values ('receipt_rollups_rebuild_pending', '{}', '2026-04-02T00:00:00Z');",
            )
            .unwrap();
        connection
    };
    let source = vectors["source"].as_str().unwrap();
    let now = vectors["now"].as_str().unwrap();
    let count = |home: &Path| {
        let step = serde_json::json!({"method": "count_receipts", "wire_args": {}});
        run_step(home, source, now, &step)
    };
    drop(prepare());
    let reply = count(&home);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], 7);
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let marker: i64 = connection
        .query_row(
            "select count(*) from sync_state where state_key = 'receipt_rollups_rebuild_pending'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(marker, 0);
    drop(connection);

    drop(prepare());
    let add = run_step(&home, source, now, &scenario["steps"][0]);
    assert_eq!(add["status"], "ok", "{add}");
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let totals: (i64, i64, i64) = connection
        .query_row(
            "select total, allowed, blocked from receipt_aggregate_totals where totals_key = 'global'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(totals, (8, 6, 2));
    let _ = std::fs::remove_dir_all(&home);
}
