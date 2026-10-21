//! `record_native_decision_receipt` against the rows Python writes.
//!
//! The vectors were recorded by running the Python store over the same receipt
//! texts, so each scenario carries both the wire text the op receives and every
//! cell the two receipt tables end up holding.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_db::query_all;
use crate::guard_store_op::evaluate_guard_store_request;

const VECTORS: &str = include_str!("../testdata/guard_store/native_receipt_vectors.json");
const TABLES: [&str; 2] = [
    "native_hook_decision_receipts",
    "native_prompt_decision_receipts",
];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn build_database(path: &Path, vectors: &Value) {
    let connection = Connection::open(path).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    // Every store write commits through `finalize_and_commit`, which backfills
    // the digests triggers leave empty on the review outbox. The recorder
    // captured only the two receipt tables, so the outbox has to be declared
    // here for the commit to reach them.
    connection
        .execute_batch(
            "create table if not exists guard_review_outbox_events (\
             stream_sequence integer primary key, payload_hash text not null default '')",
        )
        .unwrap();
}

fn record(home: &Path, receipt: &str, now: &str) -> Value {
    let mut args = Map::new();
    args.insert("receipt".to_owned(), json!(receipt));
    args.insert("now".to_owned(), json!(now));
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "native-receipt".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "record_native_decision_receipt".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

/// Every row of both tables, shaped like the recorder's own dump.
fn dump(home: &Path) -> Value {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let mut tables = Map::new();
    for table in TABLES {
        let rows = query_all(
            &connection,
            &format!("select * from {table} order by decision_id"),
            &[],
        )
        .unwrap();
        tables.insert(
            table.to_owned(),
            Value::Array(rows.into_iter().map(Value::Object).collect()),
        );
    }
    Value::Object(tables)
}

#[test]
fn stores_what_python_stores() {
    let vectors = vectors();
    let now = vectors["recorded_at"].as_str().unwrap();
    for scenario in vectors["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let home = temp_home(&format!("native-receipt-{name}"));
        build_database(&home.join("guard.db"), &vectors);
        let expected_error = scenario["error"].as_str();
        for receipt in scenario["receipt_texts"].as_array().unwrap() {
            let reply = record(&home, receipt.as_str().unwrap(), now);
            match expected_error {
                None => assert_eq!(reply["status"], "ok", "{name}: {reply}"),
                Some(_) => {
                    assert_eq!(reply["status"], "error", "{name}: {reply}");
                    assert_eq!(reply["code"], "native_guard_store_value_error", "{name}");
                }
            }
        }
        assert_eq!(dump(&home), scenario["after"], "{name}");
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn a_receipt_that_is_not_json_is_invalid() {
    let vectors = vectors();
    let home = temp_home("native-receipt-not-json");
    build_database(&home.join("guard.db"), &vectors);
    let reply = record(&home, "{not json", vectors["recorded_at"].as_str().unwrap());
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["code"], "native_guard_store_value_error");
    let _ = std::fs::remove_dir_all(&home);
}
