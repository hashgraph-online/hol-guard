//! `record_tool_call_evidence` writes the inventory row, receipt and runtime
//! event in one transaction. Seeds and the receipt/inventory wire shapes come
//! from the recorded Python vectors; only the combined request is new.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_cmd_vectors_tests::{insert_rows, temp_home};
use crate::guard_store_op::evaluate_guard_store_request;

const RECEIPTS: &str = include_str!("../testdata/guard_store/receipts_vectors.json");
const INVENTORY: &str = include_str!("../testdata/guard_store/inventory_vectors.json");
const EVENT_PAYLOAD: &str = "{\"artifact_id\": \"artifact-1\", \"signals\": []}";

fn vectors() -> (Value, Value) {
    (
        serde_json::from_str(RECEIPTS).unwrap(),
        serde_json::from_str(INVENTORY).unwrap(),
    )
}

fn build_database(path: &Path, receipts: &Value, inventory: &Value) {
    let connection = Connection::open(path).unwrap();
    connection.execute_batch("pragma journal_mode=wal").ok();
    connection
        .execute_batch("create table if not exists guard_review_outbox_events (stream_sequence integer primary key, payload_hash text not null default '')")
        .unwrap();
    for statement in receipts["schema_sql"]
        .as_array()
        .unwrap()
        .iter()
        .chain(inventory["schema_sql"].as_array().unwrap())
    {
        let sql = statement.as_str().unwrap();
        if sql.contains("TRIGGER guard_review_outbox_after_") {
            continue;
        }
        if let Err(error) = connection.execute_batch(sql) {
            assert!(error.to_string().contains("already exists"), "{error}");
        }
    }
    connection
        .execute_batch(
            "create table if not exists guard_events (event_id integer primary key autoincrement, \
             event_name text not null, payload_json text not null, occurred_at text not null)",
        )
        .unwrap();
    for (table, rows) in receipts["scenarios"][0]["seed"].as_object().unwrap() {
        insert_rows(&connection, table, rows);
    }
}

fn request_args(receipts: &Value, inventory: &Value) -> Map<String, Value> {
    let inventory_args = inventory["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|scenario| scenario["steps"].as_array().unwrap())
        .find(|step| step["method"] == "record_inventory_artifact")
        .unwrap()["wire_args"]
        .clone();
    let mut args = receipts["scenarios"][0]["steps"][0]["wire_args"]
        .as_object()
        .unwrap()
        .clone();
    args.insert("inventory".to_owned(), inventory_args);
    args.insert("event_name".to_owned(), json!("runtime_tool_call_allowed"));
    args.insert("event_payload_json".to_owned(), json!(EVENT_PAYLOAD));
    args.insert(
        "event_occurred_at".to_owned(),
        json!("2026-04-02T12:30:00.123456+00:00"),
    );
    args
}

fn run(home: &Path, args: Map<String, Value>) -> Value {
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "evidence".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "record_tool_call_evidence".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&evaluate_guard_store_request(&request).unwrap()).unwrap()
}

fn count(home: &Path, table: &str) -> i64 {
    Connection::open(home.join("guard.db"))
        .unwrap()
        .query_row(&format!("select count(*) from {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn writes_inventory_receipt_and_event_together() {
    let (receipts, inventory) = vectors();
    let home = temp_home("tool-call-evidence-ok");
    build_database(&home.join("guard.db"), &receipts, &inventory);
    let reply = run(&home, request_args(&receipts, &inventory));
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(count(&home, "artifact_inventory"), 1);
    assert_eq!(count(&home, "runtime_receipts"), 1);
    let stored: String = Connection::open(home.join("guard.db"))
        .unwrap()
        .query_row(
            "select payload_json from guard_events where event_name = 'runtime_tool_call_allowed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, EVENT_PAYLOAD);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn a_failing_part_rolls_back_every_write() {
    let (receipts, inventory) = vectors();
    let home = temp_home("tool-call-evidence-rollback");
    build_database(&home.join("guard.db"), &receipts, &inventory);
    let mut args = request_args(&receipts, &inventory);
    args.remove("event_payload_json");
    let reply = run(&home, args);
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["code"], "native_guard_store_invalid");
    for table in ["artifact_inventory", "runtime_receipts", "guard_events"] {
        assert_eq!(count(&home, table), 0, "{table} must roll back");
    }
    let _ = std::fs::remove_dir_all(&home);
}
