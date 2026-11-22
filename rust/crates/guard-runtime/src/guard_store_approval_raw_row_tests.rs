//! The raw approval request row.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table approval_requests (
               request_id text primary key, harness text, status text,
               dedupe_count integer, extra_column text);
             insert into approval_requests values ('r1', 'codex', 'pending', 2, null);",
        )
        .unwrap();
    connection
}

fn call(connection: &Connection, request_id: &str) -> StoreResult<Value> {
    let args = json!({"request_id": request_id});
    let Value::Object(args) = args else {
        unreachable!("arguments are an object")
    };
    get(connection, &Args(&args))
}

#[test]
fn the_row_carries_every_stored_column() {
    let connection = store();
    assert_eq!(
        call(&connection, "r1").unwrap(),
        json!({
            "request_id": "r1",
            "harness": "codex",
            "status": "pending",
            "dedupe_count": 2,
            "extra_column": null,
        })
    );
}

#[test]
fn a_missing_request_is_null() {
    assert_eq!(call(&store(), "missing").unwrap(), Value::Null);
}

#[test]
fn the_read_needs_a_request_id_and_is_a_snapshot_read() {
    let empty = serde_json::Map::new();
    assert!(get(&store(), &Args(&empty)).is_err());
    assert!(matches!(
        method_kind("get_raw_approval_request_snapshot"),
        Some(Kind::Snapshot)
    ));
}
