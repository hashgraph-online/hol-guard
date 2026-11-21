//! The worker-host handoff rows: approval attention, the refresh request and
//! its answer, and the repair self-check status.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;

const NOW: &str = "2026-11-21T00:00:00+00:00";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (
               state_key text primary key, payload_json text not null,
               updated_at text not null);",
        )
        .unwrap();
    connection
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let map = args.as_object().cloned().unwrap_or_default();
    dispatch(connection, method, &Args(&map))
}

fn put(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload, NOW],
        )
        .unwrap();
}

fn keys(connection: &Connection) -> Vec<String> {
    let mut statement = connection
        .prepare("select state_key from sync_state order by state_key")
        .unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn is_value_error(result: StoreResult<Value>, code: &str) -> bool {
    matches!(result, Err(StoreError::Value(message)) if message == code)
}

#[test]
fn queued_attention_is_taken_once_in_key_order() {
    let connection = store();
    for operation in ["op-b", "op-a"] {
        let args = json!({"operation_id": operation, "requests": [{"id": operation}], "now": NOW});
        assert_eq!(
            call(&connection, "queue_approval_attention", args).unwrap(),
            Value::Null
        );
    }
    put(&connection, "daemon_approval_attention:op-c", "[1]");
    put(
        &connection,
        "daemon_approval_attentionXop-d",
        "{\"operation_id\":\"x\"}",
    );
    let taken = call(&connection, "take_approval_attention", json!({})).unwrap();
    assert_eq!(
        taken,
        json!([
            {"operation_id": "op-a", "requests": [{"id": "op-a"}]},
            {"operation_id": "op-b", "requests": [{"id": "op-b"}]},
        ])
    );
    assert_eq!(
        keys(&connection),
        vec!["daemon_approval_attentionXop-d".to_owned()]
    );
    assert_eq!(
        call(&connection, "take_approval_attention", json!({})).unwrap(),
        json!([])
    );
}

#[test]
fn malformed_attention_writes_nothing() {
    let connection = store();
    let cases = [
        (
            json!({"operation_id": "", "requests": [], "now": NOW}),
            "invalid_operation_id",
        ),
        (
            json!({"operation_id": "op", "requests": {}, "now": NOW}),
            "invalid_requests",
        ),
        (
            json!({"operation_id": "op", "requests": [], "now": ""}),
            "invalid_now",
        ),
    ];
    for (args, code) in cases {
        assert!(is_value_error(
            call(&connection, "queue_approval_attention", args),
            code
        ));
    }
    assert!(keys(&connection).is_empty());
}

#[test]
fn refresh_request_round_trip_matches_the_nonce() {
    let connection = store();
    assert_eq!(
        call(&connection, "take_worker_refresh_request", json!({})).unwrap(),
        Value::Null
    );
    call(
        &connection,
        "request_worker_refresh",
        json!({"nonce": "n1", "now": NOW}),
    )
    .unwrap();
    let nonce_args = json!({"nonce": "n1"});
    assert_eq!(
        call(&connection, "worker_refresh_status", nonce_args.clone()).unwrap(),
        Value::Null
    );
    assert_eq!(
        call(&connection, "take_worker_refresh_request", json!({})).unwrap(),
        json!("n1")
    );
    assert!(keys(&connection).is_empty());
    let status = json!({"nonce": "n1", "running": true, "sync_running": false, "now": NOW});
    call(&connection, "record_worker_refresh_status", status).unwrap();
    assert_eq!(
        call(&connection, "worker_refresh_status", nonce_args).unwrap(),
        json!({"running": true, "sync_running": false})
    );
    assert_eq!(
        call(
            &connection,
            "worker_refresh_status",
            json!({"nonce": "other"})
        )
        .unwrap(),
        Value::Null
    );
}

#[test]
fn malformed_refresh_request_is_left_in_place() {
    let connection = store();
    put(
        &connection,
        "daemon_worker_refresh_request",
        "{\"nonce\":7}",
    );
    assert_eq!(
        call(&connection, "take_worker_refresh_request", json!({})).unwrap(),
        Value::Null
    );
    assert_eq!(
        keys(&connection),
        vec!["daemon_worker_refresh_request".to_owned()]
    );
}

#[test]
fn refresh_status_reads_only_true_flags() {
    let connection = store();
    put(
        &connection,
        "daemon_worker_refresh_status",
        "{\"nonce\":\"n\",\"running\":\"yes\",\"sync_running\":1}",
    );
    assert_eq!(
        call(&connection, "worker_refresh_status", json!({"nonce": "n"})).unwrap(),
        json!({"running": false, "sync_running": false})
    );
}

#[test]
fn repair_self_check_status_round_trips_objects_only() {
    let connection = store();
    assert_eq!(
        call(&connection, "repair_self_check_status", json!({})).unwrap(),
        Value::Null
    );
    let status = json!({"status": {"ok": true, "checks": [1]}, "now": NOW});
    call(&connection, "record_repair_self_check", status).unwrap();
    assert_eq!(
        call(&connection, "repair_self_check_status", json!({})).unwrap(),
        json!({"ok": true, "checks": [1]})
    );
    put(&connection, "daemon_repair_self_check_status", "[1]");
    assert_eq!(
        call(&connection, "repair_self_check_status", json!({})).unwrap(),
        Value::Null
    );
    let bad = call(
        &connection,
        "record_repair_self_check",
        json!({"status": [1], "now": NOW}),
    );
    assert!(bad.is_err());
}

#[test]
fn a_large_backlog_is_taken_in_bounded_batches() {
    let connection = store();
    let filler = "x".repeat(ATTENTION_BATCH_BYTES * 3 / 5);
    for operation in ["op-a", "op-b"] {
        let row = json!({"operation_id": operation, "requests": [{"pad": filler}]});
        put(
            &connection,
            &format!("daemon_approval_attention:{operation}"),
            &row.to_string(),
        );
    }
    let first = call(&connection, "take_approval_attention", json!({})).unwrap();
    assert_eq!(first.as_array().unwrap().len(), 1);
    assert_eq!(first[0]["operation_id"], "op-a");
    assert_eq!(
        keys(&connection),
        vec!["daemon_approval_attention:op-b".to_owned()]
    );
    let second = call(&connection, "take_approval_attention", json!({})).unwrap();
    assert_eq!(second[0]["operation_id"], "op-b");
    assert!(keys(&connection).is_empty());
}

#[test]
fn an_oversized_stored_row_is_still_delivered_alone() {
    let connection = store();
    let big =
        json!({"operation_id": "op-a", "requests": [{"pad": "y".repeat(ATTENTION_BATCH_BYTES)}]});
    put(
        &connection,
        "daemon_approval_attention:op-a",
        &big.to_string(),
    );
    put(
        &connection,
        "daemon_approval_attention:op-b",
        "{\"operation_id\":\"op-b\"}",
    );
    let first = call(&connection, "take_approval_attention", json!({})).unwrap();
    assert_eq!(first, json!([big]));
    let second = call(&connection, "take_approval_attention", json!({})).unwrap();
    assert_eq!(second, json!([{"operation_id": "op-b"}]));
}

#[test]
fn an_oversized_attention_row_is_refused_before_writing() {
    let connection = store();
    let args = json!({
        "operation_id": "op",
        "requests": [{"pad": "z".repeat(ATTENTION_BATCH_BYTES)}],
        "now": NOW,
    });
    assert!(is_value_error(
        call(&connection, "queue_approval_attention", args),
        "attention_too_large"
    ));
    assert!(keys(&connection).is_empty());
}
