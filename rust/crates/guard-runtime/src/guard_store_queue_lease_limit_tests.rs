//! The lease limit is merged into the lane row, written only when it changes.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const MAIN: &str = "guard_command_queue_state";
const DRAIN: &str = "guard_command_queue_state.review_drain.1";
const NOW: &str = "2026-09-27T12:00:00+00:00";
const BEFORE: &str = "2026-09-27T11:00:00+00:00";

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

fn put(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload, BEFORE],
        )
        .unwrap();
}

fn row(connection: &Connection, key: &str) -> (Value, String) {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
        .unwrap()
}

fn record(connection: &Connection, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    method(connection, &Args(&args))
}

fn limit(key: &str, limit: Value) -> Value {
    json!({"state_key": key, "limit": limit, "now": NOW})
}

#[test]
fn the_limit_joins_the_stored_row_and_keeps_its_other_fields() {
    let connection = store();
    put(
        &connection,
        MAIN,
        r#"{"state":"result_pending","pending_result":{"job":{"id":"j"},"payload":{}}}"#,
    );
    assert_eq!(
        record(&connection, limit(MAIN, json!(4))).unwrap(),
        json!({"saved": true})
    );
    assert_eq!(
        row(&connection, MAIN),
        (
            json!({"state": "result_pending",
                   "pending_result": {"job": {"id": "j"}, "payload": {}},
                   "exact_lease_batch_limit": 4}),
            NOW.to_owned()
        )
    );
}

#[test]
fn an_unchanged_limit_is_not_written_and_a_drop_to_one_is() {
    let connection = store();
    put(&connection, DRAIN, r#"{"exact_lease_batch_limit":4}"#);
    assert_eq!(
        record(&connection, limit(DRAIN, json!(4))).unwrap(),
        json!({"saved": false})
    );
    assert_eq!(row(&connection, DRAIN).1, BEFORE);
    assert_eq!(
        record(&connection, limit(DRAIN, json!(1))).unwrap(),
        json!({"saved": true})
    );
    assert_eq!(
        row(&connection, DRAIN),
        (json!({"exact_lease_batch_limit": 1}), NOW.to_owned())
    );
}

#[test]
fn a_missing_or_non_object_row_starts_from_an_empty_state() {
    let connection = store();
    record(&connection, limit(MAIN, json!(3))).unwrap();
    assert_eq!(
        row(&connection, MAIN).0,
        json!({"exact_lease_batch_limit": 3})
    );
    put(&connection, DRAIN, "[1, 2]");
    record(&connection, limit(DRAIN, json!(2))).unwrap();
    assert_eq!(
        row(&connection, DRAIN).0,
        json!({"exact_lease_batch_limit": 2})
    );
}

#[test]
fn a_stored_limit_that_is_not_a_positive_integer_is_replaced() {
    let connection = store();
    put(&connection, MAIN, r#"{"exact_lease_batch_limit":true}"#);
    assert_eq!(
        record(&connection, limit(MAIN, json!(1))).unwrap(),
        json!({"saved": true})
    );
    assert_eq!(
        row(&connection, MAIN).0,
        json!({"exact_lease_batch_limit": 1})
    );
}

#[test]
fn bad_limits_and_keys_outside_the_queue_lanes_are_refused() {
    let connection = store();
    for bad in [json!(0), json!(-2), json!(true), json!(2.5), json!("4")] {
        assert!(matches!(
            record(&connection, limit(MAIN, bad)),
            Err(StoreError::Value(code)) if code == "invalid_limit"
        ));
    }
    for key in [
        "oauth_local_credentials",
        "guard_command_capability_v1",
        "guard_command_queue_state.review_drain.x",
    ] {
        assert!(matches!(
            record(&connection, limit(key, json!(2))),
            Err(StoreError::Value(code)) if code == "invalid_state_key"
        ));
    }
    let count: i64 = connection
        .query_row("select count(*) from sync_state", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
