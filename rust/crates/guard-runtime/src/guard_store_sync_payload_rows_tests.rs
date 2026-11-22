//! The credential row writer, the first-write-wins insert and the deletes.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;
use crate::guard_store_op_kind::{method_kind, Kind};

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
    let Value::Object(args) = args else {
        unreachable!("arguments are an object")
    };
    dispatch(connection, method, &Args(&args))
}

fn stored(connection: &Connection, state_key: &str) -> Option<(String, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?",
            [state_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()
}

fn put(connection: &Connection, state_key: &str, payload: &str) {
    connection
        .execute(
            "insert into sync_state values (?, ?, 't0')",
            [state_key, payload],
        )
        .unwrap();
}

#[test]
fn the_credential_writer_upserts_only_credential_rows() {
    let connection = store();
    for state_key in ["oauth_local_credentials", "oauth_local_credentials:scope"] {
        call(
            &connection,
            "write_credential_sync_payload",
            json!({"state_key": state_key, "payload": {"v": 1}, "now": "t1"}),
        )
        .unwrap();
        call(
            &connection,
            "write_credential_sync_payload",
            json!({"state_key": state_key, "payload": {"v": 2}, "now": "t2"}),
        )
        .unwrap();
        assert_eq!(
            stored(&connection, state_key),
            Some((r#"{"v":2}"#.into(), "t2".into()))
        );
    }
    for state_key in ["prefs", "oauth_local_credentialsx"] {
        assert!(call(
            &connection,
            "write_credential_sync_payload",
            json!({"state_key": state_key, "payload": {}, "now": "t1"}),
        )
        .is_err());
        assert_eq!(stored(&connection, state_key), None);
    }
}

#[test]
fn a_payload_must_be_an_object_or_array() {
    let connection = store();
    for payload in [json!("text"), json!(3), Value::Null] {
        assert!(call(
            &connection,
            "write_credential_sync_payload",
            json!({"state_key": "oauth_local_credentials", "payload": payload, "now": "t1"}),
        )
        .is_err());
        assert!(call(
            &connection,
            "insert_sync_payload_if_absent",
            json!({"state_key": "prefs", "payload": payload, "now": "t1"}),
        )
        .is_err());
    }
    assert_eq!(stored(&connection, "oauth_local_credentials"), None);
    assert_eq!(stored(&connection, "prefs"), None);
}

#[test]
fn an_existing_row_wins_over_the_insert() {
    let connection = store();
    let first = call(
        &connection,
        "insert_sync_payload_if_absent",
        json!({"state_key": "key", "payload": [1], "now": "t1"}),
    )
    .unwrap();
    let second = call(
        &connection,
        "insert_sync_payload_if_absent",
        json!({"state_key": "key", "payload": [2], "now": "t2"}),
    )
    .unwrap();
    assert_eq!((first, second), (json!(true), json!(false)));
    assert_eq!(
        stored(&connection, "key"),
        Some(("[1]".into(), "t1".into()))
    );
    assert!(call(
        &connection,
        "insert_sync_payload_if_absent",
        json!({"state_key": "oauth_local_credentials", "payload": {}, "now": "t1"}),
    )
    .is_err());
}

#[test]
fn deletes_remove_the_named_rows_and_count_them() {
    let connection = store();
    for state_key in ["a", "b", "c", "oauth_local_credentials"] {
        put(&connection, state_key, "{}");
    }
    call(
        &connection,
        "delete_sync_payload",
        json!({"state_key": "a"}),
    )
    .unwrap();
    call(
        &connection,
        "delete_sync_payload",
        json!({"state_key": "oauth_local_credentials"}),
    )
    .unwrap();
    assert_eq!(stored(&connection, "a"), None);
    assert_eq!(stored(&connection, "oauth_local_credentials"), None);
    let deleted = call(
        &connection,
        "delete_sync_payloads",
        json!({"state_keys": ["b", "b", "missing"]}),
    )
    .unwrap();
    assert_eq!(deleted, json!(1));
    assert_eq!(
        call(
            &connection,
            "delete_sync_payloads",
            json!({"state_keys": []})
        )
        .unwrap(),
        json!(0)
    );
    assert!(call(&connection, "delete_sync_payloads", json!({})).is_err());
    assert!(stored(&connection, "c").is_some());
}

#[test]
fn every_method_is_a_routed_write() {
    for method in [
        "write_credential_sync_payload",
        "insert_sync_payload_if_absent",
        "delete_sync_payload",
        "delete_sync_payloads",
    ] {
        assert!(handles(method));
        assert!(super::super::handles_row_method(method));
        assert!(matches!(method_kind(method), Some(Kind::Write)));
    }
    assert!(!handles("set_sync_payload"));
}
