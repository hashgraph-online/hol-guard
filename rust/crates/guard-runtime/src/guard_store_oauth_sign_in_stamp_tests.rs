//! The stored sign-in record's digest.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;

const KEY: &str = "oauth_local_credentials";

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
            "insert or replace into sync_state values (?1, ?2, 'now')",
            rusqlite::params![key, payload],
        )
        .unwrap();
}

fn stamp(connection: &Connection, key: &str) -> StoreResult<Value> {
    let map = json!({ "state_key": key }).as_object().cloned().unwrap();
    dispatch(connection, "oauth_sign_in_stamp", &Args(&map)).map(|answer| answer["stamp"].clone())
}

#[test]
fn a_missing_record_has_no_stamp() {
    assert_eq!(stamp(&store(), KEY).unwrap(), Value::Null);
}

#[test]
fn a_stored_record_is_stamped_with_the_digest_of_its_text() {
    let connection = store();
    let text = r#"{"key_id":"first"}"#;
    put(&connection, KEY, text);

    let expected = hex::encode(Sha256::digest(text.as_bytes()));
    assert_eq!(stamp(&connection, KEY).unwrap(), json!(expected));
}

#[test]
fn a_rewritten_record_changes_the_stamp() {
    let connection = store();
    put(&connection, KEY, r#"{"key_id":"first"}"#);
    let first = stamp(&connection, KEY).unwrap();
    put(&connection, KEY, r#"{"key_id":"second"}"#);

    assert_ne!(stamp(&connection, KEY).unwrap(), first);
}

#[test]
fn a_record_that_is_not_an_object_or_array_has_no_stamp() {
    let connection = store();
    for text in ["not-json", "7", "\"text\"", "null"] {
        put(&connection, KEY, text);
        assert_eq!(stamp(&connection, KEY).unwrap(), Value::Null, "{text}");
    }
}

#[test]
fn a_blob_cell_that_is_not_utf8_has_no_stamp() {
    let connection = store();
    connection
        .execute("insert into sync_state values (?1, x'ff00', 'now')", [KEY])
        .unwrap();
    assert_eq!(stamp(&connection, KEY).unwrap(), Value::Null);
}

#[test]
fn a_source_scoped_record_can_be_stamped() {
    let connection = store();
    put(&connection, "oauth_local_credentials:desktop", "{}");
    assert!(stamp(&connection, "oauth_local_credentials:desktop")
        .unwrap()
        .is_string());
}

#[test]
fn only_credential_rows_can_be_stamped() {
    let connection = store();
    put(&connection, "sync_summary", "{}");
    for key in ["sync_summary", "oauth_local_credentialsx", ""] {
        assert!(
            matches!(stamp(&connection, key), Err(StoreError::Value(_))),
            "{key}"
        );
    }
}

#[test]
fn the_method_is_routed_and_read_as_a_snapshot() {
    assert!(handles("oauth_sign_in_stamp"));
    assert!(crate::guard_store_sync_state::handles_row_method(
        "oauth_sign_in_stamp"
    ));
    assert!(matches!(
        crate::guard_store_op_kind::method_kind("oauth_sign_in_stamp"),
        Some(crate::guard_store_op_kind::Kind::Snapshot)
    ));
}
