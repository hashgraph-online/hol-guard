//! The fleet posture hash key: reuse, creation and replacement.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;
use crate::guard_store_op_kind::{method_kind, Kind};

const NOW: &str = "2026-09-28T00:00:00+00:00";
const BEFORE: &str = "2026-09-27T23:00:00+00:00";

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

fn put(connection: &Connection, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![HASH_KEY_STATE_KEY, payload, BEFORE],
        )
        .unwrap();
}

fn stored(connection: &Connection) -> Option<(Value, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [HASH_KEY_STATE_KEY],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
}

fn call(connection: &Connection, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    method(connection, &Args(&args))
}

fn key(connection: &Connection) -> String {
    let answer = call(connection, json!({"now": NOW})).unwrap();
    answer["key"].as_str().unwrap().to_owned()
}

fn is_new_key(key: &str) -> bool {
    key.len() == 64
        && key
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
}

#[test]
fn an_empty_store_gets_a_new_key_that_is_stored() {
    let connection = store();
    let created = key(&connection);
    assert!(is_new_key(&created));
    assert_eq!(
        stored(&connection),
        Some((json!({"key": created}), NOW.to_owned()))
    );
}

#[test]
fn a_stored_key_is_returned_and_left_unchanged() {
    let connection = store();
    let existing = "k".repeat(32);
    put(&connection, &json!({"key": existing}).to_string());
    assert_eq!(key(&connection), existing);
    assert_eq!(
        stored(&connection),
        Some((json!({"key": existing}), BEFORE.to_owned()))
    );
}

#[test]
fn the_second_call_reuses_the_first_key() {
    let connection = store();
    let first = key(&connection);
    assert_eq!(key(&connection), first);
}

#[test]
fn a_short_missing_or_mistyped_key_is_replaced() {
    for payload in [
        json!({"key": "k".repeat(31)}).to_string(),
        json!({"other": "k".repeat(40)}).to_string(),
        json!({"key": 12345}).to_string(),
        json!(["k".repeat(40)]).to_string(),
        "not json".to_owned(),
    ] {
        let connection = store();
        put(&connection, &payload);
        let created = key(&connection);
        assert!(is_new_key(&created), "{payload}");
        assert_eq!(
            stored(&connection),
            Some((json!({"key": created}), NOW.to_owned())),
            "{payload}"
        );
    }
}

#[test]
fn the_length_is_counted_in_characters() {
    let connection = store();
    let existing = "é".repeat(32);
    put(&connection, &json!({"key": existing}).to_string());
    assert_eq!(key(&connection), existing);
}

#[test]
fn the_time_is_required_and_the_method_is_a_write() {
    let connection = store();
    assert!(call(&connection, json!({})).is_err());
    assert_eq!(stored(&connection), None);
    assert!(matches!(
        method_kind("fleet_posture_hash_key"),
        Some(Kind::Write)
    ));
}
