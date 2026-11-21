//! The exact Cloud Review consent rows: the capability and revocation read,
//! the compare-and-swap replace and the claimed-receipt lookup.

use rusqlite::Connection;
use serde_json::json;

use super::*;

const NOW: &str = "2026-09-28T00:10:00+00:00";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (
               state_key text primary key, payload_json text not null,
               updated_at text not null);
             create table guard_events (
               event_id integer primary key, event_name text not null,
               payload_json text not null, occurred_at text not null);
             create table guard_exact_cloud_review_receipts (
               receipt_id text primary key);",
        )
        .unwrap();
    connection
}

fn put(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload, NOW],
        )
        .unwrap();
}

fn stored(connection: &Connection, key: &str) -> Option<(Value, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
}

fn events(connection: &Connection) -> Vec<(String, Value)> {
    let mut statement = connection
        .prepare("select event_name, payload_json from guard_events order by event_id")
        .unwrap();
    statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .map(|row| {
            let (name, payload) = row.unwrap();
            (name, serde_json::from_str(&payload).unwrap())
        })
        .collect()
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    dispatch(connection, method, &Args(&args))
}

fn refused(result: StoreResult<Value>, code: &str) {
    match result {
        Err(StoreError::Value(found)) => assert_eq!(found, code),
        other => panic!("expected {code}, got {other:?}"),
    }
}

fn replace(capability: Value, revocation: Value) -> Value {
    json!({
        "capability": capability,
        "revocation": revocation,
        "now": NOW,
        "event_name": "cloud_review.exact_capability_issued",
        "event_payload": {"operation": "review"},
    })
}

#[test]
fn every_method_is_handled() {
    for method in [
        "exact_cloud_review_state",
        "replace_exact_cloud_review_state",
        "has_exact_cloud_review_receipt",
    ] {
        assert!(handles(method), "{method}");
    }
    assert!(!handles("apply_signed_remote_exact_result"));
}

#[test]
fn the_state_reads_both_rows_as_stored() {
    let connection = store();
    assert_eq!(
        call(&connection, "exact_cloud_review_state", json!({})).unwrap(),
        json!({"capability": null, "revocation": null})
    );
    put(&connection, CAPABILITY_KEY, r#"{"nonce":"n1"}"#);
    put(&connection, REVOCATION_KEY, "\"revoked\"");
    assert_eq!(
        call(&connection, "exact_cloud_review_state", json!({})).unwrap(),
        json!({"capability": {"nonce": "n1"}, "revocation": "revoked"})
    );
    put(&connection, CAPABILITY_KEY, "not json");
    assert_eq!(
        call(&connection, "exact_cloud_review_state", json!({}))
            .unwrap()
            .get("capability"),
        Some(&Value::Null)
    );
}

#[test]
fn replace_writes_both_rows_and_the_event() {
    let connection = store();
    put(&connection, REVOCATION_KEY, r#"{"revokedAt":"earlier"}"#);
    let answer = call(
        &connection,
        "replace_exact_cloud_review_state",
        replace(json!({"nonce": "n1"}), Value::Null),
    )
    .unwrap();
    assert_eq!(answer, Value::Bool(true));
    assert_eq!(
        stored(&connection, CAPABILITY_KEY),
        Some((json!({"nonce": "n1"}), NOW.to_owned()))
    );
    assert_eq!(stored(&connection, REVOCATION_KEY), None);
    assert_eq!(
        events(&connection),
        vec![(
            "cloud_review.exact_capability_issued".to_owned(),
            json!({"operation": "review"})
        )]
    );
}

#[test]
fn a_matching_expected_capability_is_replaced() {
    let connection = store();
    put(&connection, CAPABILITY_KEY, r#"{"nonce":"n1"}"#);
    let mut args = replace(Value::Null, json!({"revokedAt": NOW}));
    args["expected_capability"] = json!({"nonce": "n1"});
    args["require_expected_capability"] = json!(true);
    let answer = call(&connection, "replace_exact_cloud_review_state", args).unwrap();
    assert_eq!(answer, Value::Bool(true));
    assert_eq!(stored(&connection, CAPABILITY_KEY), None);
    assert_eq!(
        stored(&connection, REVOCATION_KEY).map(|(row, _)| row),
        Some(json!({"revokedAt": NOW}))
    );
}

#[test]
fn a_changed_capability_writes_nothing() {
    let connection = store();
    put(&connection, CAPABILITY_KEY, r#"{"nonce":"n2"}"#);
    let mut args = replace(Value::Null, json!({"revokedAt": NOW}));
    args["expected_capability"] = json!({"nonce": "n1"});
    args["require_expected_capability"] = json!(true);
    let answer = call(&connection, "replace_exact_cloud_review_state", args).unwrap();
    assert_eq!(answer, Value::Bool(false));
    assert_eq!(
        stored(&connection, CAPABILITY_KEY).map(|(row, _)| row),
        Some(json!({"nonce": "n2"}))
    );
    assert_eq!(stored(&connection, REVOCATION_KEY), None);
    assert!(events(&connection).is_empty());
}

#[test]
fn a_missing_expected_capability_matches_only_no_row() {
    let connection = store();
    let mut args = replace(Value::Null, json!({"revokedAt": NOW}));
    args["require_expected_capability"] = json!(true);
    let answer = call(
        &connection,
        "replace_exact_cloud_review_state",
        args.clone(),
    )
    .unwrap();
    assert_eq!(answer, Value::Bool(true));
    put(&connection, CAPABILITY_KEY, r#"{"nonce":"n1"}"#);
    let answer = call(&connection, "replace_exact_cloud_review_state", args).unwrap();
    assert_eq!(answer, Value::Bool(false));
}

#[test]
fn malformed_replacements_write_nothing() {
    let connection = store();
    let cases = [
        ("capability", json!("text"), "invalid_capability"),
        ("revocation", json!([1]), "invalid_revocation"),
        ("now", json!(""), "invalid_now"),
        ("event_name", json!(7), "invalid_event_name"),
        ("event_payload", json!("text"), "invalid_event_payload"),
    ];
    for (key, value, code) in cases {
        let mut args = replace(json!({"nonce": "n1"}), Value::Null);
        args[key] = value;
        refused(
            call(&connection, "replace_exact_cloud_review_state", args),
            code,
        );
    }
    assert_eq!(stored(&connection, CAPABILITY_KEY), None);
    assert!(events(&connection).is_empty());
}

#[test]
fn a_claimed_receipt_is_found() {
    let connection = store();
    let args = json!({"receipt_id": "receipt-1"});
    assert_eq!(
        call(&connection, "has_exact_cloud_review_receipt", args.clone()).unwrap(),
        Value::Bool(false)
    );
    connection
        .execute(
            "insert into guard_exact_cloud_review_receipts values ('receipt-1')",
            [],
        )
        .unwrap();
    assert_eq!(
        call(&connection, "has_exact_cloud_review_receipt", args).unwrap(),
        Value::Bool(true)
    );
    refused(
        call(
            &connection,
            "has_exact_cloud_review_receipt",
            json!({"receipt_id": ""}),
        ),
        "invalid_receipt_id",
    );
}
