//! The receipts sync delivery rows: the workspace assessment delivery and the
//! policy bundle failed acknowledgement.

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
               updated_at text not null);",
        )
        .unwrap();
    connection
}

fn put(connection: &Connection, key: &str, payload: &Value) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload.to_string(), NOW],
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

#[test]
fn every_method_is_handled() {
    for method in [
        "workspace_assessment_delivery",
        "commit_workspace_assessment_sent",
        "cached_policy_bundle",
        "record_policy_bundle_failure_ack",
    ] {
        assert!(handles(method), "{method}");
    }
    assert!(!handles("cloud_review_settings_state"));
}

#[test]
fn an_empty_store_reads_no_rows() {
    let connection = store();
    for method in ["workspace_assessment_delivery", "cached_policy_bundle"] {
        assert_eq!(call(&connection, method, json!({})).unwrap(), Value::Null);
    }
}

#[test]
fn only_an_object_row_is_read() {
    let connection = store();
    put(&connection, DELIVERY_KEY, &json!(["not", "an", "object"]));
    put(&connection, BUNDLE_KEY, &json!({}));
    assert_eq!(
        call(&connection, "workspace_assessment_delivery", json!({})).unwrap(),
        Value::Null
    );
    assert_eq!(
        call(&connection, "cached_policy_bundle", json!({})).unwrap(),
        json!({})
    );
    let bundle = json!({"bundleHash": "sha256:abc", "bundleVersion": "7"});
    put(&connection, BUNDLE_KEY, &bundle);
    assert_eq!(
        call(&connection, "cached_policy_bundle", json!({})).unwrap(),
        bundle
    );
}

#[test]
fn a_committed_delivery_is_read_back() {
    let connection = store();
    call(
        &connection,
        "commit_workspace_assessment_sent",
        json!({"digest": "sha256:summary", "sent_at": NOW}),
    )
    .unwrap();
    assert_eq!(
        stored(&connection, DELIVERY_KEY),
        Some((
            json!({"digest": "sha256:summary", "sent_at": NOW}),
            NOW.to_owned()
        ))
    );
    assert_eq!(
        call(&connection, "workspace_assessment_delivery", json!({})).unwrap(),
        json!({"digest": "sha256:summary", "sent_at": NOW})
    );
}

#[test]
fn a_malformed_delivery_is_refused_without_a_write() {
    let connection = store();
    for (args, code) in [
        (json!({"sent_at": NOW}), "invalid_digest"),
        (json!({"digest": "", "sent_at": NOW}), "invalid_digest"),
        (json!({"digest": 7, "sent_at": NOW}), "invalid_digest"),
        (json!({"digest": "sha256:summary"}), "invalid_sent_at"),
        (
            json!({"digest": "sha256:summary", "sent_at": ""}),
            "invalid_sent_at",
        ),
    ] {
        refused(
            call(&connection, "commit_workspace_assessment_sent", args),
            code,
        );
    }
    assert_eq!(stored(&connection, DELIVERY_KEY), None);
}

#[test]
fn a_failed_acknowledgement_is_recorded() {
    let connection = store();
    let ack = json!({"status": "failed", "deviceId": "device-1", "bundleHash": "sha256:abc"});
    call(
        &connection,
        "record_policy_bundle_failure_ack",
        json!({"acknowledgement": ack, "now": NOW}),
    )
    .unwrap();
    assert_eq!(stored(&connection, ACK_KEY), Some((ack, NOW.to_owned())));
}

#[test]
fn only_a_failed_acknowledgement_is_recorded() {
    let connection = store();
    for (args, code) in [
        (
            json!({"acknowledgement": {"status": "applied"}, "now": NOW}),
            "invalid_acknowledgement",
        ),
        (
            json!({"acknowledgement": {"deviceId": "device-1"}, "now": NOW}),
            "invalid_acknowledgement",
        ),
        (
            json!({"acknowledgement": [{"status": "failed"}], "now": NOW}),
            "invalid_acknowledgement",
        ),
        (json!({"now": NOW}), "invalid_acknowledgement"),
        (
            json!({"acknowledgement": {"status": "failed"}}),
            "invalid_now",
        ),
    ] {
        refused(
            call(&connection, "record_policy_bundle_failure_ack", args),
            code,
        );
    }
    assert_eq!(stored(&connection, ACK_KEY), None);
}
