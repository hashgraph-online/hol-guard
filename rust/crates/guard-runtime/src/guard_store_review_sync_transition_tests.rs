//! Each step merges its own fields into the sync state row and keeps the rest.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const KEY: &str = "guard_cloud_review_sync_state";
const SOURCE_KEY: &str = "guard_cloud_review_sync_state:desktop";
const NOW: &str = "2026-09-27T12:00:00+00:00";
const AT: &str = "2026-09-27T11:59:59+00:00";
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

fn row(connection: &Connection, key: &str) -> Option<(Value, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
}

fn run(connection: &Connection, args: Value) -> StoreResult<Value> {
    let Value::Object(mut args) = args else {
        unreachable!()
    };
    args.entry("now").or_insert(json!(NOW));
    args.entry("at").or_insert(json!(AT));
    method(connection, &Args(&args))
}

fn merged(answer: StoreResult<Value>) -> Value {
    answer.unwrap()["state"].clone()
}

fn error_code(result: StoreResult<Value>) -> String {
    match result {
        Err(StoreError::Value(code)) => code,
        other => panic!("expected a value error, got {other:?}"),
    }
}

const SYNCED: &str = r#"{"state":"error","last_error":"old","last_error_code":"cloud_delivery_error",
    "batch_binding_key":"b","batch_events":50,"rejection_counts":{"7":2}}"#;

#[test]
fn a_started_run_clears_the_error_and_keeps_the_batch_limits() {
    let connection = store();
    put(&connection, KEY, SYNCED);
    let state = merged(run(
        &connection,
        json!({"state_key": KEY, "transition": "started"}),
    ));
    let expected = json!({"state": "syncing", "last_error": null, "last_error_code": null,
        "last_sync_attempt_at": AT, "batch_binding_key": "b", "batch_events": 50,
        "rejection_counts": {"7": 2}});
    assert_eq!(state, expected);
    assert_eq!(row(&connection, KEY), Some((expected, NOW.to_owned())));
}

#[test]
fn a_source_key_is_its_own_row_and_an_unreadable_row_starts_empty() {
    let connection = store();
    put(&connection, SOURCE_KEY, "[1]");
    let state = merged(run(
        &connection,
        json!({"state_key": SOURCE_KEY, "transition": "batch_limits", "binding_key": "k",
            "limits": {"events": 25, "bytes": 4096, "event_cap": 100}}),
    ));
    assert_eq!(
        state,
        json!({"batch_binding_key": "k", "batch_events": 25, "batch_max_bytes": 4096,
            "batch_event_cap": 100})
    );
    assert_eq!(row(&connection, KEY), None);
}

#[test]
fn a_completed_run_records_success_delivery_and_the_outbox() {
    let connection = store();
    put(&connection, KEY, SYNCED);
    let binding = json!({"workspace_id": "w", "machine_id": "m"});
    let state = merged(run(
        &connection,
        json!({"state_key": KEY, "transition": "completed",
            "counts": {"accepted": 3, "delivered": 2, "rejected": 1},
            "outbox": {"depth": 4, "oldest_changed_at": BEFORE},
            "delivery_binding": binding, "error": null}),
    ));
    assert_eq!(state["state"], json!("idle"));
    assert_eq!(state["last_success_at"], json!(AT));
    assert_eq!(state["last_delivery_at"], json!(AT));
    assert_eq!(state["last_delivery_binding"], binding);
    assert_eq!(state["synced_count"], json!(3));
    assert_eq!(state["rejected_count"], json!(1));
    assert_eq!(state["last_error"], Value::Null);
    assert_eq!(state["outbox_depth"], json!(4));
    assert_eq!(state["outbox_oldest_changed_at"], json!(BEFORE));
    assert_eq!(state["last_error_code"], json!("cloud_delivery_error"));
}

#[test]
fn a_completed_run_with_an_error_and_waiting_events_stays_in_error() {
    let connection = store();
    let args = |error: &str, depth: i64| {
        json!({"state_key": KEY, "transition": "completed",
            "counts": {"accepted": 0, "delivered": 0, "rejected": 0},
            "outbox": {"depth": depth, "oldest_changed_at": null}, "error": error})
    };
    let state = merged(run(&connection, args("HTTP 503", 2)));
    assert_eq!(state["state"], json!("error"));
    assert_eq!(state["last_error"], json!("HTTP 503"));
    assert!(state.get("last_success_at").is_none());
    assert!(state.get("last_delivery_at").is_none());
    // An empty outbox is a success even with an error, and an empty error is none.
    let state = merged(run(&connection, args("HTTP 503", 0)));
    assert_eq!(state["state"], json!("idle"));
    assert_eq!(state["last_success_at"], json!(AT));
    let state = merged(run(&connection, args("", 2)));
    assert_eq!(state["state"], json!("idle"));
}

#[test]
fn a_failure_sets_its_code_or_keeps_the_stored_one() {
    let connection = store();
    put(
        &connection,
        KEY,
        r#"{"last_error_code":"cloud_auth_expired","synced_count":5}"#,
    );
    let failed = |extra: Value| {
        let mut args = json!({"state_key": KEY, "transition": "failed", "error": "boom"});
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        merged(run(&connection, args))
    };
    // No code: the stored code stays.
    let state = failed(json!({}));
    assert_eq!(state["state"], json!("error"));
    assert_eq!(state["last_error"], json!("boom"));
    assert_eq!(state["last_error_at"], json!(AT));
    assert_eq!(state["last_error_code"], json!("cloud_auth_expired"));
    assert_eq!(state["synced_count"], json!(5));
    // A transient failure keeps a code that says sign-in is still required.
    let state = failed(json!({"error_code": "cloud_delivery_error", "keep_auth_code": true}));
    assert_eq!(state["last_error_code"], json!("cloud_auth_expired"));
    // An explicit code replaces it.
    let state = failed(json!({"error_code": "cloud_delivery_error"}));
    assert_eq!(state["last_error_code"], json!("cloud_delivery_error"));
    // Once the stored code is not an auth code, a transient failure records its own.
    let state = failed(json!({"error_code": "cloud_connect_required", "keep_auth_code": true}));
    assert_eq!(state["last_error_code"], json!("cloud_connect_required"));
}

#[test]
fn a_bad_step_or_key_is_refused_and_writes_nothing() {
    let connection = store();
    let cases = [
        (
            json!({"state_key": "other", "transition": "started"}),
            "invalid_state_key",
        ),
        (
            json!({"state_key": "guard_cloud_review_sync_state:", "transition": "started"}),
            "invalid_state_key",
        ),
        (
            json!({"state_key": KEY, "transition": "bogus"}),
            "invalid_transition",
        ),
        (
            json!({"state_key": KEY, "transition": "failed"}),
            "invalid_error",
        ),
        (
            json!({"state_key": KEY, "transition": "failed", "error": "e", "keep_auth_code": true}),
            "invalid_error_code",
        ),
        (
            json!({"state_key": KEY, "transition": "batch_limits", "binding_key": "k", "limits": {"events": 1}}),
            "invalid_limits",
        ),
        (
            json!({"state_key": KEY, "transition": "completed", "counts": {"accepted": 1}, "outbox": {"depth": 0}}),
            "invalid_counts",
        ),
        (
            json!({"state_key": KEY, "transition": "completed",
            "counts": {"accepted": 0, "delivered": 0, "rejected": 0},
            "outbox": {"depth": 0, "oldest_changed_at": 3}}),
            "invalid_outbox",
        ),
    ];
    for (args, code) in cases {
        assert_eq!(error_code(run(&connection, args)), code);
    }
    assert_eq!(row(&connection, KEY), None);
}
