//! The Cloud Review settings rows: the sync view, the reconnect rule and the
//! recovery row.

use rusqlite::Connection;
use serde_json::json;

use super::*;

const NOW: &str = "2026-09-28T00:10:00+00:00";
const SOURCE_KEY: &str = "guard_cloud_review_sync_state:staging";

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

fn stored(connection: &Connection, key: &str) -> Option<Value> {
    connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            [key],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .map(|payload| serde_json::from_str(&payload).unwrap())
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    dispatch(connection, method, &Args(&args))
}

fn state(connection: &Connection, source: &str, binding: &Value) -> Value {
    call(
        connection,
        "cloud_review_settings_state",
        json!({"source": source, "binding": binding}),
    )
    .unwrap()
}

fn binding() -> Value {
    json!({"workspace_id": "ws-1", "oauth_source": "default"})
}

fn reconnect(sync: &Value) -> bool {
    let connection = store();
    put(&connection, SYNC_KEY, sync);
    state(&connection, "default", &Value::Null)["sync_reconnect_required"] == json!(true)
}

#[test]
fn an_empty_store_reads_an_idle_view() {
    let connection = store();
    assert_eq!(
        state(&connection, "default", &binding()),
        json!({"sync": {}, "sync_reconnect_required": false, "recovery_error": null})
    );
}

#[test]
fn the_sync_row_is_read_for_the_store_source() {
    let connection = store();
    put(&connection, SYNC_KEY, &json!({"state": "idle"}));
    put(&connection, SOURCE_KEY, &json!({"state": "syncing"}));
    assert_eq!(
        state(&connection, "default", &Value::Null)["sync"],
        json!({"state": "idle"})
    );
    assert_eq!(
        state(&connection, "staging", &Value::Null)["sync"],
        json!({"state": "syncing"})
    );
    put(&connection, SYNC_KEY, &json!(["not", "an", "object"]));
    assert_eq!(
        state(&connection, "default", &Value::Null)["sync"],
        json!({})
    );
}

#[test]
fn a_recorded_code_decides_whether_sign_in_is_needed() {
    for code in AUTH_CODES {
        assert!(reconnect(&json!({"state": "error", ERROR_CODE: code})));
    }
    assert!(!reconnect(
        &json!({"state": "error", ERROR_CODE: "cloud_unreachable"})
    ));
    assert!(!reconnect(
        &json!({"state": "idle", ERROR_CODE: "cloud_auth_expired"})
    ));
    // A cleared code means sign-in worked, whatever the old message says.
    assert!(!reconnect(
        &json!({"state": "error", ERROR_CODE: null, "last_error": "HTTP Error 401: Unauthorized"})
    ));
}

#[test]
fn rows_without_a_code_fall_back_to_the_message() {
    for prefix in AUTH_ERROR_PREFIXES {
        let error = format!("{prefix} Sign in again.");
        assert!(reconnect(&json!({"state": "error", "last_error": error})));
    }
    assert!(!reconnect(
        &json!({"state": "error", "last_error": "Guard Cloud timed out."})
    ));
    assert!(!reconnect(&json!({"state": "error", "last_error": 401})));
    assert!(!reconnect(&json!({"state": "error"})));
}

#[test]
fn the_recovery_error_counts_only_for_the_same_binding() {
    let connection = store();
    call(
        &connection,
        "record_cloud_review_recovery",
        json!({"binding": binding(), "error": "worker_refresh_failed", "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        stored(&connection, RECOVERY_KEY),
        Some(json!({"binding": binding(), "error": "worker_refresh_failed"}))
    );
    assert_eq!(
        state(&connection, "default", &binding())["recovery_error"],
        json!("worker_refresh_failed")
    );
    let other = json!({"workspace_id": "ws-2", "oauth_source": "default"});
    assert_eq!(
        state(&connection, "default", &other)["recovery_error"],
        Value::Null
    );
    assert_eq!(
        state(&connection, "default", &Value::Null)["recovery_error"],
        Value::Null
    );

    call(
        &connection,
        "record_cloud_review_recovery",
        json!({"binding": null, "error": null, "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        stored(&connection, RECOVERY_KEY),
        Some(json!({"binding": null, "error": null}))
    );
    assert_eq!(
        state(&connection, "default", &Value::Null)["recovery_error"],
        Value::Null
    );
}

#[test]
fn malformed_inputs_are_refused_without_a_write() {
    let connection = store();
    for (method, args, code) in [
        (
            "record_cloud_review_recovery",
            json!({"binding": "ws-1", "error": null, "now": NOW}),
            "invalid_binding",
        ),
        (
            "record_cloud_review_recovery",
            json!({"binding": binding(), "error": "", "now": NOW}),
            "invalid_error",
        ),
        (
            "record_cloud_review_recovery",
            json!({"binding": binding(), "error": 7, "now": NOW}),
            "invalid_error",
        ),
        (
            "cloud_review_settings_state",
            json!({"source": "", "binding": null}),
            "invalid_source",
        ),
        (
            "cloud_review_settings_state",
            json!({"source": "default", "binding": []}),
            "invalid_binding",
        ),
    ] {
        match call(&connection, method, args) {
            Err(StoreError::Value(found)) => assert_eq!(found, code),
            other => panic!("expected {code}, got {other:?}"),
        }
    }
    assert_eq!(stored(&connection, RECOVERY_KEY), None);
}
