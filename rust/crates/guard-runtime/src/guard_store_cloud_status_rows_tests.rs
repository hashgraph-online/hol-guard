//! The Cloud status snapshot: row shapes, the sign-in-expired rule, the last
//! sync time and the latest Guard Cloud sync.

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

fn snapshot(connection: &Connection) -> Value {
    let args = Map::new();
    dispatch(connection, "cloud_status_rows", &Args(&args)).unwrap()
}

#[test]
fn an_empty_store_reads_every_row_as_empty() {
    let answer = snapshot(&store());
    for key in ROWS {
        assert_eq!(answer["rows"][key], json!({}), "{key}");
    }
    assert_eq!(answer["cloud_auth_expired"], json!(false));
    assert_eq!(answer["last_sync_at"], Value::Null);
    assert_eq!(answer["latest_cloud_sync"], json!({}));
}

#[test]
fn a_row_that_is_not_an_object_reads_as_empty() {
    let connection = store();
    put(&connection, "sync_summary", &json!(["synced"]));
    put(&connection, "alert_preferences", &json!("on"));
    let answer = snapshot(&connection);
    assert_eq!(answer["rows"]["sync_summary"], json!({}));
    assert_eq!(answer["rows"]["alert_preferences"], json!({}));
}

#[test]
fn stored_rows_come_back_unchanged() {
    let connection = store();
    let preferences = json!({"watchlistEnabled": true, "teamAlertsEnabled": false});
    put(&connection, "alert_preferences", &preferences);
    put(
        &connection,
        "runtime_session_summary",
        &json!({"runtime_device_id": "device-1"}),
    );
    let answer = snapshot(&connection);
    assert_eq!(answer["rows"]["alert_preferences"], preferences);
    assert_eq!(
        answer["rows"]["runtime_session_summary"],
        json!({"runtime_device_id": "device-1"})
    );
}

#[test]
fn each_sign_in_row_can_report_an_expired_sign_in() {
    for (key, field) in [
        ("policy_bundle_last_error", "reason"),
        ("headless_app_sync_summary", "status"),
        ("guard_cloud_review_sync_state", "state"),
    ] {
        let connection = store();
        put(&connection, key, &json!({ field: "auth_expired" }));
        assert_eq!(
            snapshot(&connection)["cloud_auth_expired"],
            json!(true),
            "{key}"
        );
    }
}

#[test]
fn other_values_and_other_fields_do_not_report_an_expired_sign_in() {
    let connection = store();
    put(
        &connection,
        "policy_bundle_last_error",
        &json!({"reason": "network"}),
    );
    put(
        &connection,
        "headless_app_sync_summary",
        &json!({"state": "auth_expired"}),
    );
    put(
        &connection,
        "guard_cloud_review_sync_state",
        &json!({"status": "auth_expired"}),
    );
    put(
        &connection,
        "sync_summary",
        &json!({"status": "auth_expired"}),
    );
    assert_eq!(snapshot(&connection)["cloud_auth_expired"], json!(false));
}

#[test]
fn the_last_sync_time_prefers_the_summary_then_the_cursor() {
    let connection = store();
    put(
        &connection,
        "receipt_sync_cursor",
        &json!({"synced_at": "cursor-time"}),
    );
    assert_eq!(snapshot(&connection)["last_sync_at"], json!("cursor-time"));
    put(&connection, "sync_summary", &json!({"synced_at": 7}));
    assert_eq!(snapshot(&connection)["last_sync_at"], json!("cursor-time"));
    put(
        &connection,
        "sync_summary",
        &json!({"synced_at": "summary-time"}),
    );
    assert_eq!(snapshot(&connection)["last_sync_at"], json!("summary-time"));
}

#[test]
fn the_latest_cloud_sync_prefers_the_headless_app_summary() {
    let connection = store();
    put(
        &connection,
        "sync_summary",
        &json!({"synced_at": "receipts"}),
    );
    assert_eq!(
        snapshot(&connection)["latest_cloud_sync"],
        json!({"synced_at": "receipts"})
    );
    put(&connection, "headless_app_sync_summary", &json!({}));
    assert_eq!(snapshot(&connection)["latest_cloud_sync"], json!({}));
    put(
        &connection,
        "headless_app_sync_summary",
        &json!({"status": "ok"}),
    );
    assert_eq!(
        snapshot(&connection)["latest_cloud_sync"],
        json!({"status": "ok"})
    );
}

#[test]
fn only_the_snapshot_method_is_handled() {
    assert!(handles("cloud_status_rows"));
    assert!(!handles("cloud_review_settings_state"));
    let args = Map::new();
    assert!(dispatch(&store(), "cloud_status_row", &Args(&args)).is_err());
}
