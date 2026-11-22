//! The AI-BOM sync rows and the timing rules that read them.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::*;

const NOW: &str = "2026-11-21T12:00:00Z";

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

fn put(connection: &Connection, key: &str, payload: Value) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload.to_string(), NOW],
        )
        .unwrap();
}

fn row(connection: &Connection, key: &str) -> Option<Value> {
    read_payload(connection, key).unwrap()
}

fn schedule(connection: &Connection, interval: i64) -> Value {
    call(
        connection,
        "aibom_sync_schedule",
        json!({ "generated_at": NOW, "min_interval_seconds": interval }),
    )
    .unwrap()
}

#[test]
fn sync_is_due_without_a_successful_sync() {
    let connection = store();
    assert_eq!(
        schedule(&connection, 600),
        json!({ "due": true, "last_sync_at": null })
    );
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": false, "synced_at": NOW }),
    );
    assert_eq!(schedule(&connection, 600)["due"], json!(true));
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": true, "synced_at": "  " }),
    );
    assert_eq!(schedule(&connection, 600)["due"], json!(true));
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": true, "synced_at": "not a time" }),
    );
    assert_eq!(schedule(&connection, 600)["due"], json!(true));
    put(&connection, SYNC_SUMMARY_KEY, json!([1, 2]));
    assert_eq!(schedule(&connection, 600)["due"], json!(true));
}

#[test]
fn sync_waits_for_the_interval() {
    let connection = store();
    let recent = "2026-11-21T11:55:00+00:00";
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": true, "synced_at": recent, "snapshots": 3 }),
    );
    assert_eq!(
        schedule(&connection, 600),
        json!({ "due": false, "last_sync_at": recent })
    );
    assert_eq!(schedule(&connection, 300)["due"], json!(true));
    // A naive time reads as UTC.
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": true, "synced_at": "2026-11-21T11:50:00" }),
    );
    assert_eq!(schedule(&connection, 600)["due"], json!(true));
}

#[test]
fn empty_sync_retries_after_two_minutes() {
    let connection = store();
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": true, "synced_at": "2026-11-21T11:57:00Z", "snapshots": 0 }),
    );
    assert_eq!(schedule(&connection, 3600)["due"], json!(true));
    put(
        &connection,
        SYNC_SUMMARY_KEY,
        json!({ "synced": true, "synced_at": "2026-11-21T11:59:00Z", "snapshots": 0 }),
    );
    assert_eq!(schedule(&connection, 3600)["due"], json!(false));
    assert_eq!(schedule(&connection, 30)["due"], json!(true));
}

#[test]
fn summary_round_trip_and_refusals() {
    let connection = store();
    assert_eq!(
        call(&connection, "aibom_sync_summary", json!({})).unwrap(),
        Value::Null
    );
    let summary = json!({ "synced": true, "synced_at": NOW, "snapshots": 2 });
    call(
        &connection,
        "record_aibom_sync_summary",
        json!({ "payload": summary, "now": NOW }),
    )
    .unwrap();
    assert_eq!(
        call(&connection, "aibom_sync_summary", json!({})).unwrap(),
        summary
    );
    for args in [
        json!({ "payload": [1], "now": NOW }),
        json!({ "payload": {}, "now": "" }),
        json!({ "now": NOW }),
    ] {
        let fresh = store();
        assert!(call(&fresh, "record_aibom_sync_summary", args).is_err());
        assert_eq!(row(&fresh, SYNC_SUMMARY_KEY), None);
    }
}

#[test]
fn guard_events_backoff_holds_for_five_minutes() {
    let connection = store();
    let active = |at: &str| {
        call(
            &connection,
            "aibom_guard_events_backoff_active",
            json!({ "now": at }),
        )
        .unwrap()
    };
    assert_eq!(active(NOW), json!(false));
    call(
        &connection,
        "record_aibom_guard_events_unavailable",
        json!({ "events": 7, "accepted": 3, "now": NOW }),
    )
    .unwrap();
    assert_eq!(
        row(&connection, BACKOFF_KEY),
        Some(json!({
            "synced_at": NOW, "events": 7, "accepted": 3, "skipped": 7,
            "sync_skipped": true, "sync_reason": ENDPOINT_UNAVAILABLE,
        }))
    );
    assert_eq!(active("2026-11-21T12:04:59Z"), json!(true));
    assert_eq!(active("2026-11-21T12:05:00Z"), json!(false));
    put(
        &connection,
        BACKOFF_KEY,
        json!({ "synced_at": NOW, "sync_reason": "other" }),
    );
    assert_eq!(active(NOW), json!(false));
    put(
        &connection,
        BACKOFF_KEY,
        json!({ "synced_at": "bad", "sync_reason": ENDPOINT_UNAVAILABLE }),
    );
    assert_eq!(active(NOW), json!(false));
}

#[test]
fn user_inventory_recency_reads_the_last_collection() {
    let connection = store();
    let recency = |interval: i64| {
        call(
            &connection,
            "aibom_user_inventory_recency",
            json!({ "generated_at": NOW, "min_interval_seconds": interval }),
        )
        .unwrap()
    };
    assert_eq!(
        recency(600),
        json!({ "recent": false, "collected_at": null })
    );
    let summary = json!({ "collected": true, "collected_at": "2026-11-21T11:58:00Z", "items": 4 });
    call(
        &connection,
        "record_aibom_user_inventory",
        json!({ "payload": summary, "now": NOW }),
    )
    .unwrap();
    assert_eq!(
        recency(600),
        json!({ "recent": true, "collected_at": "2026-11-21T11:58:00Z" })
    );
    assert_eq!(recency(60)["recent"], json!(false));
    // A collection stamped after `generated_at` is not recent.
    put(
        &connection,
        USER_INVENTORY_KEY,
        json!({ "collected_at": "2026-11-21T12:01:00Z" }),
    );
    assert_eq!(recency(600)["recent"], json!(false));
}

#[test]
fn inventory_context_is_bound_to_the_workspace() {
    let connection = store();
    let context = |workspace: Value| {
        call(
            &connection,
            "aibom_inventory_context",
            json!({ "workspace_id": workspace }),
        )
        .unwrap()
    };
    assert_eq!(context(json!("ws-1")), json!({}));
    let stored = json!({ "home_dir": "/home/a", "workspace_dir": "/w", "workspace_id": "ws-1" });
    call(
        &connection,
        "record_aibom_inventory_context",
        json!({ "payload": stored, "now": NOW }),
    )
    .unwrap();
    assert_eq!(context(json!("ws-1")), stored);
    assert_eq!(context(json!("ws-2")), json!({}));
    assert_eq!(context(Value::Null), json!({}));
}

#[test]
fn daemon_record_is_written() {
    let connection = store();
    let record = json!({ "status": "synced", "refreshed_at": NOW });
    call(
        &connection,
        "record_aibom_inventory_daemon",
        json!({ "payload": record, "now": NOW }),
    )
    .unwrap();
    assert_eq!(row(&connection, DAEMON_KEY), Some(record));
}
