//! Probe timing, backoff and authority rules of the replay marker.

use serde_json::json;

use super::*;

pub(super) const NOW: &str = "2026-09-27T12:00:00+00:00";
pub(super) const BEFORE: &str = "2026-09-27T11:00:00+00:00";

pub(super) fn store() -> Connection {
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

pub(super) fn binding() -> Value {
    json!({"workspace_id": "workspace-1", "machine_installation_id": "install-1"})
}

pub(super) fn args(extra: Value) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("source".to_owned(), json!("default"));
    args.insert("request_id".to_owned(), json!("request-1"));
    args.insert("binding".to_owned(), binding());
    args.insert("now".to_owned(), json!(NOW));
    if let Value::Object(extra) = extra {
        args.extend(extra);
    }
    args
}

pub(super) fn put(connection: &Connection, payload: &Value) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![
                marker_key("default", "request-1"),
                payload.to_string(),
                BEFORE
            ],
        )
        .unwrap();
}

fn due(connection: &Connection, extra: Value) -> bool {
    let args = args(extra);
    read_method(connection, &Args(&args)).unwrap()["due"] == json!(true)
}

#[test]
fn key_is_source_and_request_digest() {
    let key = marker_key("default", "request-1");
    assert!(key.starts_with("guard_cloud_review_native_workspace_review_replay:default:request:"));
    assert_eq!(key.rsplit(':').next().map(str::len), Some(64));
}

#[test]
fn probe_is_due_without_marker_or_with_another_binding() {
    let connection = store();
    assert!(due(&connection, json!({})));
    put(
        &connection,
        &json!({"binding": {"workspace_id": "other"}, "next_probe_at": "2026-09-27T13:00:00+00:00"}),
    );
    assert!(due(&connection, json!({})));
}

#[test]
fn probe_waits_for_retry_time_unless_forced() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": binding(), "next_probe_at": "2026-09-27T13:00:00+00:00"}),
    );
    assert!(!due(&connection, json!({})));
    assert!(due(&connection, json!({"force_probe": true})));
    put(
        &connection,
        &json!({"binding": binding(), "next_probe_at": NOW}),
    );
    assert!(due(&connection, json!({})));
    for unreadable in [json!("2026-09-27T13:00:00"), json!("soon"), json!(5)] {
        put(
            &connection,
            &json!({"binding": binding(), "next_probe_at": unreadable}),
        );
        assert!(due(&connection, json!({})));
    }
}

#[test]
fn read_returns_key_and_stored_marker() {
    let connection = store();
    put(&connection, &json!({"binding": binding(), "attempts": 2}));
    let args = args(json!({}));
    let read = read_method(&connection, &Args(&args)).unwrap();
    assert_eq!(read["key"], json!(marker_key("default", "request-1")));
    assert_eq!(read["marker"]["attempts"], json!(2));
}

#[test]
fn retry_and_replay_delays_are_bounded() {
    assert_eq!(
        [0, 1, 2, 3, 4, 9].map(retry_delay),
        [60, 120, 240, 480, 900, 900]
    );
    assert_eq!(
        [0, 1, 2, 3, 4, 9].map(replay_delay),
        [300, 300, 900, 3600, 21600, 21600]
    );
}

#[test]
fn request_refuses_bad_inputs() {
    for extra in [
        json!({"source": ""}),
        json!({"request_id": ""}),
        json!({"binding": {}}),
        json!({"binding": {"workspace_id": 1}}),
        json!({"now": "2026-09-27T12:00:00"}),
    ] {
        let args = args(extra);
        assert!(request(&Args(&args)).is_err());
    }
}
