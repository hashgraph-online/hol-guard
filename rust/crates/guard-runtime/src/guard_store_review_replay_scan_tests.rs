//! Scan cursor reads, progress rules and refusals.

use serde_json::json;

use super::super::tests::{binding, store, BEFORE, NOW};
use super::*;

fn args(extra: Value) -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("source".to_owned(), json!("default"));
    args.insert("binding".to_owned(), binding());
    if let Value::Object(extra) = extra {
        args.extend(extra);
    }
    args
}

fn put(connection: &Connection, payload: &Value) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![scan_key("default"), payload.to_string(), BEFORE],
        )
        .unwrap();
}

fn read(connection: &Connection) -> Value {
    read_method(connection, &Args(&args(json!({})))).unwrap()
}

fn record(connection: &Connection, mut extra: Value) -> Value {
    extra["changed_at"] = json!(NOW);
    record_method(connection, &Args(&args(extra))).unwrap()
}

#[test]
fn key_is_scan_marker_and_source() {
    assert_eq!(
        scan_key("default"),
        "guard_cloud_review_native_workspace_review_replay:scan:default"
    );
}

#[test]
fn no_row_starts_a_new_snapshot() {
    let connection = store();
    assert_eq!(
        read(&connection),
        json!({"cursor": null, "through_request_id": null})
    );
}

#[test]
fn stored_bounds_for_the_binding_are_returned() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": binding(), "cursor": "request-02", "through_request_id": "request-09"}),
    );
    assert_eq!(
        read(&connection),
        json!({"cursor": "request-02", "through_request_id": "request-09"})
    );
}

#[test]
fn another_binding_starts_a_new_snapshot() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": {"workspace_id": "other"}, "cursor": "request-02", "through_request_id": "request-09"}),
    );
    assert_eq!(read(&connection)["through_request_id"], Value::Null);
}

#[test]
fn legacy_row_without_upper_bound_restarts() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": binding(), "cursor": "request-99"}),
    );
    assert_eq!(
        read(&connection),
        json!({"cursor": null, "through_request_id": null})
    );
}

#[test]
fn empty_cursor_reads_as_none() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": binding(), "cursor": "", "through_request_id": "request-09"}),
    );
    assert_eq!(
        read(&connection),
        json!({"cursor": null, "through_request_id": "request-09"})
    );
}

#[test]
fn full_batch_below_the_bound_advances() {
    let connection = store();
    let state = record(
        &connection,
        json!({"request_ids": ["request-01", "request-02"], "limit": 2, "through_request_id": "request-09"}),
    );
    assert_eq!(state["cursor"], json!("request-02"));
    assert_eq!(state["through_request_id"], json!("request-09"));
    assert_eq!(state["schema"], json!(SCHEMA));
    assert_eq!(
        read(&connection),
        json!({"cursor": "request-02", "through_request_id": "request-09"})
    );
}

#[test]
fn short_batch_finishes_the_snapshot() {
    let connection = store();
    let state = record(
        &connection,
        json!({"request_ids": ["request-08"], "limit": 2, "through_request_id": "request-09"}),
    );
    assert_eq!(state["cursor"], Value::Null);
    assert_eq!(state["through_request_id"], Value::Null);
}

#[test]
fn batch_reaching_the_bound_finishes_the_snapshot() {
    let connection = store();
    let state = record(
        &connection,
        json!({"request_ids": ["request-08", "request-09"], "limit": 2, "through_request_id": "request-09"}),
    );
    assert_eq!(state["cursor"], Value::Null);
}

#[test]
fn empty_batch_resets_progress() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": binding(), "cursor": "request-02", "through_request_id": "request-09"}),
    );
    let state = record(&connection, json!({"request_ids": [], "limit": 2}));
    assert_eq!(state["cursor"], Value::Null);
    assert_eq!(
        read(&connection),
        json!({"cursor": null, "through_request_id": null})
    );
}

#[test]
fn bad_inputs_are_refused_without_a_write() {
    let connection = store();
    let refused = |extra: Value, overrides: Value| {
        let mut args = args(extra);
        if let Value::Object(overrides) = overrides {
            args.extend(overrides);
        }
        args.insert("changed_at".to_owned(), json!(NOW));
        record_method(&connection, &Args(&args)).is_err()
    };
    let batch = || json!({"request_ids": ["request-01"], "through_request_id": "request-09"});
    assert!(refused(batch(), json!({"limit": 0})));
    assert!(refused(batch(), json!({"limit": 2, "source": ""})));
    assert!(refused(batch(), json!({"limit": 2, "binding": {}})));
    assert!(refused(batch(), json!({"limit": 2, "binding": {"a": 1}})));
    assert!(refused(json!({"request_ids": [1], "limit": 2}), json!({})));
    assert!(read_method(&connection, &Args(&args(json!({"source": ""})))).is_err());
    assert_eq!(
        read(&connection),
        json!({"cursor": null, "through_request_id": null})
    );
}
