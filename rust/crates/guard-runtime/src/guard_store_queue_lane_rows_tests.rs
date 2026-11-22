//! Each named lane answers whether it holds an unsent result and which lease
//! batch limit it records; an unparseable row is named, not read as empty.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const MAIN: &str = "guard_command_queue_state";
const DRAIN: &str = "guard_command_queue_state.review_drain.1";
const OTHER: &str = "guard_command_queue_state.review_drain.2";

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
            "insert or replace into sync_state values (?1, ?2, '2026-11-22T00:00:00Z')",
            rusqlite::params![key, payload],
        )
        .unwrap();
}

fn read(connection: &Connection, keys: Value) -> StoreResult<Value> {
    let mut args = Map::new();
    args.insert("state_keys".to_owned(), keys);
    dispatch(connection, "command_queue_lane_rows", &Args(&args))
}

fn lane_answer(key: &str, readable: bool, pending: bool, has_limit: bool, limit: u64) -> Value {
    json!({
        "state_key": key,
        "readable": readable,
        "pending_result": pending,
        "has_lease_batch_limit": has_limit,
        "exact_lease_batch_limit": limit,
    })
}

#[test]
fn missing_lanes_hold_nothing_and_use_a_limit_of_one() {
    let connection = store();
    assert_eq!(
        read(&connection, json!([MAIN, DRAIN])).unwrap(),
        json!({"lanes": [
            lane_answer(MAIN, true, false, false, 1),
            lane_answer(DRAIN, true, false, false, 1),
        ]})
    );
}

#[test]
fn each_lane_reports_its_own_pending_result_and_limit() {
    let connection = store();
    put(
        &connection,
        MAIN,
        r#"{"state":"idle","exact_lease_batch_limit":7}"#,
    );
    put(
        &connection,
        DRAIN,
        r#"{"state":"result_pending","pending_result":{"job":{"id":"j"},"payload":{}}}"#,
    );
    put(&connection, OTHER, r#"{"pending_result":"text"}"#);
    assert_eq!(
        read(&connection, json!([MAIN, DRAIN, OTHER])).unwrap(),
        json!({"lanes": [
            lane_answer(MAIN, true, false, true, 7),
            lane_answer(DRAIN, true, true, false, 1),
            lane_answer(OTHER, true, false, false, 1),
        ]})
    );
}

#[test]
fn a_limit_that_is_not_a_whole_number_of_at_least_one_reads_as_one() {
    let connection = store();
    for stored in ["0", "-3", "true", "2.0", "2.5", "\"4\"", "null"] {
        put(
            &connection,
            MAIN,
            &format!(r#"{{"exact_lease_batch_limit":{stored}}}"#),
        );
        assert_eq!(
            read(&connection, json!([MAIN])).unwrap(),
            json!({"lanes": [lane_answer(MAIN, true, false, true, 1)]}),
            "stored {stored}"
        );
    }
}

#[test]
fn rows_that_are_not_objects_hold_nothing() {
    let connection = store();
    for stored in ["[1,2]", "\"text\"", "3", "null"] {
        put(&connection, DRAIN, stored);
        assert_eq!(
            read(&connection, json!([DRAIN])).unwrap(),
            json!({"lanes": [lane_answer(DRAIN, true, false, false, 1)]}),
            "stored {stored}"
        );
    }
}

#[test]
fn a_row_that_is_not_json_is_named_unreadable() {
    let connection = store();
    put(&connection, DRAIN, "not json");
    put(
        &connection,
        OTHER,
        r#"{"pending_result":{"job":{},"payload":{}}}"#,
    );
    assert_eq!(
        read(&connection, json!([DRAIN, OTHER])).unwrap(),
        json!({"lanes": [
            lane_answer(DRAIN, false, false, false, 1),
            lane_answer(OTHER, true, true, false, 1),
        ]})
    );
}

#[test]
fn a_damaged_cell_is_unreadable_without_hiding_another_lane() {
    let connection = store();
    connection
        .execute(
            "insert into sync_state values (?1, ?2, '2026-11-22T00:00:00Z')",
            rusqlite::params![DRAIN, vec![0xff_u8, 0xfe, 0x7b]],
        )
        .unwrap();
    put(
        &connection,
        OTHER,
        r#"{"pending_result":{"job":{},"payload":{}}}"#,
    );
    assert_eq!(
        read(&connection, json!([DRAIN, OTHER])).unwrap(),
        json!({"lanes": [
            lane_answer(DRAIN, false, false, false, 1),
            lane_answer(OTHER, true, true, false, 1),
        ]})
    );
}

#[test]
fn a_utf8_blob_cell_reads_like_text() {
    let connection = store();
    connection
        .execute(
            "insert into sync_state values (?1, ?2, '2026-11-22T00:00:00Z')",
            rusqlite::params![MAIN, br#"{"exact_lease_batch_limit":4}"#.to_vec()],
        )
        .unwrap();
    assert_eq!(
        read(&connection, json!([MAIN])).unwrap(),
        json!({"lanes": [lane_answer(MAIN, true, false, true, 4)]})
    );
}

#[test]
fn keys_outside_the_queue_lanes_and_bad_lists_are_refused() {
    let connection = store();
    for key in [
        "oauth_local_credentials",
        "guard_command_capability_v1",
        "guard_command_queue_state.review_drain.x",
        "guard_command_queue_state.review_drain.",
    ] {
        assert!(matches!(
            read(&connection, json!([MAIN, key])),
            Err(StoreError::Value(code)) if code == "invalid_state_key"
        ));
    }
    let too_many: Vec<String> = (0..=MAX_LANES)
        .map(|slot| format!("guard_command_queue_state.review_drain.{slot}"))
        .collect();
    for bad in [json!([]), json!(too_many)] {
        assert!(matches!(
            read(&connection, bad),
            Err(StoreError::Value(code)) if code == "invalid_state_keys"
        ));
    }
    assert!(matches!(
        read(&connection, json!(MAIN)),
        Err(StoreError::Invalid(_))
    ));
    let args = Map::new();
    assert!(matches!(
        dispatch(&connection, "command_queue_lane_rows", &Args(&args)),
        Err(StoreError::Value(code)) if code == "invalid_state_keys"
    ));
}

#[test]
fn the_method_routes_here_and_reads_in_one_snapshot() {
    use crate::guard_store_op_kind::{method_kind, Kind};
    assert!(handles("command_queue_lane_rows"));
    assert!(!handles("record_command_queue_lease_limit"));
    let args = Map::new();
    assert!(dispatch(&store(), "command_queue_lane_row", &Args(&args)).is_err());
    assert!(matches!(
        method_kind("command_queue_lane_rows"),
        Some(Kind::Snapshot)
    ));
    assert!(crate::guard_store_sync_state::handles_row_method(
        "command_queue_lane_rows"
    ));
}
