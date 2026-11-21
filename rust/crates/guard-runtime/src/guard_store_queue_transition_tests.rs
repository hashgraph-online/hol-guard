//! Each step merges its own fields into the lane row and keeps the rest.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const MAIN: &str = "guard_command_queue_state";
const DRAIN: &str = "guard_command_queue_state.review_drain.2";
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

fn row(connection: &Connection, key: &str) -> (Value, String) {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
        .unwrap()
}

fn run(connection: &Connection, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    method(connection, &Args(&args))
}

fn transition(connection: &Connection, key: &str, name: &str) -> Value {
    run(
        connection,
        json!({"state_key": key, "transition": name, "now": NOW, "at": AT}),
    )
    .unwrap()
}

fn error_code(result: StoreResult<Value>) -> String {
    match result {
        Err(StoreError::Value(code)) => code,
        other => panic!("expected a value error, got {other:?}"),
    }
}

const LEASED: &str = r#"{"state":"leased","active_job":{"id":"j"},"last_lease_at":"t0",
    "exact_lease_batch_limit":4,"last_error":"old","last_poll_was_empty":true}"#;

#[test]
fn polling_merges_its_fields_and_keeps_the_lease_limit() {
    let connection = store();
    put(&connection, MAIN, LEASED);
    let answer = transition(&connection, MAIN, "polling");
    let expected = json!({"state": "polling", "active_job": {"id": "j"},
        "last_lease_at": "t0", "exact_lease_batch_limit": 4, "last_error": null,
        "last_poll_was_empty": false, "last_poll_at": AT});
    assert_eq!(answer, json!({"state": expected}));
    assert_eq!(row(&connection, MAIN), (expected, NOW.to_owned()));
}

#[test]
fn disabled_clears_the_job_and_error_on_an_empty_lane() {
    let connection = store();
    let answer = transition(&connection, DRAIN, "disabled");
    assert_eq!(
        answer,
        json!({"state": {"state": "disabled", "last_error": null, "active_job": null}})
    );
}

#[test]
fn a_heartbeat_failure_drops_the_job_and_names_the_error() {
    let connection = store();
    put(&connection, MAIN, LEASED);
    let state = &transition(&connection, MAIN, "heartbeat_failed")["state"];
    assert!(state.get("active_job").is_none());
    assert_eq!(state["state"], json!("error"));
    assert_eq!(
        state["last_error"],
        json!("Guard command heartbeat failed.")
    );
    assert_eq!(state["exact_lease_batch_limit"], json!(4));
}

#[test]
fn auth_expired_only_changes_the_state_name() {
    let connection = store();
    put(&connection, MAIN, LEASED);
    let state = &transition(&connection, MAIN, "auth_expired")["state"];
    assert_eq!(state["state"], json!("auth_expired"));
    assert_eq!(state["active_job"], json!({"id": "j"}));
}

#[test]
fn a_pending_result_is_kept_with_its_record_time() {
    let connection = store();
    put(&connection, MAIN, LEASED);
    let answer = run(
        &connection,
        json!({"state_key": MAIN, "transition": "result_pending", "now": NOW, "at": AT,
               "pending": {"job": {"id": "j"}, "payload": {"status": "ok"}}}),
    )
    .unwrap();
    assert_eq!(answer["state"]["state"], json!("result_pending"));
    assert_eq!(
        answer["state"]["pending_result"],
        json!({"job": {"id": "j"}, "payload": {"status": "ok"}, "recorded_at": AT})
    );
    for pending in [
        json!(null),
        json!({"job": {"id": "j"}}),
        json!({"job": 1, "payload": {}}),
    ] {
        let result = run(
            &connection,
            json!({"state_key": MAIN, "transition": "result_pending", "now": NOW,
                   "pending": pending}),
        );
        assert_eq!(error_code(result), "invalid_pending_result");
    }
}

#[test]
fn the_closing_steps_drop_the_job_and_kept_result() {
    let pending = r#"{"state":"result_pending","active_job":{"id":"j"},
        "pending_result":{"job":{"id":"j"},"payload":{}},"last_error":"x",
        "exact_lease_batch_limit":2}"#;
    let cases = [
        (
            "settled",
            json!({"state": "idle", "last_result_at": AT, "last_error": null,
            "last_poll_was_empty": false, "exact_lease_batch_limit": 2}),
        ),
        (
            "result_refused",
            json!({"state": "idle", "last_error": null,
            "last_poll_was_empty": false, "exact_lease_batch_limit": 2}),
        ),
        (
            "stale_result_dropped",
            json!({"state": "idle", "last_error": null,
            "exact_lease_batch_limit": 2}),
        ),
        (
            "malformed_result_dropped",
            json!({"state": "result_pending", "last_error": "x",
            "exact_lease_batch_limit": 2}),
        ),
    ];
    for (name, expected) in cases {
        let connection = store();
        put(&connection, MAIN, pending);
        assert_eq!(
            transition(&connection, MAIN, name),
            json!({"state": expected}),
            "{name}"
        );
    }
}

#[test]
fn the_record_time_defaults_to_now_and_a_bad_row_reads_as_empty() {
    let connection = store();
    put(&connection, MAIN, "[1]");
    let answer = run(
        &connection,
        json!({"state_key": MAIN, "transition": "polling", "now": NOW}),
    )
    .unwrap();
    assert_eq!(answer["state"]["last_poll_at"], json!(NOW));
    assert_eq!(answer["state"].as_object().unwrap().len(), 4);
}

#[test]
fn an_unknown_step_or_lane_is_refused_and_writes_nothing() {
    let connection = store();
    put(&connection, MAIN, LEASED);
    let unknown = run(
        &connection,
        json!({"state_key": MAIN, "transition": "leased", "now": NOW}),
    );
    assert_eq!(error_code(unknown), "invalid_transition");
    let lane = run(
        &connection,
        json!({"state_key": "guard_command_queue_state.other", "transition": "polling",
               "now": NOW}),
    );
    assert_eq!(error_code(lane), "invalid_state_key");
    assert_eq!(row(&connection, MAIN).1, BEFORE);
}
