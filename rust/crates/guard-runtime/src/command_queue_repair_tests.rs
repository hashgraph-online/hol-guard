use std::path::Path;

use rusqlite::OptionalExtension;

use super::tests::{call, home};
use super::*;
use crate::command_queue_repair::lane_state_key;
use crate::local_store_read::STORE_FILE_NAME;

const NOW: &str = "2026-09-27T12:00:00+00:00";
const DRAIN_KEY: &str = "guard_command_queue_state.review_drain.2";

fn put(home: &Path, key: &str, payload: &str) {
    Connection::open(home.join(STORE_FILE_NAME))
        .unwrap()
        .execute(
            "INSERT OR REPLACE INTO sync_state VALUES (?1, ?2, ?3)",
            rusqlite::params![key, payload, "2026-09-27T11:00:00+00:00"],
        )
        .unwrap();
}

fn get(home: &Path, key: &str) -> Option<(Value, String)> {
    Connection::open(home.join(STORE_FILE_NAME))
        .unwrap()
        .query_row(
            "SELECT payload_json, updated_at FROM sync_state WHERE state_key = ?1",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .unwrap()
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
}

fn repair(home: &Path, fields: Value) -> Result<Value, String> {
    call(home, "queue_repair", NOW, fields)
}

#[test]
fn damaged_fields_are_dropped_and_the_lane_goes_idle() {
    let home = home();
    put(
        home.path(),
        QUEUE_RUNTIME_KEY,
        r#"{"state":"running","last_error":"boom","active_job":"job-1",
            "pending_result":{"job":{"id":"job-1"},"payload":[]},"last_poll_at":"t"}"#,
    );
    let answer = repair(home.path(), json!({})).unwrap();
    assert_eq!(
        answer,
        json!({"repaired": ["active_job", "pending_result"]})
    );
    let (state, at) = get(home.path(), QUEUE_RUNTIME_KEY).unwrap();
    assert_eq!(
        state,
        json!({"state": "idle", "last_error": null, "last_poll_at": "t"})
    );
    assert_eq!(at, NOW);
}

#[test]
fn usable_and_null_fields_are_left_alone() {
    let home = home();
    let saved = r#"{"state":"running","last_error":"boom","active_job":{"id":"job-1"},
        "pending_result":{"job":{"id":"job-1"},"payload":{"ok":true}}}"#;
    put(home.path(), QUEUE_RUNTIME_KEY, saved);
    assert_eq!(
        repair(home.path(), json!({})).unwrap(),
        json!({"repaired": []})
    );
    let (_, at) = get(home.path(), QUEUE_RUNTIME_KEY).unwrap();
    assert_ne!(at, NOW, "a healthy row is not written back");

    put(
        home.path(),
        QUEUE_RUNTIME_KEY,
        r#"{"active_job":null,"pending_result":null}"#,
    );
    assert_eq!(
        repair(home.path(), json!({})).unwrap(),
        json!({"repaired": []})
    );
}

#[test]
fn a_pending_result_needs_an_object_job_and_payload() {
    for pending in [
        r#""text""#,
        r#"{"payload":{}}"#,
        r#"{"job":{}}"#,
        r#"{"job":"job-1","payload":{}}"#,
    ] {
        let home = home();
        put(
            home.path(),
            QUEUE_RUNTIME_KEY,
            &format!(r#"{{"pending_result":{pending}}}"#),
        );
        assert_eq!(
            repair(home.path(), json!({})).unwrap(),
            json!({"repaired": ["pending_result"]}),
            "{pending}"
        );
    }
}

#[test]
fn a_drain_lane_repairs_only_its_own_row() {
    let home = home();
    put(home.path(), QUEUE_RUNTIME_KEY, r#"{"active_job":7}"#);
    put(home.path(), DRAIN_KEY, r#"{"active_job":7}"#);
    assert_eq!(
        repair(home.path(), json!({"state_key": DRAIN_KEY})).unwrap(),
        json!({"repaired": ["active_job"]})
    );
    assert_eq!(
        get(home.path(), QUEUE_RUNTIME_KEY).unwrap().0,
        json!({"active_job": 7})
    );
}

#[test]
fn only_queue_lane_rows_may_be_named() {
    assert_eq!(lane_state_key(None), Some(QUEUE_RUNTIME_KEY));
    assert_eq!(lane_state_key(Some(DRAIN_KEY)), Some(DRAIN_KEY));
    for key in [
        CAPABILITY_KEY,
        "guard_command_queue_state.review_drain.",
        "guard_command_queue_state.review_drain.1a",
        "guard_command_queue_state.other.1",
    ] {
        assert_eq!(lane_state_key(Some(key)), None, "{key}");
    }
    let home = home();
    put(home.path(), CAPABILITY_KEY, r#"{"active_job":7}"#);
    assert_eq!(
        repair(home.path(), json!({"state_key": CAPABILITY_KEY})),
        Err(INVALID.to_owned())
    );
    assert_eq!(
        get(home.path(), CAPABILITY_KEY).unwrap().0,
        json!({"active_job": 7})
    );
}

#[test]
fn missing_rows_stores_and_non_objects_have_nothing_to_repair() {
    let home = home();
    assert_eq!(
        repair(home.path(), json!({})).unwrap(),
        json!({"repaired": []})
    );
    put(home.path(), QUEUE_RUNTIME_KEY, "[1,2]");
    assert_eq!(
        repair(home.path(), json!({})).unwrap(),
        json!({"repaired": []})
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        repair(empty.path(), json!({})).unwrap(),
        json!({"repaired": []})
    );
    assert!(!empty.path().join(STORE_FILE_NAME).exists());
}

#[test]
fn an_unreadable_row_is_refused() {
    let home = home();
    put(home.path(), QUEUE_RUNTIME_KEY, "{not json");
    assert_eq!(repair(home.path(), json!({})), Err(UNREADABLE.to_owned()));
}
