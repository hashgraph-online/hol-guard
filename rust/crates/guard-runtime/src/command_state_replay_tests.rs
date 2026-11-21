use std::path::Path;

use super::tests::{call, home};
use super::*;
use crate::local_store_read::STORE_FILE_NAME;

const NOW: &str = "2026-09-27T12:00:00+00:00";

fn put(home: &Path, key: &str, payload: Value) {
    Connection::open(home.join(STORE_FILE_NAME))
        .unwrap()
        .execute(
            "INSERT OR REPLACE INTO sync_state VALUES (?1, ?2, ?3)",
            rusqlite::params![key, payload.to_string(), NOW],
        )
        .unwrap();
}

fn keys(home: &Path) -> Vec<String> {
    let conn = Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    let mut statement = conn
        .prepare("SELECT state_key FROM sync_state ORDER BY state_key")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn rows() -> Value {
    json!({"version": 1, "items": [
        {"jobId": "job-1", "idempotencyKey": "key-1"},
        {"jobId": "job-2", "idempotencyKey": "key-2"},
        {"jobId": "job-3", "idempotencyKey": "key-3"},
        {"identityDigest": "sha256:x"},
        {"jobId": 7, "idempotencyKey": "key-7"},
        "not a row",
    ]})
}

fn job_ids(answer: Value) -> Vec<Value> {
    answer
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row.get("jobId").cloned().unwrap_or(Value::Null))
        .collect()
}

#[test]
fn replay_rows_keep_only_rows_that_could_name_the_subject() {
    let home = home();
    put(home.path(), REPLAY_KEY, rows());
    let by_id = call(
        home.path(),
        "replay_rows",
        NOW,
        json!({"subject": {"id": " job-2 "}}),
    );
    assert_eq!(
        job_ids(by_id.unwrap()),
        vec![json!("job-2"), Value::Null, json!(7)]
    );
    let by_key = call(
        home.path(),
        "replay_rows",
        NOW,
        json!({"subject": {"id": "job-9", "idempotencyKey": "key-3"}}),
    );
    assert_eq!(
        job_ids(by_key.unwrap()),
        vec![json!("job-3"), Value::Null, json!(7)]
    );
    let none = call(
        home.path(),
        "replay_rows",
        NOW,
        json!({"subject": {"id": "job-9", "idempotencyKey": 4}}),
    );
    assert_eq!(job_ids(none.unwrap()), vec![Value::Null, json!(7)]);
}

#[test]
fn a_subject_that_is_not_an_object_keeps_every_row() {
    let home = home();
    put(home.path(), REPLAY_KEY, rows());
    for fields in [json!({"subject": ["job-1"]}), json!({})] {
        let answer = call(home.path(), "replay_rows", NOW, fields).unwrap();
        assert_eq!(answer.as_array().unwrap().len(), 5);
    }
}

#[test]
fn replay_rows_of_a_missing_store_are_empty_and_create_nothing() {
    let home = tempfile::tempdir().unwrap();
    let answer = call(
        home.path(),
        "replay_rows",
        NOW,
        json!({"subject": {"id": "job-1"}}),
    );
    assert_eq!(answer, Ok(json!([])));
    assert!(!home.path().join(STORE_FILE_NAME).exists());
}

#[test]
fn unreadable_replay_rows_are_refused() {
    let home = home();
    Connection::open(home.path().join(STORE_FILE_NAME))
        .unwrap()
        .execute(
            "INSERT INTO sync_state VALUES (?1, 'not json', ?2)",
            rusqlite::params![REPLAY_KEY, NOW],
        )
        .unwrap();
    let answer = call(
        home.path(),
        "replay_rows",
        NOW,
        json!({"subject": {"id": "job-1"}}),
    );
    assert_eq!(answer, Err(UNREADABLE.to_owned()));
}

#[test]
fn clear_drops_the_capability_and_the_whole_ledger_only() {
    let home = home();
    for key in CLEARED_KEYS {
        put(home.path(), key, json!({"items": []}));
    }
    put(home.path(), "guard_auto_update_state", json!({}));
    assert_eq!(call(home.path(), "clear", NOW, json!({})), Ok(Value::Null));
    assert_eq!(
        keys(home.path()),
        vec!["guard_auto_update_state".to_owned()]
    );
}

#[test]
fn clearing_a_missing_store_creates_nothing() {
    let home = tempfile::tempdir().unwrap();
    assert_eq!(call(home.path(), "clear", NOW, json!({})), Ok(Value::Null));
    assert!(!home.path().join(STORE_FILE_NAME).exists());
}

#[test]
fn issuing_a_capability_resets_the_queue_but_keeps_replay_rows() {
    let home = home();
    for key in CLEARED_KEYS {
        put(home.path(), key, json!({"items": []}));
    }
    let capability = json!({"version": 1, "operations": ["guard.example"]});
    let answer = call(home.path(), "issue", NOW, json!({"capability": capability}));
    assert_eq!(answer, Ok(Value::Null));
    assert_eq!(
        keys(home.path()),
        vec![CAPABILITY_KEY.to_owned(), REPLAY_KEY.to_owned()]
    );
    let saved: String = Connection::open(home.path().join(STORE_FILE_NAME))
        .unwrap()
        .query_row(
            "SELECT payload_json FROM sync_state WHERE state_key = ?1",
            [CAPABILITY_KEY],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&saved).unwrap(), capability);
}

#[test]
fn issuing_without_a_capability_is_refused_and_changes_nothing() {
    let home = home();
    put(home.path(), PENDING_KEY, json!({"items": []}));
    assert_eq!(
        call(home.path(), "issue", NOW, json!({})),
        Err(INVALID.to_owned())
    );
    assert_eq!(keys(home.path()), vec![PENDING_KEY.to_owned()]);
}
