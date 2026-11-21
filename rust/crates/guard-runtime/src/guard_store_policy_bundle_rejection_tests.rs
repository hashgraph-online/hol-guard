//! The rejection bookkeeping writes the rows and events the runner wrote.

use serde_json::json;

use super::*;

const T1: &str = "2026-08-03T00:01:00Z";
const PAYLOAD: &str = "{\"error\": \"invalid_signature\", \"rejected_at\": \"t\"}";

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key,
               payload_json text not null, updated_at text not null);
             create table guard_events (id integer primary key,
               event_name text not null, payload_json text not null,
               occurred_at text not null);",
        )
        .unwrap();
    connection
}

fn run(connection: &Connection, args: Value) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    method(connection, &Args(&args))
}

fn events(connection: &Connection) -> Vec<(String, String, String)> {
    let mut statement = connection
        .prepare("select event_name, payload_json, occurred_at from guard_events order by id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn last_error(connection: &Connection) -> Option<(String, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?",
            [LAST_ERROR],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()
}

#[test]
fn a_persisted_rejection_stores_the_same_text_in_the_row_and_the_event() {
    let connection = store();
    let args = json!({"payload_json": PAYLOAD, "now": T1, "persist_last_error": true});
    run(&connection, args).unwrap();
    assert_eq!(
        last_error(&connection),
        Some((PAYLOAD.to_owned(), T1.to_owned()))
    );
    assert_eq!(
        events(&connection),
        vec![(REJECTED_EVENT.to_owned(), PAYLOAD.to_owned(), T1.to_owned())]
    );
}

#[test]
fn an_event_only_rejection_leaves_the_last_error_alone() {
    let connection = store();
    run(&connection, json!({"payload_json": PAYLOAD, "now": T1})).unwrap();
    assert_eq!(last_error(&connection), None);
    assert_eq!(events(&connection).len(), 1);
}

#[test]
fn a_gate_block_adds_its_event_after_the_rejection() {
    let connection = store();
    let blocked = "{\"error\": \"approval_gate_locked\", \"remote_policies_count\": 2}";
    let args = json!({
        "payload_json": PAYLOAD,
        "now": T1,
        "persist_last_error": true,
        "gate_blocked_payload_json": blocked,
    });
    run(&connection, args).unwrap();
    let names: Vec<String> = events(&connection).into_iter().map(|e| e.0).collect();
    assert_eq!(names, vec![REJECTED_EVENT, GATE_BLOCKED_EVENT]);
    assert_eq!(events(&connection)[1].1, blocked);
}

#[test]
fn a_payload_that_is_not_an_object_is_rejected_before_any_write() {
    let connection = store();
    for payload in ["[1]", "\"x\"", "{", ""] {
        let args = json!({"payload_json": payload, "now": T1, "persist_last_error": true});
        assert!(run(&connection, args).is_err());
    }
    let args = json!({
        "payload_json": PAYLOAD,
        "now": T1,
        "gate_blocked_payload_json": "[]",
    });
    assert!(run(&connection, args).is_err());
    assert!(run(&connection, json!({"now": T1})).is_err());
    assert_eq!(last_error(&connection), None);
    assert!(events(&connection).is_empty());
}

#[test]
fn a_failed_event_rolls_back_the_last_error_through_the_store_op() {
    // A trigger makes the event insert fail after the last-error row is
    // written. Only the store op's write transaction can undo the row, so this
    // fails if the method stops being dispatched as a write.
    let nonce = crate::unique_nanos::unique_nanos();
    let home = std::env::temp_dir().join(format!(
        "hol-guard-store-rejection-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = std::fs::canonicalize(home).unwrap();
    let path = home.join("guard.db");
    let previous = "{\"error\": \"older\"}";
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "create table sync_state (state_key text primary key,
                   payload_json text not null, updated_at text not null);
                 create table guard_events (id integer primary key,
                   event_name text not null, payload_json text not null,
                   occurred_at text not null);
                 create trigger refuse_events before insert on guard_events
                   begin select raise(abort, 'refused'); end;",
            )
            .unwrap();
        connection
            .execute(
                "insert into sync_state values (?, ?, 't0')",
                [LAST_ERROR, previous],
            )
            .unwrap();
    }
    let Value::Object(args) =
        json!({"payload_json": PAYLOAD, "now": T1, "persist_last_error": true})
    else {
        unreachable!()
    };
    let request = guard_contracts::GuardStoreRequestV1 {
        schema: guard_contracts::GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "rejection".to_owned(),
        store_path: path.to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "record_policy_bundle_rejection".to_owned(),
        source: "default".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    // The trigger's own failure, not an earlier request check.
    match crate::guard_store_op::evaluate(&request) {
        Err(crate::guard_store_db::StoreError::Sqlite(error)) => {
            assert!(error.to_string().contains("refused"), "{error}");
        }
        other => panic!("expected the refused event insert, got {other:?}"),
    }
    let connection = Connection::open(&path).unwrap();
    assert_eq!(
        last_error(&connection),
        Some((previous.to_owned(), "t0".to_owned()))
    );
    assert!(events(&connection).is_empty());
    drop(connection);
    let _ = std::fs::remove_dir_all(&home);
}
