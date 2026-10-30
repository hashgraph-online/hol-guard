//! The event log and upload queue answer as `store_cloud_events.py` did: a
//! full queue drops new events and records the rejection, and uploading the
//! backlog records the recovery.

use super::*;
use rusqlite::Connection;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_events (
               event_id integer primary key autoincrement, event_name text not null,
               payload_json text not null, occurred_at text not null);
             create table guard_cloud_events (
               event_id text primary key, idempotency_key text not null unique,
               event_type text not null, payload_json text not null,
               occurred_at text not null, uploaded_at text);
             create table sync_state (
               state_key text primary key, payload_json text not null,
               updated_at text not null);",
        )
        .unwrap();
    connection
}

fn call(
    connection: &Connection,
    op: fn(&Connection, &Args<'_>) -> StoreResult<Value>,
    args: Value,
) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    op(connection, &Args(&args))
}

fn event(id: &str, occurred_at: &str) -> Value {
    json!({
        "schemaVersion": "guard.event.v1",
        "eventId": id,
        "idempotencyKey": format!("key:{id}"),
        "eventType": "test.event",
        "occurredAt": occurred_at,
        "payload": {"b": 1, "a": "é"},
    })
}

fn queue(connection: &Connection, id: &str, occurred_at: &str, limit: i64) {
    call(
        connection,
        add,
        json!({"event": event(id, occurred_at), "event_queue_limit": limit, "now": "t-now"}),
    )
    .unwrap();
}

fn capacity(connection: &Connection) -> Value {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(CAPACITY_KEY)],
    )
    .unwrap()
    .unwrap();
    serde_json::from_str(text(&row, "payload_json")).unwrap()
}

#[test]
fn the_event_log_keeps_the_payload_text_it_was_sent() {
    let connection = store();
    let args = json!({"event_name": "session/started", "payload_json": "{\"z\": 1, \"a\": 2}", "occurred_at": "t1"});
    call(&connection, add_event, args).unwrap();
    let row = query_one(
        &connection,
        "select event_name, payload_json from guard_events",
        &[],
    )
    .unwrap()
    .unwrap();
    assert_eq!(text(&row, "event_name"), "session/started");
    assert_eq!(text(&row, "payload_json"), "{\"z\": 1, \"a\": 2}");
}

#[test]
fn queued_events_count_and_read_oldest_first() {
    let connection = store();
    queue(&connection, "e-2", "t2", 10);
    queue(&connection, "e-1", "t1", 10);
    queue(&connection, "e-1", "t1", 10);
    let all = call(&connection, count, json!({})).unwrap();
    assert_eq!(all, json!(2));
    let listed = queued(&connection, "", 200).unwrap();
    assert_eq!(listed[0]["event_id"], json!("e-1"));
    assert_eq!(listed[1]["event_id"], json!("e-2"));
    assert_eq!(listed[0]["uploaded_at"], Value::Null);
    assert_eq!(listed[0]["payload"]["payload"], json!({"a": "é", "b": 1}));
    assert_eq!(
        queued(&connection, "", 1)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn a_full_queue_drops_new_events_and_records_why() {
    let connection = store();
    queue(&connection, "e-1", "t1", 1);
    queue(&connection, "e-2", "t2", 1);
    queue(&connection, "e-3", "t3", 1);
    assert_eq!(call(&connection, count, json!({})).unwrap(), json!(1));
    let state = capacity(&connection);
    assert_eq!(state["exhausted"], json!(true));
    assert_eq!(state["firstRejectedAt"], json!("t2"));
    assert_eq!(state["lastRejectedAt"], json!("t3"));
    assert_eq!(state["rejectedCount"], json!(2));
}

#[test]
fn uploading_the_backlog_records_the_recovery() {
    let connection = store();
    queue(&connection, "e-1", "t1", 1);
    queue(&connection, "e-2", "t2", 1);
    let marked = call(
        &connection,
        mark_uploaded,
        json!({"event_ids": ["e-1", "  ", "missing"], "uploaded_at": "t9", "event_queue_limit": 1}),
    )
    .unwrap();
    assert_eq!(marked, json!(1));
    assert_eq!(
        call(&connection, count, json!({"uploaded": true})).unwrap(),
        json!(1)
    );
    assert_eq!(
        call(&connection, count, json!({"uploaded": false})).unwrap(),
        json!(0)
    );
    let state = capacity(&connection);
    assert_eq!(state["exhausted"], json!(false));
    assert_eq!(state["pendingCount"], json!(0));
    assert_eq!(state["recoveredAt"], json!("t9"));
    assert_eq!(state["rejectedCount"], json!(1));
    let listed = queued(&connection, " where uploaded_at is not null", 200).unwrap();
    assert_eq!(listed[0]["uploaded_at"], json!("t9"));
}

#[test]
fn blank_ids_mark_nothing() {
    let connection = store();
    queue(&connection, "e-1", "t1", 10);
    let marked = call(
        &connection,
        mark_uploaded,
        json!({"event_ids": [" ", ""], "uploaded_at": "t9", "event_queue_limit": 10}),
    )
    .unwrap();
    assert_eq!(marked, json!(0));
    assert_eq!(
        call(&connection, count, json!({"uploaded": false})).unwrap(),
        json!(1)
    );
}

#[test]
fn a_payload_that_is_not_json_is_refused() {
    let connection = store();
    exec(
        &connection,
        "insert into guard_cloud_events values ('e-1', 'k', 't', 'not json', 't1', null)",
        &[],
    )
    .unwrap();
    assert!(matches!(
        queued(&connection, "", 200),
        Err(StoreError::Invalid("guard_event_payload_invalid"))
    ));
    assert!(matches!(
        call(&connection, count, json!({"uploaded": "yes"})),
        Err(StoreError::Invalid("native_guard_store_args_invalid"))
    ));
}
