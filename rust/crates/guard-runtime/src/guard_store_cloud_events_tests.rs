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
    let listed = queued(&connection, "", 200, "t-now").unwrap();
    assert_eq!(listed[0]["event_id"], json!("e-1"));
    assert_eq!(listed[1]["event_id"], json!("e-2"));
    assert_eq!(listed[0]["uploaded_at"], Value::Null);
    assert_eq!(listed[0]["payload"]["payload"], json!({"a": "é", "b": 1}));
    assert_eq!(
        queued(&connection, "", 1, "t-now")
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
    let listed = queued(&connection, " where uploaded_at is not null", 200, "t-now").unwrap();
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
        queued(&connection, "", 200, "t-now"),
        Err(StoreError::Invalid("guard_event_payload_invalid"))
    ));
    assert!(matches!(
        call(&connection, count, json!({"uploaded": "yes"})),
        Err(StoreError::Invalid("native_guard_store_args_invalid"))
    ));
}

fn store_raw(connection: &Connection, id: &str, occurred_at: &str, payload_json: &str) {
    exec(
        connection,
        "insert into guard_cloud_events \
         (event_id, idempotency_key, event_type, payload_json, occurred_at, uploaded_at) \
         values (?, ?, 'test.event', ?, ?, null)",
        &[
            Value::from(id),
            Value::from(format!("key:{id}")),
            Value::from(payload_json),
            Value::from(occurred_at),
        ],
    )
    .unwrap();
}

fn padded(bytes: usize) -> String {
    format!("{{\"pad\": \"{}\"}}", "x".repeat(bytes))
}

fn oversized(connection: &Connection) -> Value {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(
            crate::guard_store_receipt_events::OVERSIZED_KEY,
        )],
    )
    .unwrap()
    .unwrap();
    serde_json::from_str(text(&row, "payload_json")).unwrap()
}

#[test]
fn a_queue_read_stops_at_its_byte_budget_and_the_next_read_continues() {
    let connection = store();
    let third = READ_BYTES_BUDGET / 3;
    for (id, at) in [("e-1", "t1"), ("e-2", "t2"), ("e-3", "t3"), ("e-4", "t4")] {
        store_raw(&connection, id, at, &padded(third));
    }
    let first = queued(&connection, " where uploaded_at is null", 200, "t-now").unwrap();
    let ids: Vec<_> = first
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_id"].clone())
        .collect();
    assert_eq!(ids, vec![json!("e-1"), json!("e-2")]);
    exec(
        &connection,
        "update guard_cloud_events set uploaded_at = 'u' where event_id in ('e-1', 'e-2')",
        &[],
    )
    .unwrap();
    let second = queued(&connection, " where uploaded_at is null", 200, "t-now").unwrap();
    assert_eq!(second.as_array().unwrap().len(), 2);
}

#[test]
fn one_event_that_fills_the_budget_is_still_read() {
    let connection = store();
    store_raw(&connection, "e-1", "t1", &padded(EVENT_BYTES_LIMIT - 16));
    store_raw(&connection, "e-2", "t2", &padded(8));
    let listed = queued(&connection, " where uploaded_at is null", 200, "t-now").unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["event_id"], json!("e-1"));
}

#[test]
fn a_stored_event_too_large_to_read_leaves_the_queue_and_is_recorded() {
    let connection = store();
    store_raw(&connection, "e-1", "t1", &padded(EVENT_BYTES_LIMIT));
    store_raw(&connection, "e-2", "t2", &padded(8));
    let listed = queued(&connection, " where uploaded_at is null", 200, "t-now").unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["event_id"], json!("e-2"));
    assert_eq!(call(&connection, count, json!({})).unwrap(), json!(1));
    let state = oversized(&connection);
    assert_eq!(state["droppedCount"], json!(1));
    assert_eq!(state["lastEventType"], json!("test.event"));
    assert_eq!(state["lastDroppedAt"], json!("t-now"));
}

#[test]
fn an_event_too_large_to_read_is_never_queued() {
    let connection = store();
    let mut big = event("e-1", "t1");
    big["payload"] = json!({"pad": "x".repeat(EVENT_BYTES_LIMIT)});
    call(
        &connection,
        add,
        json!({"event": big, "event_queue_limit": 10, "now": "t-now"}),
    )
    .unwrap();
    assert_eq!(call(&connection, count, json!({})).unwrap(), json!(0));
    assert_eq!(oversized(&connection)["droppedCount"], json!(1));
}
