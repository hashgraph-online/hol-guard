use super::*;
use serde_json::Map;

use crate::guard_store_op_kind::{method_kind, Kind};

fn connection() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_runtime_state (state_key text primary key, session_id text not null, \
             daemon_host text not null, daemon_port integer not null, started_at text not null, \
             last_heartbeat_at text not null);",
        )
        .unwrap();
    connection
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let map: Map<String, Value> = args.as_object().cloned().unwrap_or_default();
    dispatch(connection, method, &Args(&map))
}

fn upsert(connection: &Connection, session_id: &str) {
    call(
        connection,
        "upsert_runtime_state",
        json!({
            "session_id": session_id,
            "daemon_host": "127.0.0.1",
            "daemon_port": 4319,
            "started_at": "2026-01-01T00:00:00Z",
            "last_heartbeat_at": "2026-01-01T00:00:05Z",
        }),
    )
    .unwrap();
}

#[test]
fn no_runtime_row_reads_null() {
    assert_eq!(
        call(&connection(), "get_runtime_state", json!({})).unwrap(),
        Value::Null
    );
}

#[test]
fn the_recorded_runtime_row_reads_back() {
    let connection = connection();
    upsert(&connection, "session-a");
    assert_eq!(
        call(&connection, "get_runtime_state", json!({})).unwrap(),
        json!({
            "session_id": "session-a",
            "daemon_host": "127.0.0.1",
            "daemon_port": 4319,
            "started_at": "2026-01-01T00:00:00Z",
            "last_heartbeat_at": "2026-01-01T00:00:05Z",
        })
    );
}

#[test]
fn a_port_that_is_not_a_whole_number_is_refused() {
    let connection = connection();
    connection
        .execute(
            "insert into guard_runtime_state values ('runtime', 's', 'h', 'not-a-port', 'a', 'b')",
            [],
        )
        .unwrap();
    assert!(matches!(
        call(&connection, "get_runtime_state", json!({})),
        Err(StoreError::Value(_))
    ));
}

#[test]
fn a_text_field_that_is_not_text_is_refused() {
    // A column with no declared type keeps the integer; a `text` column would
    // store it as the string "7".
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_runtime_state (state_key text primary key, session_id, \
             daemon_host text not null, daemon_port integer not null, started_at text not null, \
             last_heartbeat_at text not null);",
        )
        .unwrap();
    connection
        .execute(
            "insert into guard_runtime_state values ('runtime', 7, 'h', 1, 'a', 'b')",
            [],
        )
        .unwrap();
    assert!(matches!(
        call(&connection, "get_runtime_state", json!({})),
        Err(StoreError::Value(_))
    ));
}

#[test]
fn clearing_removes_only_the_owning_sessions_row() {
    let connection = connection();
    upsert(&connection, "session-new");
    call(
        &connection,
        "clear_runtime_state",
        json!({"session_id": "session-old"}),
    )
    .unwrap();
    assert_eq!(
        call(&connection, "get_runtime_state", json!({})).unwrap()["session_id"],
        "session-new"
    );
    call(
        &connection,
        "clear_runtime_state",
        json!({"session_id": "session-new"}),
    )
    .unwrap();
    assert_eq!(
        call(&connection, "get_runtime_state", json!({})).unwrap(),
        Value::Null
    );
}

#[test]
fn clearing_requires_a_session_id() {
    assert!(call(&connection(), "clear_runtime_state", json!({})).is_err());
}

#[test]
fn the_runtime_state_methods_route_here_with_their_kinds() {
    assert!(handles("get_runtime_state"));
    assert!(handles("clear_runtime_state"));
    assert!(matches!(method_kind("get_runtime_state"), Some(Kind::Read)));
    assert!(matches!(
        method_kind("clear_runtime_state"),
        Some(Kind::Write)
    ));
}
