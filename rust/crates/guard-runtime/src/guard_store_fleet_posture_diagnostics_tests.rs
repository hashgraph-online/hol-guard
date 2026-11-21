//! The fleet posture diagnostics cache: freshness and merged saves.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-09-28T00:10:00Z";
const FRESH: &str = "2026-09-28T00:05:00Z";
const STALE: &str = "2026-09-27T23:59:00Z";
const FUTURE: &str = "2026-09-28T00:11:00Z";
const BEFORE: &str = "2026-09-27T23:00:00+00:00";

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

fn put(connection: &Connection, payload: &Value) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![DIAGNOSTICS_KEY, payload.to_string(), BEFORE],
        )
        .unwrap();
}

fn stored(connection: &Connection) -> Option<Value> {
    connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            [DIAGNOSTICS_KEY],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .map(|payload| serde_json::from_str(&payload).unwrap())
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

fn cached(connection: &Connection, ttl_seconds: i64) -> Value {
    call(
        connection,
        cached_method,
        json!({"now": NOW, "ttl_seconds": ttl_seconds}),
    )
    .unwrap()["diagnostics"]
        .clone()
}

fn summary(status: &str) -> Value {
    json!({"setup_status": status, "has_config_paths": true, "tool_version": null})
}

#[test]
fn only_entries_younger_than_the_ttl_are_fresh() {
    let connection = store();
    put(
        &connection,
        &json!({
            "codex": {"at": FRESH, "diagnostics": summary("active")},
            "cursor": {"at": STALE, "diagnostics": summary("broken")},
            "claude-code": {"at": FUTURE, "diagnostics": summary("active")},
            "omp": {"at": "2026-09-28T00:05:00+00:00", "diagnostics": summary("partial")},
            "naive": {"at": " 2026-09-28T00:06:00 ", "diagnostics": summary("active")},
            "edge": {"at": "2026-09-28T00:00:00Z", "diagnostics": summary("active")},
            "no-time": {"diagnostics": summary("active")},
            "bad-time": {"at": "yesterday", "diagnostics": summary("active")},
            "not-object": {"at": FRESH, "diagnostics": "active"},
            "flat": "active",
        }),
    );
    assert_eq!(
        cached(&connection, 600),
        json!({
            "codex": summary("active"),
            "omp": summary("partial"),
            "naive": summary("active"),
        })
    );
}

#[test]
fn a_ttl_of_zero_or_an_empty_store_reads_nothing() {
    let connection = store();
    assert_eq!(cached(&connection, 600), json!({}));
    put(
        &connection,
        &json!({"codex": {"at": FRESH, "diagnostics": summary("active")}}),
    );
    assert_eq!(cached(&connection, 0), json!({}));
    assert_eq!(cached(&connection, -5), json!({}));
}

#[test]
fn recording_merges_into_the_stored_row() {
    let connection = store();
    put(
        &connection,
        &json!({
            "codex": {"at": STALE, "diagnostics": summary("broken")},
            "cursor": {"at": FRESH, "diagnostics": summary("active")},
        }),
    );
    call(
        &connection,
        record_method,
        json!({"entries": {"codex": summary("active"), "omp": summary("partial")}, "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        stored(&connection),
        Some(json!({
            "codex": {"at": NOW, "diagnostics": summary("active")},
            "cursor": {"at": FRESH, "diagnostics": summary("active")},
            "omp": {"at": NOW, "diagnostics": summary("partial")},
        }))
    );
    assert_eq!(
        cached(&connection, 600),
        json!({
            "codex": summary("active"),
            "cursor": summary("active"),
            "omp": summary("partial"),
        })
    );
}

#[test]
fn recording_replaces_an_unreadable_row() {
    let connection = store();
    connection
        .execute(
            "insert into sync_state values (?1, 'not json', ?2)",
            rusqlite::params![DIAGNOSTICS_KEY, BEFORE],
        )
        .unwrap();
    call(
        &connection,
        record_method,
        json!({"entries": {"codex": summary("active")}, "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        stored(&connection),
        Some(json!({"codex": {"at": NOW, "diagnostics": summary("active")}}))
    );
}

#[test]
fn malformed_inputs_are_refused_without_a_write() {
    let connection = store();
    for (op, args, code) in [
        (
            record_method as fn(&Connection, &Args<'_>) -> StoreResult<Value>,
            json!({"entries": {}, "now": NOW}),
            "invalid_entries",
        ),
        (record_method, json!({"now": NOW}), "invalid_entries"),
        (
            record_method,
            json!({"entries": {"codex": "active"}, "now": NOW}),
            "invalid_entries",
        ),
        (
            record_method,
            json!({"entries": {"": summary("active")}, "now": NOW}),
            "invalid_entries",
        ),
        (
            record_method,
            json!({"entries": {"codex": summary("active")}, "now": "soon"}),
            "invalid_now",
        ),
        (
            cached_method,
            json!({"now": "soon", "ttl_seconds": 600}),
            "invalid_now",
        ),
    ] {
        match call(&connection, op, args) {
            Err(StoreError::Value(found)) => assert_eq!(found, code),
            other => panic!("expected {code}, got {other:?}"),
        }
    }
    assert_eq!(stored(&connection), None);
}
