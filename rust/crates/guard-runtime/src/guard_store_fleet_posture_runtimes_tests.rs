//! The fleet posture runtimes cache: scope, TTL and bundle expiry.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-09-28T01:00:00Z";
/// `NOW` as Unix seconds.
const NOW_SECONDS: f64 = 1_790_557_200.0;
const FRESH: &str = "2026-09-28T00:30:00Z";
const STALE: &str = "2026-09-27T23:59:00Z";
const FUTURE: &str = "2026-09-28T01:01:00Z";
const BEFORE: &str = "2026-09-27T23:00:00+00:00";
const SCOPE: &str = "scope-a";

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
            rusqlite::params![RUNTIMES_KEY, payload.to_string(), BEFORE],
        )
        .unwrap();
}

fn stored(connection: &Connection) -> Option<Value> {
    connection
        .query_row(
            "select payload_json from sync_state where state_key = ?1",
            [RUNTIMES_KEY],
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

fn cached(connection: &Connection, scope: &str, ttl_seconds: i64) -> Value {
    call(
        connection,
        cached_method,
        json!({"scope": scope, "now": NOW, "ttl_seconds": ttl_seconds}),
    )
    .unwrap()["section"]
        .clone()
}

fn section() -> Value {
    json!({"scope": "partial", "runtimes": [{"family": "node"}]})
}

fn row(at: &str, valid_until: &Value) -> Value {
    json!({"at": at, "scope": SCOPE, "section": section(), "valid_until": valid_until})
}

#[test]
fn the_now_constant_matches_its_seconds() {
    let micros = instant(Some(&Value::from(NOW))).unwrap();
    assert_eq!(micros, 1_790_557_200_000_000);
}

#[test]
fn a_fresh_row_for_the_same_scope_is_read_back() {
    let connection = store();
    assert_eq!(cached(&connection, SCOPE, 3600), Value::Null);
    put(&connection, &row(FRESH, &Value::Null));
    assert_eq!(cached(&connection, SCOPE, 3600), section());
    let naive = json!({"at": " 2026-09-28T00:30:00 ", "scope": SCOPE, "section": section()});
    put(&connection, &naive);
    assert_eq!(cached(&connection, SCOPE, 3600), section());
}

#[test]
fn another_scope_an_old_row_or_a_future_row_reads_nothing() {
    let connection = store();
    put(&connection, &row(FRESH, &Value::Null));
    assert_eq!(cached(&connection, "scope-b", 3600), Value::Null);
    assert_eq!(cached(&connection, SCOPE, 0), Value::Null);
    assert_eq!(cached(&connection, SCOPE, -1), Value::Null);
    for at in [STALE, FUTURE, "yesterday"] {
        put(&connection, &row(at, &Value::Null));
        assert_eq!(cached(&connection, SCOPE, 3600), Value::Null, "{at}");
    }
    for malformed in [
        json!({"at": FRESH, "scope": SCOPE, "section": "partial"}),
        json!({"at": FRESH, "section": section()}),
        json!({"scope": SCOPE, "section": section()}),
        json!("flat"),
    ] {
        put(&connection, &malformed);
        assert_eq!(cached(&connection, SCOPE, 3600), Value::Null, "{malformed}");
    }
}

#[test]
fn a_row_lapses_with_its_bundle() {
    let connection = store();
    for (valid_until, fresh) in [
        (json!(NOW_SECONDS + 60.0), true),
        (json!(NOW_SECONDS as i64 + 1), true),
        (json!(NOW_SECONDS), false),
        (json!(NOW_SECONDS - 1.0), false),
        (json!("tomorrow"), false),
        (json!(true), false),
    ] {
        put(&connection, &row(FRESH, &valid_until));
        let expected = if fresh { section() } else { Value::Null };
        assert_eq!(cached(&connection, SCOPE, 3600), expected, "{valid_until}");
    }
}

#[test]
fn recording_replaces_the_row() {
    let connection = store();
    put(&connection, &row(STALE, &Value::Null));
    call(
        &connection,
        record_method,
        json!({"scope": SCOPE, "section": section(), "valid_until": NOW_SECONDS + 60.0, "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        stored(&connection),
        Some(json!({
            "at": NOW,
            "scope": SCOPE,
            "section": section(),
            "valid_until": NOW_SECONDS + 60.0,
        }))
    );
    assert_eq!(cached(&connection, SCOPE, 3600), section());
    call(
        &connection,
        record_method,
        json!({"scope": "scope-b", "section": section(), "now": NOW}),
    )
    .unwrap();
    assert_eq!(stored(&connection).unwrap()["valid_until"], Value::Null);
    assert_eq!(cached(&connection, SCOPE, 3600), Value::Null);
}

#[test]
fn malformed_inputs_are_refused_without_a_write() {
    let connection = store();
    for (op, args, code) in [
        (
            record_method as fn(&Connection, &Args<'_>) -> StoreResult<Value>,
            json!({"section": section(), "now": NOW}),
            "invalid_scope",
        ),
        (
            record_method,
            json!({"scope": "", "section": section(), "now": NOW}),
            "invalid_scope",
        ),
        (
            record_method,
            json!({"scope": SCOPE, "section": "partial", "now": NOW}),
            "invalid_section",
        ),
        (
            record_method,
            json!({"scope": SCOPE, "section": section(), "valid_until": "soon", "now": NOW}),
            "invalid_valid_until",
        ),
        (
            record_method,
            json!({"scope": SCOPE, "section": section(), "now": "soon"}),
            "invalid_now",
        ),
        (
            cached_method,
            json!({"scope": SCOPE, "now": "soon", "ttl_seconds": 3600}),
            "invalid_now",
        ),
        (
            cached_method,
            json!({"now": NOW, "ttl_seconds": 3600}),
            "invalid_scope",
        ),
    ] {
        match call(&connection, op, args) {
            Err(StoreError::Value(found)) => assert_eq!(found, code),
            other => panic!("expected {code}, got {other:?}"),
        }
    }
    assert_eq!(stored(&connection), None);
}
