//! The fleet posture settings, full-inventory request and last-sent rows.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-09-28T00:00:00+00:00";
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

fn put(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, ?3)",
            rusqlite::params![key, payload, BEFORE],
        )
        .unwrap();
}

fn row(connection: &Connection, key: &str) -> Option<(Value, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
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

fn state(connection: &Connection) -> Value {
    call(connection, state_method, json!({})).unwrap()
}

fn refusal(result: StoreResult<Value>) -> String {
    match result {
        Err(StoreError::Value(code)) => code,
        Err(StoreError::Invalid(code)) => code.to_owned(),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_empty_store_reports_nothing() {
    let connection = store();
    assert_eq!(
        state(&connection),
        json!({"opted_out": false, "full_inventory_requested": false, "last_sent": null})
    );
}

#[test]
fn only_an_explicit_false_opts_out() {
    let connection = store();
    for (payload, opted_out) in [
        (r#"{"enabled": false}"#, true),
        (r#"{"enabled": true}"#, false),
        (r#"{"enabled": 0}"#, false),
        (r#"{}"#, false),
        (r#"[false]"#, false),
        ("not json", false),
    ] {
        put(&connection, SETTINGS_KEY, payload);
        assert_eq!(
            state(&connection)["opted_out"],
            json!(opted_out),
            "{payload}"
        );
    }
}

#[test]
fn setting_reporting_writes_the_record_and_returns_it() {
    let connection = store();
    let answer = call(
        &connection,
        set_reporting_method,
        json!({"enabled": false, "now": NOW}),
    )
    .unwrap();
    let record = json!({"enabled": false, "updatedAt": NOW});
    assert_eq!(answer, json!({"record": record}));
    assert_eq!(
        row(&connection, SETTINGS_KEY),
        Some((record, NOW.to_owned()))
    );
    assert_eq!(state(&connection)["opted_out"], json!(true));
    call(
        &connection,
        set_reporting_method,
        json!({"enabled": true, "now": NOW}),
    )
    .unwrap();
    assert_eq!(state(&connection)["opted_out"], json!(false));
}

#[test]
fn a_full_inventory_request_counts_only_while_the_row_is_a_non_empty_object() {
    let connection = store();
    call(
        &connection,
        request_full_method,
        json!({"source": "cli", "now": NOW}),
    )
    .unwrap();
    assert_eq!(
        row(&connection, FORCE_FULL_KEY),
        Some((json!({"requestedAt": NOW, "source": "cli"}), NOW.to_owned()))
    );
    assert_eq!(state(&connection)["full_inventory_requested"], json!(true));
    for payload in ["{}", "[1]", "null"] {
        put(&connection, FORCE_FULL_KEY, payload);
        assert_eq!(
            state(&connection)["full_inventory_requested"],
            json!(false),
            "{payload}"
        );
    }
}

#[test]
fn the_last_sent_snapshot_reads_back_even_when_empty() {
    let connection = store();
    put(&connection, LAST_SENT_KEY, "{}");
    assert_eq!(state(&connection)["last_sent"], json!({}));
    put(&connection, LAST_SENT_KEY, r#"[{"items": {}}]"#);
    assert_eq!(state(&connection)["last_sent"], Value::Null);
}

#[test]
fn committing_an_advancing_report_clears_a_pending_request() {
    let connection = store();
    put(
        &connection,
        FORCE_FULL_KEY,
        r#"{"requestedAt": "x", "source": "cloud"}"#,
    );
    let next = json!({"items": {"a": "1"}, "sentAt": NOW});
    let answer = call(
        &connection,
        commit_sent_method,
        json!({"next_state": next, "advanced_inventory": true, "now": NOW}),
    )
    .unwrap();
    assert_eq!(answer, json!({"cleared_full_inventory_request": true}));
    assert_eq!(
        row(&connection, LAST_SENT_KEY),
        Some((next.clone(), NOW.to_owned()))
    );
    assert_eq!(
        row(&connection, FORCE_FULL_KEY),
        Some((json!({}), NOW.to_owned()))
    );
    assert_eq!(state(&connection)["last_sent"], next);
}

#[test]
fn committing_leaves_the_request_alone_unless_the_inventory_advanced() {
    let connection = store();
    let request = json!({"requestedAt": "x", "source": "cloud"});
    put(&connection, FORCE_FULL_KEY, &request.to_string());
    let answer = call(
        &connection,
        commit_sent_method,
        json!({"next_state": {"items": {}}, "advanced_inventory": false, "now": NOW}),
    )
    .unwrap();
    assert_eq!(answer, json!({"cleared_full_inventory_request": false}));
    assert_eq!(
        row(&connection, FORCE_FULL_KEY),
        Some((request, BEFORE.to_owned()))
    );
}

#[test]
fn committing_without_a_pending_request_writes_no_request_row() {
    let connection = store();
    let answer = call(
        &connection,
        commit_sent_method,
        json!({"next_state": {"items": {}}, "advanced_inventory": true, "now": NOW}),
    )
    .unwrap();
    assert_eq!(answer, json!({"cleared_full_inventory_request": false}));
    assert_eq!(row(&connection, FORCE_FULL_KEY), None);
}

#[test]
fn malformed_inputs_are_refused_without_a_write() {
    let connection = store();
    for (op, args, code) in [
        (
            set_reporting_method as fn(&Connection, &Args<'_>) -> StoreResult<Value>,
            json!({"enabled": "no", "now": NOW}),
            "invalid_enabled",
        ),
        (set_reporting_method, json!({"now": NOW}), "invalid_enabled"),
        (
            request_full_method,
            json!({"source": "", "now": NOW}),
            "invalid_source",
        ),
        (request_full_method, json!({"now": NOW}), "invalid_source"),
        (
            commit_sent_method,
            json!({"next_state": [1], "advanced_inventory": true, "now": NOW}),
            "invalid_next_state",
        ),
        (
            commit_sent_method,
            json!({"advanced_inventory": true, "now": NOW}),
            "invalid_next_state",
        ),
    ] {
        assert_eq!(refusal(call(&connection, op, args)), code);
    }
    assert_eq!(
        connection
            .query_row("select count(*) from sync_state", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
