//! The enrollment schedule row: binding, cooldown and recorded outcome.

use serde_json::json;

use super::*;
use crate::guard_store_db::StoreError;

const NOW: &str = "2026-09-28T00:00:00+00:00";
const NEXT: &str = "2026-09-28T00:05:00+00:00";
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
            rusqlite::params![STATE_KEY, payload.to_string(), BEFORE],
        )
        .unwrap();
}

fn row(connection: &Connection) -> Option<(Value, String)> {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = ?1",
            [STATE_KEY],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .ok()
        .map(|(payload, at)| (serde_json::from_str(&payload).unwrap(), at))
}

fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        unreachable!()
    };
    map
}

fn auth() -> Value {
    json!({"workspace_id": "workspace-1", "machine_installation_id": "installation-1",
        "sync_url": "https://guard.example.test"})
}

fn binding_value() -> Value {
    json!([
        "workspace-1",
        "installation-1",
        "https://guard.example.test"
    ])
}

fn check(connection: &Connection, auth: Value, now: &str) -> StoreResult<Value> {
    let args = object(json!({"auth": auth, "now": now}));
    due_method(connection, &Args(&args))
}

fn record(connection: &Connection, args: Value) -> StoreResult<Value> {
    let mut args = object(args);
    args.entry("now").or_insert(json!(NOW));
    args.entry("binding").or_insert(binding_value());
    record_method(connection, &Args(&args))
}

fn error_code(result: StoreResult<Value>) -> String {
    match result {
        Err(StoreError::Value(code)) => code,
        other => panic!("expected a value error, got {other:?}"),
    }
}

#[test]
fn an_empty_row_is_due_and_names_the_binding() {
    let connection = store();
    let answer = check(&connection, auth(), NOW).unwrap();
    assert_eq!(answer, json!({"binding": binding_value(), "due": true}));
}

#[test]
fn the_oauth_subject_joins_the_binding_and_a_bad_field_drops_it() {
    let connection = store();
    let mut with_subject = auth();
    with_subject["oauth_subject_hash"] = json!("subject-1");
    let answer = check(&connection, with_subject, NOW).unwrap();
    assert_eq!(answer["binding"][3], json!("subject-1"));
    let mut null_subject = auth();
    null_subject["oauth_subject_hash"] = Value::Null;
    assert_eq!(
        check(&connection, null_subject, NOW).unwrap()["binding"],
        binding_value()
    );
    for (field, value) in [
        ("oauth_subject_hash", json!("")),
        ("oauth_subject_hash", json!(7)),
        ("workspace_id", json!("")),
        ("sync_url", Value::Null),
        ("machine_installation_id", json!(["installation-1"])),
    ] {
        let mut broken = auth();
        broken[field] = value;
        let answer = check(&connection, broken, NOW).unwrap();
        assert_eq!(answer, json!({"binding": null, "due": false}), "{field}");
    }
}

#[test]
fn a_recorded_check_waits_one_interval_for_the_same_binding() {
    let connection = store();
    let state = record(&connection, json!({"outcome": "enrolled", "record": "{}"})).unwrap();
    let digest = hex::encode(Sha256::digest(b"{}"));
    let expected = json!({"binding": binding_value(), "next_check_at": NEXT,
        "record_digest": digest, "status": "enrolled"});
    assert_eq!(state["state"], expected);
    assert_eq!(row(&connection), Some((expected, NOW.to_owned())));
    assert_eq!(
        check(&connection, auth(), "2026-09-28T00:01:00+00:00").unwrap()["due"],
        json!(false)
    );
    assert_eq!(
        check(&connection, auth(), NEXT).unwrap()["due"],
        json!(true)
    );
    let mut other = auth();
    other["workspace_id"] = json!("workspace-2");
    assert_eq!(
        check(&connection, other, "2026-09-28T00:01:00+00:00").unwrap()["due"],
        json!(true)
    );
}

#[test]
fn an_unreadable_naive_or_far_schedule_is_due() {
    let connection = store();
    for next in [
        json!("soon"),
        json!("2026-09-28T00:03:00"),
        json!(7),
        json!("2026-09-28T00:05:01+00:00"),
    ] {
        put(
            &connection,
            &json!({"binding": binding_value(), "next_check_at": next}),
        );
        assert_eq!(
            check(&connection, auth(), NOW).unwrap()["due"],
            json!(true),
            "{next}"
        );
    }
    put(
        &connection,
        &json!({"binding": binding_value(), "next_check_at": NEXT}),
    );
    assert_eq!(
        check(&connection, auth(), NOW).unwrap()["due"],
        json!(false)
    );
    put(&connection, &json!(["not", "an", "object"]));
    assert_eq!(check(&connection, auth(), NOW).unwrap()["due"], json!(true));
}

#[test]
fn a_schedule_under_another_offset_compares_as_the_same_instant() {
    let connection = store();
    put(
        &connection,
        &json!({"binding": binding_value(),
        "next_check_at": "2026-09-28T02:04:00+02:00"}),
    );
    assert_eq!(
        check(&connection, auth(), NOW).unwrap()["due"],
        json!(false)
    );
    assert_eq!(
        check(&connection, auth(), "2026-09-28T00:04:00Z").unwrap()["due"],
        json!(true)
    );
}

#[test]
fn an_unavailable_check_records_the_http_status_or_the_failure_code() {
    let connection = store();
    let state = record(
        &connection,
        json!({"outcome": "unavailable", "http_status": 503}),
    )
    .unwrap();
    assert_eq!(state["state"]["status"], json!("unavailable"));
    assert_eq!(state["state"]["http_status"], json!(503));
    assert!(state["state"].get("record_digest").is_none());
    let coded = record(
        &connection,
        json!({"outcome": "unavailable",
        "error_code": "native_workspace_review_state_unavailable", "error_type": "ValueError"}),
    )
    .unwrap();
    assert_eq!(
        coded["state"]["error_code"],
        json!("native_workspace_review_state_unavailable")
    );
    for code in [json!("permission denied"), Value::Null, json!("")] {
        let typed = record(
            &connection,
            json!({"outcome": "unavailable",
            "error_code": code, "error_type": "OSError"}),
        )
        .unwrap();
        assert_eq!(typed["state"]["error_code"], json!("OSError"));
    }
    assert_eq!(row(&connection).unwrap().0["error_code"], json!("OSError"));
}

#[test]
fn a_microsecond_now_keeps_python_isoformat() {
    let connection = store();
    let state = record(
        &connection,
        json!({"outcome": "unavailable", "http_status": 500,
        "now": "2026-09-28T00:00:00.250000+00:00"}),
    )
    .unwrap();
    assert_eq!(
        state["state"]["next_check_at"],
        json!("2026-09-28T00:05:00.250000+00:00")
    );
}

#[test]
fn bad_inputs_fail_without_a_write() {
    let connection = store();
    for (args, code) in [
        (json!({"outcome": "unknown"}), "invalid_outcome"),
        (
            json!({"outcome": "unavailable", "http_status": "503"}),
            "invalid_outcome",
        ),
        (
            json!({"outcome": "unavailable", "error_type": ""}),
            "invalid_outcome",
        ),
        (
            json!({"outcome": "enrolled", "record": "{}", "binding": ["a", "b"]}),
            "invalid_binding",
        ),
        (
            json!({"outcome": "enrolled", "record": "{}", "binding": ["a", "", "c"]}),
            "invalid_binding",
        ),
        (
            json!({"outcome": "enrolled", "record": "{}", "now": "2026-09-28T00:00:00"}),
            "invalid_now",
        ),
    ] {
        assert_eq!(
            error_code(record(&connection, args.clone())),
            code,
            "{args}"
        );
    }
    assert!(matches!(
        record(&connection, json!({"outcome": "enrolled"})),
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(row(&connection), None);
    assert_eq!(
        error_code(check(&connection, auth(), "later")),
        "invalid_now"
    );
}
