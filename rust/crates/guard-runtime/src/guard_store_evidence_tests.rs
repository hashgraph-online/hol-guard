//! The evidence log answers as `store_evidence.py` did: newest first, the
//! same filters, details only when asked for, and a read that stops at its
//! byte budget says more rows remain.

use super::*;
use rusqlite::Connection;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_evidence (
               evidence_id text not null primary key,
               action_id text not null default '', request_id text not null default '',
               harness text not null default '', workspace text not null default '',
               signal_id text not null default '', category text not null default '',
               severity text not null default '', confidence real not null default 0.0,
               summary text not null default '', details_json text not null default '{}',
               action_identity text, created_at text not null);",
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

fn record(id: &str, created_at: &str, harness: &str, details_json: &str) -> Value {
    json!({
        "evidence_id": id,
        "action_id": format!("action-{id}"),
        "request_id": "req-1",
        "harness": harness,
        "workspace": "/work",
        "signal_id": "signal",
        "category": "secrets",
        "severity": "high",
        "confidence": 1,
        "summary": "found",
        "details_json": details_json,
        "action_identity": null,
        "created_at": created_at,
    })
}

fn ids(page: &Value) -> Vec<&str> {
    page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["evidence_id"].as_str().unwrap())
        .collect()
}

#[test]
fn records_list_newest_first_with_details_only_when_asked() {
    let connection = store();
    call(
        &connection,
        add,
        record("ev-1", "t1", "codex", "{\"z\": 1, \"a\": 2}"),
    )
    .unwrap();
    call(&connection, add, record("ev-2", "t2", "cursor", "{}")).unwrap();
    let page = call(
        &connection,
        list,
        json!({"limit": 10, "include_details": true}),
    )
    .unwrap();
    assert_eq!(ids(&page), vec!["ev-2", "ev-1"]);
    assert_eq!(page["more"], json!(false));
    assert_eq!(
        page["rows"][1]["details_json"],
        json!("{\"z\": 1, \"a\": 2}")
    );
    assert_eq!(page["rows"][1]["confidence"], json!(1.0));
    assert_eq!(page["rows"][1]["action_identity"], Value::Null);
    let summary = call(&connection, list, json!({"limit": 10})).unwrap();
    assert!(summary["rows"][0].get("details_json").is_none());
}

#[test]
fn the_same_id_replaces_its_record() {
    let connection = store();
    call(&connection, add, record("ev-1", "t1", "codex", "{}")).unwrap();
    call(&connection, add, record("ev-1", "t2", "cursor", "{}")).unwrap();
    assert_eq!(call(&connection, count, json!({})).unwrap(), json!(1));
    let page = call(&connection, list, json!({"limit": 10})).unwrap();
    assert_eq!(page["rows"][0]["harness"], json!("cursor"));
}

#[test]
fn filters_narrow_both_the_list_and_the_count() {
    let connection = store();
    call(&connection, add, record("ev-1", "t1", "codex", "{}")).unwrap();
    call(&connection, add, record("ev-2", "t2", "cursor", "{}")).unwrap();
    call(&connection, add, record("ev-3", "t3", "codex", "{}")).unwrap();
    let codex = call(&connection, list, json!({"limit": 10, "harness": "codex"})).unwrap();
    assert_eq!(ids(&codex), vec!["ev-3", "ev-1"]);
    let before = call(
        &connection,
        list,
        json!({"limit": 10, "harness": "codex", "before_cursor": "t3"}),
    )
    .unwrap();
    assert_eq!(ids(&before), vec!["ev-1"]);
    let offset = call(&connection, list, json!({"limit": 1, "offset": 1})).unwrap();
    assert_eq!(ids(&offset), vec!["ev-2"]);
    assert_eq!(
        call(&connection, count, json!({"harness": "codex"})).unwrap(),
        json!(2)
    );
    assert_eq!(
        call(
            &connection,
            count,
            json!({"harness": "codex", "severity": "low"})
        )
        .unwrap(),
        json!(0)
    );
}

#[test]
fn a_read_stops_at_its_byte_budget_and_says_more_remain() {
    let connection = store();
    let details = format!("{{\"pad\": \"{}\"}}", "x".repeat(READ_BYTES_BUDGET / 3));
    for (id, at) in [("ev-1", "t1"), ("ev-2", "t2"), ("ev-3", "t3")] {
        call(&connection, add, record(id, at, "codex", &details)).unwrap();
    }
    let args = json!({"limit": 10, "include_details": true});
    let first = call(&connection, list, args).unwrap();
    assert_eq!(ids(&first), vec!["ev-3", "ev-2"]);
    assert_eq!(first["more"], json!(true));
    let rest = call(
        &connection,
        list,
        json!({"limit": 8, "offset": 2, "include_details": true}),
    )
    .unwrap();
    assert_eq!(ids(&rest), vec!["ev-1"]);
    assert_eq!(rest["more"], json!(false));
}

#[test]
fn one_record_larger_than_the_budget_is_still_read() {
    let connection = store();
    let details = format!("{{\"pad\": \"{}\"}}", "x".repeat(READ_BYTES_BUDGET));
    call(&connection, add, record("ev-1", "t1", "codex", &details)).unwrap();
    let page = call(
        &connection,
        list,
        json!({"limit": 10, "include_details": true}),
    )
    .unwrap();
    assert_eq!(ids(&page), vec!["ev-1"]);
    assert_eq!(page["more"], json!(false));
}

#[test]
fn clearing_reports_how_many_records_it_removed() {
    let connection = store();
    call(&connection, add, record("ev-1", "t1", "codex", "{}")).unwrap();
    call(&connection, add, record("ev-2", "t2", "codex", "{}")).unwrap();
    assert_eq!(call(&connection, clear, json!({})).unwrap(), json!(2));
    assert_eq!(call(&connection, count, json!({})).unwrap(), json!(0));
}

#[test]
fn a_record_without_a_numeric_confidence_is_refused() {
    let connection = store();
    let mut bad = record("ev-1", "t1", "codex", "{}");
    bad["confidence"] = json!("high");
    assert!(matches!(
        call(&connection, add, bad),
        Err(StoreError::Invalid("native_guard_store_args_invalid"))
    ));
}
