use super::*;
use rusqlite::{params, Connection};
use serde_json::Map;

use crate::guard_store_cloud_events::list_log;
use crate::guard_store_db::StoreError;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_events (
               event_id integer primary key autoincrement, event_name text not null,
               payload_json text not null, occurred_at text not null);",
        )
        .unwrap();
    connection
}

fn log(connection: &Connection, name: &str, payload_json: &str, occurred_at: &str) {
    connection
        .execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
            params![name, payload_json, occurred_at],
        )
        .unwrap();
}

fn call(connection: &Connection, method: &str, args: Value) -> StoreResult<Value> {
    let map: Map<String, Value> = args.as_object().cloned().unwrap();
    list_log(connection, method, &Args(&map))
}

fn ids(page: &Value) -> Vec<i64> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["event_id"].as_i64().unwrap())
        .collect()
}

#[test]
fn events_read_newest_first_with_their_stored_payload_text() {
    let connection = store();
    log(
        &connection,
        "a",
        "{\"z\": 1, \"a\": 2}",
        "2026-01-01T00:00:00Z",
    );
    log(&connection, "b", "[]", "2026-01-02T00:00:00Z");
    log(&connection, "c", "{}", "2026-01-02T00:00:00Z");
    let page = call(&connection, "list_events", json!({"limit": 10})).unwrap();
    assert_eq!(ids(&page), vec![3, 2, 1]);
    assert_eq!(page["more"], false);
    assert_eq!(page["items"][2]["payload_json"], "{\"z\": 1, \"a\": 2}");
    assert_eq!(page["items"][2]["event_name"], "a");
    assert_eq!(page["items"][2]["occurred_at"], "2026-01-01T00:00:00Z");
}

#[test]
fn the_limit_and_the_event_name_narrow_the_read() {
    let connection = store();
    for (name, at) in [("a", "t1"), ("b", "t2"), ("a", "t3"), ("a", "t4")] {
        log(&connection, name, "{}", at);
    }
    let page = call(
        &connection,
        "list_events",
        json!({"limit": 2, "event_name": "a"}),
    )
    .unwrap();
    assert_eq!(ids(&page), vec![4, 3]);
    assert_eq!(page["more"], false);
}

#[test]
fn a_page_stops_at_its_payload_budget_and_the_cursor_continues() {
    let connection = store();
    let big = format!("\"{}\"", "x".repeat(PAGE_PAYLOAD_BYTES / 2));
    for at in ["t1", "t2", "t3"] {
        log(&connection, "a", &big, at);
    }
    let first = call(&connection, "list_events", json!({"limit": 10})).unwrap();
    assert_eq!(ids(&first), vec![3]);
    assert_eq!(first["more"], true);
    log(&connection, "a", "{}", "t9");
    let second = call(
        &connection,
        "list_events",
        json!({"limit": 9, "before": {"occurred_at": "t3", "event_id": 3}}),
    )
    .unwrap();
    assert_eq!(ids(&second), vec![2]);
    assert_eq!(second["more"], true);
    let third = call(
        &connection,
        "list_events",
        json!({"limit": 8, "before": {"occurred_at": "t2", "event_id": 2}}),
    )
    .unwrap();
    assert_eq!(ids(&third), vec![1]);
    assert_eq!(third["more"], false);
}

#[test]
fn one_event_larger_than_the_budget_is_still_read() {
    let connection = store();
    log(&connection, "a", &"y".repeat(PAGE_PAYLOAD_BYTES + 1), "t1");
    let page = call(&connection, "list_events", json!({"limit": 1})).unwrap();
    assert_eq!(ids(&page), vec![1]);
    assert_eq!(page["more"], false);
}

#[test]
fn a_payload_too_large_for_one_reply_reads_as_an_empty_object() {
    let connection = store();
    log(&connection, "a", "{\"k\": 1}", "t1");
    log(&connection, "a", &"q".repeat(ROW_PAYLOAD_BYTES), "t2");
    let page = call(&connection, "list_events", json!({"limit": 10})).unwrap();
    assert_eq!(ids(&page), vec![2, 1]);
    assert_eq!(page["items"][0]["payload_json"], "{}");
    assert_eq!(page["items"][1]["payload_json"], "{\"k\": 1}");
}

#[test]
fn the_page_budget_counts_the_escaped_payload_text() {
    let connection = store();
    // Each quote doubles once escaped, so two of these fill a page.
    let quoted = "\"".repeat(PAGE_PAYLOAD_BYTES / 3);
    log(&connection, "a", &quoted, "t1");
    log(&connection, "a", &quoted, "t2");
    let page = call(&connection, "list_events", json!({"limit": 10})).unwrap();
    assert_eq!(ids(&page), vec![2]);
    assert_eq!(page["more"], true);
}

#[test]
fn a_page_after_an_id_reads_oldest_first_and_continues_from_the_last_id() {
    let connection = store();
    let big = format!("\"{}\"", "x".repeat(PAGE_PAYLOAD_BYTES / 2));
    for (name, at) in [("a", "t1"), ("b", "t2"), ("a", "t3"), ("a", "t4")] {
        log(&connection, name, &big, at);
    }
    let first = call(
        &connection,
        "list_events",
        json!({"limit": 10, "after_event_id": 0, "event_names": ["a"]}),
    )
    .unwrap();
    assert_eq!(ids(&first), vec![1]);
    assert_eq!(first["more"], true);
    let second = call(
        &connection,
        "list_events",
        json!({"limit": 1, "after_event_id": 1, "event_names": ["a"]}),
    )
    .unwrap();
    assert_eq!(ids(&second), vec![3]);
    assert_eq!(second["more"], false);
}

#[test]
fn a_page_names_one_cursor_and_a_whole_number_id() {
    let connection = store();
    for args in [
        json!({"limit": 1, "after_event_id": 0, "before": {"occurred_at": "t", "event_id": 1}}),
        json!({"limit": 1, "after_event_id": "0"}),
        json!({"limit": 1, "after_event_id": true}),
    ] {
        assert!(matches!(
            call(&connection, "list_events", args),
            Err(StoreError::Value(_))
        ));
    }
}

#[test]
fn a_cursor_without_both_parts_is_refused() {
    let connection = store();
    assert!(matches!(
        call(
            &connection,
            "list_events",
            json!({"limit": 1, "before": {"occurred_at": "t1"}}),
        ),
        Err(StoreError::Value(_))
    ));
    assert!(call(
        &connection,
        "list_events",
        json!({"limit": 1, "event_name": null})
    )
    .is_err());
}

#[test]
fn events_after_an_id_can_be_limited_to_named_events() {
    let connection = store();
    for (name, at) in [("a", "t1"), ("b", "t2"), ("c", "t3"), ("b", "t4")] {
        log(&connection, name, "{\"k\": 1}", at);
    }
    let named = call(
        &connection,
        "list_events_after",
        json!({"event_id": 1, "limit": 10, "event_names": ["b", "c"]}),
    )
    .unwrap();
    let named_ids: Vec<i64> = named
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["event_id"].as_i64().unwrap())
        .collect();
    assert_eq!(named_ids, vec![2, 3, 4]);
    assert_eq!(named[0]["payload"], json!({"k": 1}));
    let every = call(
        &connection,
        "list_events_after",
        json!({"event_id": 0, "limit": 2, "event_names": []}),
    )
    .unwrap();
    assert_eq!(every.as_array().unwrap().len(), 2);
}

#[test]
fn the_event_log_reads_are_read_transactions() {
    for method in ["list_events", "list_events_after"] {
        assert!(matches!(
            crate::guard_store_op_kind::method_kind(method),
            Some(crate::guard_store_op_kind::Kind::Read)
        ));
    }
}
