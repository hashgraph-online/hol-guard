use super::*;
use serde_json::Map;

use crate::guard_store_op_kind::{method_kind, Kind};

fn store(events: &[Value]) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_events (event_id integer primary key autoincrement, \
             event_name text not null, payload_json text not null, occurred_at text not null);",
        )
        .unwrap();
    for event in events {
        let (name, payload) = match event {
            Value::String(raw) => (MIGRATED_EVENT, raw.clone()),
            other => (MIGRATED_EVENT, other.to_string()),
        };
        connection
            .execute(
                "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, 't')",
                (name, payload),
            )
            .unwrap();
    }
    connection
}

fn writer(connection: &Connection, digest: &str) -> Value {
    let mut map = Map::new();
    map.insert("catalog_digest".into(), Value::from(digest));
    dispatch(connection, &Args(&map)).unwrap()["writer_version"].clone()
}

#[test]
fn the_method_is_a_routed_read() {
    assert!(handles("catalog_recorded_writer_version"));
    assert!(!handles("catalog_recorded_writer"));
    assert!(matches!(
        method_kind("catalog_recorded_writer_version"),
        Some(Kind::Read)
    ));
}

#[test]
fn an_empty_store_names_no_writer() {
    assert_eq!(writer(&store(&[]), "catalog-x"), Value::Null);
}

#[test]
fn a_backfill_over_an_attributed_revision_keeps_the_writer() {
    let connection = store(&[
        json!({"revision": 4, "catalog_digest": "catalog-x", "provenance": {"writer_version": "3.47.0"}}),
        json!({"revision": 5, "catalog_digest": "catalog-y", "provenance": {"writer_version": "3.48.0"}}),
        json!({"revision": 6, "catalog_digest": "catalog-x", "provenance": {"trigger": "authority-read-backfill"}}),
    ]);
    assert_eq!(writer(&connection, "catalog-x"), json!("3.47.0"));
    assert_eq!(writer(&connection, "catalog-y"), json!("3.48.0"));
    assert_eq!(writer(&connection, "catalog-z"), Value::Null);
}

#[test]
fn the_newest_attributed_event_wins() {
    let connection = store(&[
        json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": "3.40.0"}}),
        json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": "3.47.0"}}),
    ]);
    assert_eq!(writer(&connection, "catalog-x"), json!("3.47.0"));
}

#[test]
fn malformed_and_blank_events_are_skipped() {
    let connection = store(&[
        json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": "3.41.0"}}),
        Value::from("not json"),
        Value::from("[1, 2]"),
        json!({"catalog_digest": "catalog-x", "provenance": "3.50.0"}),
        json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": ""}}),
        json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": 7}}),
        json!({"catalog_digest": 1, "provenance": {"writer_version": "3.52.0"}}),
    ]);
    assert_eq!(writer(&connection, "catalog-x"), json!("3.41.0"));
}

#[test]
fn other_event_names_are_ignored() {
    let connection = store(&[]);
    connection
        .execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?, ?, 't')",
            (
                "extension_control_authority_catalog_regressed",
                json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": "3.47.0"}})
                    .to_string(),
            ),
        )
        .unwrap();
    assert_eq!(writer(&connection, "catalog-x"), Value::Null);
}

#[test]
fn the_scan_stops_at_the_newest_512_migrations() {
    let mut events =
        vec![json!({"catalog_digest": "catalog-x", "provenance": {"writer_version": "3.30.0"}})];
    events.extend(
        (0..WRITER_LOOKUP_LIMIT)
            .map(|revision| json!({"revision": revision, "catalog_digest": "catalog-y"})),
    );
    assert_eq!(writer(&store(&events), "catalog-x"), Value::Null);
    events.pop();
    assert_eq!(writer(&store(&events), "catalog-x"), json!("3.30.0"));
}

#[test]
fn a_missing_digest_is_refused() {
    let map = Map::new();
    assert!(dispatch(&store(&[]), &Args(&map)).is_err());
}
