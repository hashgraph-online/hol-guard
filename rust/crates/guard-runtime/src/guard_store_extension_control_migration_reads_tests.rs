use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::{dispatch, handles};
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

const METHODS: [&str; 3] = [
    "extension_control_migration_recorded",
    "extension_control_catalog_writer_version",
    "command_pack_baseline_retained",
];
const MIGRATED: &str = "extension_control_authority_catalog_migrated";

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection
        .execute_batch(
            "create table guard_events ( \
               event_id integer primary key autoincrement, event_name text, payload_json)",
        )
        .expect("events");
    connection
}

fn event(connection: &Connection, name: &str, payload: rusqlite::types::Value) {
    connection
        .execute(
            "insert into guard_events (event_name, payload_json) values (?1, ?2)",
            params![name, payload],
        )
        .expect("event");
}

fn migrated(connection: &Connection, payload: Value) {
    event(
        connection,
        MIGRATED,
        rusqlite::types::Value::Text(payload.to_string()),
    );
}

fn call(connection: &Connection, method: &str, args: Value) -> Value {
    let Value::Object(map) = args else {
        panic!("object args");
    };
    dispatch(connection, method, &Args(&map)).expect("read")
}

fn recorded(connection: &Connection, revision: i64) -> Value {
    call(
        connection,
        "extension_control_migration_recorded",
        json!({"revision": revision}),
    )
}

fn writer(connection: &Connection, digest: &str) -> Value {
    call(
        connection,
        "extension_control_catalog_writer_version",
        json!({"catalog_digest": digest}),
    )
}

fn baseline(connection: &Connection) -> Value {
    call(connection, "command_pack_baseline_retained", json!({}))
}

#[test]
fn every_read_is_routed_as_a_snapshot() {
    for method in METHODS {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Snapshot)));
    }
    assert!(!handles("extension_control_snapshot_head"));
}

#[test]
fn a_migration_is_recorded_once_an_event_names_its_revision() {
    let connection = store();
    assert_eq!(recorded(&connection, 4), json!({"recorded": false}));
    migrated(&connection, json!({"revision": 3}));
    event(
        &connection,
        "other_event",
        rusqlite::types::Value::Text(json!({"revision": 4}).to_string()),
    );
    assert_eq!(recorded(&connection, 4), json!({"recorded": false}));
    migrated(&connection, json!({"revision": 4.0}));
    assert_eq!(recorded(&connection, 4), json!({"recorded": true}));
    assert_eq!(recorded(&connection, 3), json!({"recorded": true}));
}

#[test]
fn payloads_that_are_not_objects_are_skipped() {
    let connection = store();
    event(
        &connection,
        MIGRATED,
        rusqlite::types::Value::Text("{".into()),
    );
    event(
        &connection,
        MIGRATED,
        rusqlite::types::Value::Text("[4]".into()),
    );
    event(
        &connection,
        MIGRATED,
        rusqlite::types::Value::Blob(b"{}".to_vec()),
    );
    migrated(&connection, json!({"revision": "4"}));
    migrated(&connection, json!({"revision": true}));
    assert_eq!(recorded(&connection, 4), json!({"recorded": false}));
    assert_eq!(recorded(&connection, 1), json!({"recorded": false}));
    assert_eq!(writer(&connection, "cat"), json!({"writer_version": null}));
}

#[test]
fn the_writer_is_the_newest_event_for_the_catalog_that_names_one() {
    let connection = store();
    migrated(
        &connection,
        json!({"catalog_digest": "cat", "provenance": {"writer_version": "1.0"}}),
    );
    migrated(
        &connection,
        json!({"catalog_digest": "cat", "provenance": {"writer_version": "1.1"}}),
    );
    migrated(
        &connection,
        json!({"catalog_digest": "other", "provenance": {"writer_version": "9.9"}}),
    );
    migrated(
        &connection,
        json!({"catalog_digest": "cat", "provenance": {"writer_version": ""}}),
    );
    migrated(
        &connection,
        json!({"catalog_digest": "cat", "provenance": "x"}),
    );
    migrated(&connection, json!({"catalog_digest": "cat"}));
    assert_eq!(writer(&connection, "cat"), json!({"writer_version": "1.1"}));
    assert_eq!(writer(&connection, "none"), json!({"writer_version": null}));
}

#[test]
fn the_writer_lookup_reads_only_the_newest_events() {
    let connection = store();
    migrated(
        &connection,
        json!({"catalog_digest": "cat", "provenance": {"writer_version": "1.0"}}),
    );
    for _ in 0..512 {
        migrated(&connection, json!({"catalog_digest": "other"}));
    }
    assert_eq!(writer(&connection, "cat"), json!({"writer_version": null}));
}

#[test]
fn a_store_without_events_has_no_migrations() {
    let connection = Connection::open_in_memory().expect("memory store");
    assert_eq!(recorded(&connection, 1), json!({"recorded": false}));
    assert_eq!(writer(&connection, "cat"), json!({"writer_version": null}));
}

#[test]
fn the_baseline_is_retained_only_by_a_pack_schema_with_a_slot() {
    let connection = store();
    assert_eq!(baseline(&connection), json!({"state": "schema_missing"}));
    connection
        .execute_batch(
            "create table extension_control_schema_migration ( \
               singleton integer primary key, version, checksum)",
        )
        .expect("marker table");
    assert_eq!(
        baseline(&connection),
        json!({"state": "present", "retained": false})
    );
    connection
        .execute(
            "insert into extension_control_schema_migration values (1, 4, 'c')",
            [],
        )
        .expect("marker");
    assert_eq!(
        baseline(&connection),
        json!({"state": "present", "retained": false})
    );
    connection
        .execute(
            "update extension_control_schema_migration set version = 5",
            [],
        )
        .expect("pack marker");
    assert_eq!(baseline(&connection), json!({"state": "schema_missing"}));
    connection
        .execute_batch("create table extension_command_pack_activation (singleton integer)")
        .expect("slot table");
    assert_eq!(
        baseline(&connection),
        json!({"state": "present", "retained": false})
    );
    connection
        .execute(
            "insert into extension_command_pack_activation values (1)",
            [],
        )
        .expect("slot");
    for version in ["6", "'6'"] {
        connection
            .execute_batch(&format!(
                "update extension_control_schema_migration set version = {version}"
            ))
            .expect("marker version");
        let retained = version == "6";
        assert_eq!(
            baseline(&connection),
            json!({"state": "present", "retained": retained})
        );
    }
}

#[test]
fn the_args_each_read_needs_are_required() {
    let connection = store();
    for method in &METHODS[..2] {
        assert!(dispatch(&connection, method, &Args(&Map::new())).is_err());
    }
}
