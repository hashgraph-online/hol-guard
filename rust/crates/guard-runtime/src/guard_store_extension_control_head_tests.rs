use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::{dispatch, handles};
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

const METHODS: [&str; 3] = [
    "extension_control_snapshot_head",
    "extension_control_recovery_transition",
    "extension_control_transition_committed",
];

fn store() -> Connection {
    Connection::open_in_memory().expect("memory store")
}

fn schema(connection: &Connection) {
    connection
        .execute_batch(
            "create table extension_control_authority_snapshot ( \
               singleton integer primary key, revision, catalog_digest, snapshot_digest); \
             create table extension_control_authority_transition ( \
               revision integer primary key, phase text not null);",
        )
        .expect("schema");
}

fn transition(connection: &Connection, revision: i64, phase: &str) {
    connection
        .execute(
            "insert into extension_control_authority_transition values (?1, ?2)",
            params![revision, phase],
        )
        .expect("transition");
}

fn call(connection: &Connection, method: &str, args: Value) -> Value {
    let Value::Object(map) = args else {
        panic!("object args");
    };
    dispatch(connection, method, &Args(&map)).expect("read")
}

fn head(connection: &Connection) -> Value {
    call(connection, "extension_control_snapshot_head", json!({}))
}

fn recovery(connection: &Connection, revision: i64) -> Value {
    call(
        connection,
        "extension_control_recovery_transition",
        json!({"revision": revision}),
    )
}

fn committed(connection: &Connection, revision: i64) -> Value {
    call(
        connection,
        "extension_control_transition_committed",
        json!({"revision": revision}),
    )
}

#[test]
fn every_read_is_routed_as_a_snapshot() {
    for method in METHODS {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Snapshot)));
    }
    assert!(!handles("extension_control_snapshot_layers"));
}

#[test]
fn a_store_without_tables_has_no_head_and_no_transitions() {
    let connection = store();
    assert_eq!(head(&connection), json!({"snapshot": null}));
    assert_eq!(recovery(&connection, 3), json!({"revision": null}));
    assert_eq!(committed(&connection, 3), json!({"committed": false}));
}

#[test]
fn an_empty_snapshot_table_has_no_head() {
    let connection = store();
    schema(&connection);
    assert_eq!(head(&connection), json!({"snapshot": null}));
}

#[test]
fn the_head_comes_back_as_stored() {
    let connection = store();
    schema(&connection);
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, 4, 'cat', 'snap')",
            [],
        )
        .expect("snapshot");
    assert_eq!(
        head(&connection),
        json!({"snapshot": {"revision": 4, "snapshot_digest": "snap", "catalog_digest": "cat"}})
    );
}

#[test]
fn cells_of_the_wrong_type_read_as_null() {
    let connection = store();
    schema(&connection);
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, '4', ?1, 7)",
            params![b"cat".to_vec()],
        )
        .expect("snapshot");
    assert_eq!(
        head(&connection),
        json!({"snapshot": {"revision": null, "snapshot_digest": null, "catalog_digest": null}})
    );
}

#[test]
fn an_uncommitted_head_transition_is_resumed_first() {
    let connection = store();
    schema(&connection);
    transition(&connection, 4, "anchored");
    transition(&connection, 5, "prepared");
    assert_eq!(recovery(&connection, 4), json!({"revision": 4}));
}

#[test]
fn a_committed_head_resumes_the_next_transition() {
    let connection = store();
    schema(&connection);
    transition(&connection, 4, "committed");
    transition(&connection, 5, "prepared");
    assert_eq!(recovery(&connection, 4), json!({"revision": 5}));
}

#[test]
fn nothing_to_resume_past_a_committed_head() {
    let connection = store();
    schema(&connection);
    transition(&connection, 3, "prepared");
    transition(&connection, 4, "committed");
    transition(&connection, 6, "prepared");
    assert_eq!(recovery(&connection, 4), json!({"revision": null}));
}

#[test]
fn the_committed_check_reads_the_phase() {
    let connection = store();
    schema(&connection);
    transition(&connection, 4, "committed");
    transition(&connection, 5, "anchored");
    assert_eq!(committed(&connection, 4), json!({"committed": true}));
    assert_eq!(committed(&connection, 5), json!({"committed": false}));
    assert_eq!(committed(&connection, 6), json!({"committed": false}));
}

#[test]
fn a_revision_argument_is_required() {
    for method in &METHODS[1..] {
        assert!(dispatch(&store(), method, &Args(&Map::new())).is_err());
    }
}
