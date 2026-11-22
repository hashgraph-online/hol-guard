use rusqlite::{params, Connection};
use serde_json::json;

use super::{dispatch, handles};
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    Connection::open_in_memory().expect("memory store")
}

fn snapshot_table(connection: &Connection) {
    connection
        .execute_batch(
            "create table extension_control_authority_snapshot ( \
               singleton integer primary key check (singleton = 1), \
               revision integer not null, layers_json, snapshot_digest text not null);",
        )
        .expect("schema");
}

#[test]
fn the_snapshot_read_is_routed_as_a_snapshot() {
    assert!(handles("extension_control_snapshot_layers"));
    assert!(!handles("extension_control_schema_state"));
    assert!(matches!(
        method_kind("extension_control_snapshot_layers"),
        Some(Kind::Snapshot)
    ));
}

#[test]
fn a_store_without_the_snapshot_table_has_no_snapshot() {
    assert_eq!(dispatch(&store()).expect("read"), json!({"snapshot": null}));
}

#[test]
fn an_empty_snapshot_table_has_no_snapshot() {
    let connection = store();
    snapshot_table(&connection);
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"snapshot": null})
    );
}

#[test]
fn the_committed_layers_come_back_as_stored() {
    let connection = store();
    snapshot_table(&connection);
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, 4, ?1, ?2)",
            params!["[{\"controls\":[]}]", "d".repeat(64)],
        )
        .expect("row");
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"snapshot": {"layers_json": "[{\"controls\":[]}]"}})
    );
}

#[test]
fn a_non_text_layers_cell_reads_as_null_inside_a_present_snapshot() {
    let connection = store();
    snapshot_table(&connection);
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, 4, ?1, ?2)",
            params![vec![0_u8, 1, 2], "d".repeat(64)],
        )
        .expect("row");
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"snapshot": {"layers_json": null}})
    );
}
