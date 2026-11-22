use rusqlite::{params, Connection};
use serde_json::json;

use sha2::{Digest, Sha256};

use super::{dispatch, handles, read};
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    Connection::open_in_memory().expect("memory store")
}

fn mark(connection: &Connection, version: i64, checksum: &str) {
    connection
        .execute_batch(
            "create table extension_control_schema_migration ( \
               singleton integer primary key check (singleton = 1), \
               version integer not null, checksum text not null); \
             create table extension_command_pack_activation ( \
               singleton integer primary key check (singleton = 1), \
               revision integer not null check (revision >= 0), \
               record_json text not null, record_digest text not null, \
               record_mac text not null, recorded_at text not null);",
        )
        .expect("schema");
    connection
        .execute(
            "insert into extension_control_schema_migration values (1, ?1, ?2)",
            params![version, checksum],
        )
        .expect("marker");
}

fn slot(connection: &Connection, record: &str, digest: &str) {
    connection
        .execute(
            "insert into extension_command_pack_activation values (1, 3, ?1, ?2, ?3, 'now')",
            params![record, digest, "m".repeat(64)],
        )
        .expect("slot");
}

#[test]
fn the_read_is_routed_as_a_snapshot() {
    assert!(handles("read_command_pack_activation"));
    assert!(matches!(
        method_kind("read_command_pack_activation"),
        Some(Kind::Snapshot)
    ));
}

fn schema_state(connection: &Connection) -> serde_json::Value {
    dispatch(
        connection,
        "extension_control_schema_state",
        &Args(&serde_json::Map::new()),
    )
    .expect("schema state")
}

#[test]
fn the_schema_state_names_missing_compatible_and_incompatible_markers() {
    assert!(handles("extension_control_schema_state"));
    assert!(matches!(
        method_kind("extension_control_schema_state"),
        Some(Kind::Snapshot)
    ));
    let connection = store();
    assert_eq!(schema_state(&connection), json!({"state": "missing"}));
    mark(&connection, 6, &schema_checksum(6));
    // The marker alone is not the schema: the snapshot table must be there too.
    assert_eq!(schema_state(&connection), json!({"state": "missing"}));
    connection
        .execute_batch("create table extension_control_authority_snapshot (singleton integer)")
        .expect("snapshot table");
    assert_eq!(schema_state(&connection), json!({"state": "compatible"}));
    for (version, checksum) in [(5, schema_checksum(4)), (7, schema_checksum(7))] {
        connection
            .execute(
                "update extension_control_schema_migration set version = ?1, checksum = ?2",
                params![version, checksum],
            )
            .expect("marker");
        assert_eq!(schema_state(&connection), json!({"state": "incompatible"}));
    }
    connection
        .execute("delete from extension_control_schema_migration", [])
        .expect("clear marker");
    assert_eq!(schema_state(&connection), json!({"state": "missing"}));
}

#[test]
fn a_store_without_the_pack_schema_has_no_slot() {
    let connection = store();
    assert_eq!(read(&connection).expect("read"), json!({"state": "absent"}));
    mark(&connection, 4, &schema_checksum(4));
    assert_eq!(read(&connection).expect("read"), json!({"state": "absent"}));
}

#[test]
fn an_unknown_or_forged_marker_is_invalid() {
    for (version, checksum) in [
        (5, schema_checksum(4)),
        (7, schema_checksum(7)),
        (0, schema_checksum(0)),
    ] {
        let connection = store();
        mark(&connection, version, &checksum);
        assert_eq!(
            read(&connection).expect("read"),
            json!({"state": "refused", "code": "native_command_pack_schema_invalid"}),
            "{version}"
        );
    }
    let empty = store();
    mark(&empty, 5, &schema_checksum(5));
    empty
        .execute_batch("delete from extension_control_schema_migration")
        .expect("clear");
    assert_eq!(
        read(&empty).expect("read"),
        json!({"state": "refused", "code": "native_command_pack_schema_invalid"})
    );
}

#[test]
fn an_empty_or_malformed_slot_is_missing() {
    let connection = store();
    mark(&connection, 6, &schema_checksum(6));
    assert_eq!(
        read(&connection).expect("read"),
        json!({"state": "refused", "code": "native_command_pack_activation_missing"})
    );
    slot(&connection, "{}", "short");
    assert_eq!(
        read(&connection).expect("read"),
        json!({"state": "refused", "code": "native_command_pack_activation_missing"})
    );
}

#[test]
fn a_filled_slot_comes_back_as_stored() {
    let connection = store();
    mark(&connection, 5, &schema_checksum(5));
    slot(&connection, "{\"revision\":3}", &"d".repeat(64));
    assert_eq!(
        read(&connection).expect("read"),
        json!({"state": "present", "row": {
            "revision": 3,
            "record_json": "{\"revision\":3}",
            "record_digest": "d".repeat(64),
            "record_mac": "m".repeat(64),
            "recorded_at": "now",
        }})
    );
}

/// The marker checksum the authority writer stores, spelled out so a change
/// to its format fails here too.
fn schema_checksum(version: i64) -> String {
    hex::encode(Sha256::digest(
        format!("hol-guard.extension-control-authority.schema.v{version}").as_bytes(),
    ))
}
