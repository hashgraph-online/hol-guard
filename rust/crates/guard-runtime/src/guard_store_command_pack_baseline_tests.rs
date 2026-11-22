use rusqlite::Connection;
use serde_json::{json, Value};

use super::{dispatch, handles};
use crate::guard_store_op_kind::{method_kind, Kind};

fn baseline(connection: &Connection) -> Value {
    dispatch(connection).expect("read")
}

#[test]
fn the_read_is_routed_as_a_snapshot() {
    assert!(handles("command_pack_baseline_retained"));
    assert!(matches!(
        method_kind("command_pack_baseline_retained"),
        Some(Kind::Snapshot)
    ));
    assert!(!handles("extension_control_snapshot_head"));
}

#[test]
fn the_baseline_is_retained_only_by_a_pack_schema_with_a_slot() {
    let connection = Connection::open_in_memory().expect("memory store");
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
