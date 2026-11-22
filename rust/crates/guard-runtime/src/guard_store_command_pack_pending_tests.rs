use rusqlite::{params, Connection};
use serde_json::json;

use super::{dispatch, handles};
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    Connection::open_in_memory().expect("memory store")
}

fn pending_table(connection: &Connection) {
    connection
        .execute_batch(
            "create table extension_command_pack_pending ( \
               control_revision integer primary key check (control_revision > 0), \
               record_json, record_digest, record_mac, \
               link_json text not null, link_digest text not null, link_mac text not null);",
        )
        .expect("schema");
}

fn pending(connection: &Connection, revision: i64, record: &dyn rusqlite::ToSql) {
    connection
        .execute(
            "insert into extension_command_pack_pending values (?1, ?2, 'd', 'm', 'l', 'ld', 'lm')",
            params![revision, record],
        )
        .expect("pending");
}

#[test]
fn the_pending_read_is_routed_as_a_read() {
    assert!(handles("list_command_pack_pending_records"));
    assert!(!handles("read_command_pack_activation"));
    assert!(matches!(
        method_kind("list_command_pack_pending_records"),
        Some(Kind::Read)
    ));
}

#[test]
fn a_store_without_the_pending_table_has_no_records() {
    assert_eq!(dispatch(&store()).expect("read"), json!({"items": []}));
}

#[test]
fn records_come_back_as_stored_in_revision_order() {
    let connection = store();
    pending_table(&connection);
    pending(&connection, 9, &"{\"r\":9}");
    pending(&connection, 2, &"{\"r\":2}");
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"items": [
            {"record_json": "{\"r\":2}", "record_digest": "d", "record_mac": "m"},
            {"record_json": "{\"r\":9}", "record_digest": "d", "record_mac": "m"},
        ]})
    );
}

#[test]
fn a_non_text_record_comes_back_null() {
    let connection = store();
    pending_table(&connection);
    pending(&connection, 3, &vec![1_u8, 2]);
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"items": [{"record_json": null, "record_digest": "d", "record_mac": "m"}]})
    );
}
