//! The continuity snapshot pairs the authority revision with the two rows a
//! continuity commit is checked against, and names a row it cannot parse.

use serde_json::{json, Map};

use super::*;

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

fn with_authority(connection: &Connection, revision: &str) {
    connection
        .execute_batch(&format!(
            "create table local_cli_authority (
               singleton integer primary key check (singleton = 1),
               revision);
             insert into local_cli_authority values (1, {revision});"
        ))
        .unwrap();
}

fn put(connection: &Connection, key: &str, payload: impl rusqlite::ToSql) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, '2026-11-22T00:00:00Z')",
            rusqlite::params![key, payload],
        )
        .unwrap();
}

fn read(connection: &Connection) -> StoreResult<Value> {
    let args = Map::new();
    dispatch(connection, "custom_extension_continuity_rows", &Args(&args))
}

#[test]
fn an_empty_store_holds_revision_zero_and_no_rows() {
    let connection = store();
    assert_eq!(
        read(&connection).unwrap(),
        json!({"revision": 0, "state": null, "removals": null, "unreadable": []})
    );
}

#[test]
fn stored_rows_and_the_revision_come_back_together() {
    let connection = store();
    with_authority(&connection, "4");
    put(
        &connection,
        STATE_KEY,
        r#"{"items":{"cli-a":{"status":"applied"}}}"#,
    );
    put(&connection, REMOVALS_KEY, r#"["cli-b"]"#);
    assert_eq!(
        read(&connection).unwrap(),
        json!({
            "revision": 4,
            "state": {"items": {"cli-a": {"status": "applied"}}},
            "removals": ["cli-b"],
            "unreadable": [],
        })
    );
}

#[test]
fn a_row_holding_another_json_value_reads_as_absent() {
    let connection = store();
    put(&connection, STATE_KEY, "7");
    put(&connection, REMOVALS_KEY, r#""text""#);
    assert_eq!(
        read(&connection).unwrap(),
        json!({"revision": 0, "state": null, "removals": null, "unreadable": []})
    );
}

#[test]
fn a_row_that_is_not_json_is_named_unreadable() {
    let connection = store();
    put(&connection, STATE_KEY, "not json");
    put(&connection, REMOVALS_KEY, vec![0xff_u8, 0xfe, 0x7b]);
    assert_eq!(
        read(&connection).unwrap(),
        json!({"revision": 0, "state": null, "removals": null, "unreadable": ["state", "removals"]})
    );
}

#[test]
fn a_utf8_blob_row_reads_like_text() {
    let connection = store();
    put(&connection, REMOVALS_KEY, br#"{"cli-b":{}}"#.to_vec());
    assert_eq!(read(&connection).unwrap()["removals"], json!({"cli-b": {}}));
}

#[test]
fn a_revision_that_is_not_a_whole_number_is_refused() {
    let connection = store();
    with_authority(&connection, "'seven'");
    let Err(StoreError::Value(message)) = read(&connection) else {
        panic!("a text revision must be refused");
    };
    assert_eq!(message, "invalid local CLI row");
}

#[test]
fn the_method_routes_here_and_reads_in_one_snapshot() {
    assert!(handles("custom_extension_continuity_rows"));
    assert!(!handles("custom_extension_continuity"));
    assert!(crate::guard_store_sync_state::handles_row_method(
        "custom_extension_continuity_rows"
    ));
    use crate::guard_store_op_kind::{method_kind, Kind};
    assert!(matches!(
        method_kind("custom_extension_continuity_rows"),
        Some(Kind::Snapshot)
    ));
}
