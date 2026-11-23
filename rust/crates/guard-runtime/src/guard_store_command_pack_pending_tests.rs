use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::{handles, HISTORY_PAGE_BYTES};
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

fn dispatch(connection: &Connection) -> Result<Value, crate::guard_store_db::StoreError> {
    super::dispatch(connection, &Args(&Map::new()))
}

fn page_after(connection: &Connection, after: i64) -> Value {
    let mut args = Map::new();
    args.insert("after_revision".to_owned(), json!(after));
    super::dispatch(connection, &Args(&args)).expect("page")
}

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
fn the_pending_read_is_routed_as_a_snapshot() {
    assert!(handles("list_command_pack_pending_records"));
    assert!(!handles("read_command_pack_activation"));
    assert!(matches!(
        method_kind("list_command_pack_pending_records"),
        Some(Kind::Snapshot)
    ));
}

#[test]
fn a_store_without_the_pending_table_has_no_records() {
    assert_eq!(
        dispatch(&store()).expect("read"),
        json!({"items": [], "next": null})
    );
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
        ], "next": null})
    );
}

#[test]
fn a_non_text_record_comes_back_null() {
    let connection = store();
    pending_table(&connection);
    pending(&connection, 3, &vec![1_u8, 2]);
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"items": [{"record_json": null, "record_digest": "d", "record_mac": "m"}], "next": null})
    );
}

#[test]
fn a_pending_set_larger_than_one_reply_is_paged_without_dropping_a_record() {
    let connection = store();
    pending_table(&connection);
    let body = "x".repeat(HISTORY_PAGE_BYTES / 3);
    for revision in 1..=4 {
        pending(&connection, revision, &body);
    }
    let mut seen = Vec::new();
    let mut after = 0;
    loop {
        let page = page_after(&connection, after);
        let items = page["items"].as_array().expect("items");
        assert!(!items.is_empty());
        seen.extend(items.iter().cloned());
        match page["next"].as_i64() {
            Some(next) => {
                assert!(next > after);
                after = next;
            }
            None => break,
        }
    }
    assert_eq!(seen.len(), 4);
    assert!(
        page_after(&connection, 0)["items"]
            .as_array()
            .expect("items")
            .len()
            < 4
    );
}

#[test]
fn a_record_too_large_for_any_page_is_refused() {
    let connection = store();
    pending_table(&connection);
    pending(&connection, 1, &"x".repeat(HISTORY_PAGE_BYTES));
    assert!(dispatch(&connection).is_err());
}
