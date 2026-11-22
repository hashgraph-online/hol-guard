//! The multi-row snapshot answers each named row as `get_sync_payload` did,
//! names a row it cannot parse, and refuses a malformed key list.

use serde_json::{json, Map};

use super::*;
use crate::guard_store_op_kind::{method_kind, Kind};

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

fn put(connection: &Connection, key: &str, payload: impl rusqlite::ToSql) {
    connection
        .execute(
            "insert or replace into sync_state values (?1, ?2, '2026-11-22T00:00:00Z')",
            rusqlite::params![key, payload],
        )
        .unwrap();
}

fn read(connection: &Connection, keys: Value) -> StoreResult<Value> {
    let mut args = Map::new();
    args.insert("keys".to_owned(), keys);
    dispatch(connection, "sync_payload_snapshot", &Args(&args))
}

#[test]
fn missing_rows_read_as_null() {
    assert_eq!(
        read(&store(), json!(["a", "b"])).unwrap(),
        json!({"rows": {"a": null, "b": null}, "unreadable": []})
    );
}

#[test]
fn objects_and_arrays_come_back_as_stored_and_scalars_as_null() {
    let connection = store();
    put(
        &connection,
        "object",
        r#"{"syncedAt":"2026-11-22T00:00:00Z"}"#,
    );
    put(&connection, "array", "[1,2]");
    put(&connection, "number", "7");
    put(&connection, "text", r#""x""#);
    put(&connection, "null", "null");
    assert_eq!(
        read(
            &connection,
            json!(["object", "array", "number", "text", "null"])
        )
        .unwrap(),
        json!({"rows": {
            "object": {"syncedAt": "2026-11-22T00:00:00Z"},
            "array": [1, 2],
            "number": null,
            "text": null,
            "null": null,
        }, "unreadable": []})
    );
}

#[test]
fn rows_come_back_in_request_order() {
    let connection = store();
    let answer = read(&connection, json!(["z", "a", "m"])).unwrap();
    let order: Vec<&str> = answer["rows"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(order, ["z", "a", "m"]);
}

#[test]
fn a_damaged_cell_is_named_without_hiding_another_row() {
    let connection = store();
    put(&connection, "text", "not json{");
    put(&connection, "blob", vec![0xff_u8, 0xfe]);
    put(&connection, "good", r#"{"ok":true}"#);
    assert_eq!(
        read(&connection, json!(["text", "good", "blob"])).unwrap(),
        json!({"rows": {"text": null, "good": {"ok": true}, "blob": null},
               "unreadable": ["text", "blob"]})
    );
}

#[test]
fn a_utf8_blob_cell_reads_like_text() {
    let connection = store();
    put(&connection, "blob", br#"{"ok":true}"#.to_vec());
    assert_eq!(
        read(&connection, json!(["blob"])).unwrap()["rows"]["blob"],
        json!({"ok": true})
    );
}

#[test]
fn a_malformed_key_list_is_refused() {
    let connection = store();
    let too_many: Vec<String> = (0..=MAX_KEYS).map(|index| format!("k{index}")).collect();
    for keys in [
        json!([]),
        json!(["a", "a"]),
        json!(["a", ""]),
        json!(["a", 1]),
        json!("a"),
        Value::Null,
        json!(too_many),
    ] {
        assert!(read(&connection, keys.clone()).is_err(), "{keys}");
    }
    let most: Vec<String> = (0..MAX_KEYS).map(|index| format!("k{index}")).collect();
    assert!(read(&connection, json!(most)).is_ok());
}

#[test]
fn the_method_is_a_snapshot_routed_here() {
    assert!(handles("sync_payload_snapshot"));
    assert!(!handles("get_sync_payload"));
    assert!(matches!(
        method_kind("sync_payload_snapshot"),
        Some(Kind::Snapshot)
    ));
}
