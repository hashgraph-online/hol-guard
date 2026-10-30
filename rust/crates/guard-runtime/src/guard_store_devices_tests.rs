//! The device row reads and writes answer as `store_inventory.py` did.

use super::*;
use crate::guard_store_db::StoreError;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table guard_devices (
               device_key text primary key, installation_id text not null,
               device_label text not null, created_at text not null, updated_at text not null);
             create table sync_state (
               state_key text primary key, payload_json text not null,
               updated_at text not null);",
        )
        .unwrap();
    connection
}

fn call(
    connection: &Connection,
    op: fn(&Connection, &Args<'_>) -> StoreResult<Value>,
    args: Value,
) -> StoreResult<Value> {
    let Value::Object(args) = args else {
        unreachable!()
    };
    op(connection, &Args(&args))
}

fn fresh() -> Value {
    json!({"new_device_id": "fresh-id", "created_at": "t0"})
}

#[test]
fn a_missing_row_reads_as_null_until_a_write_recreates_it() {
    let connection = store();
    assert_eq!(call(&connection, get, json!({})).unwrap(), Value::Null);
    let created = call(&connection, ensure, fresh()).unwrap();
    assert_eq!(
        created,
        json!({"installation_id": "fresh-id", "device_label": "Local machine"})
    );
    let again = json!({"new_device_id": "other-id", "created_at": "t1"});
    assert_eq!(call(&connection, ensure, again).unwrap(), created);
    assert_eq!(call(&connection, get, json!({})).unwrap(), created);
}

#[test]
fn a_label_and_a_rotation_update_the_one_row() {
    let connection = store();
    let mut args = fresh();
    args["label"] = json!("Work laptop");
    args["now"] = json!("t2");
    let labelled = call(&connection, set_label, args).unwrap();
    assert_eq!(
        labelled,
        json!({"installation_id": "fresh-id", "device_label": "Work laptop"})
    );
    let mut args = fresh();
    args["installation_id"] = json!("rotated-id");
    args["now"] = json!("t3");
    let rotated = call(&connection, rotate, args).unwrap();
    assert_eq!(
        rotated,
        json!({"installation_id": "rotated-id", "device_label": "Work laptop"})
    );
    let row = query_one(
        &connection,
        "select count(*) as n, max(updated_at) as at from guard_devices",
        &[],
    )
    .unwrap()
    .unwrap();
    assert_eq!(crate::guard_store_db::int(&row, "n"), 1);
    assert_eq!(text(&row, "at"), "t3");
}

#[test]
fn the_workspace_comes_from_the_stored_pairing() {
    let connection = store();
    assert_eq!(
        call(&connection, cloud_workspace_id, json!({})).unwrap(),
        Value::Null
    );
    let pair = |payload: &str| {
        exec(
            &connection,
            "insert or replace into sync_state values ('oauth_local_credentials', ?, 't')",
            &[Value::from(payload)],
        )
        .unwrap();
    };
    pair(r#"{"workspace_id": "ws-1"}"#);
    assert_eq!(
        call(&connection, cloud_workspace_id, json!({})).unwrap(),
        json!("ws-1")
    );
    for blank in [r#"{"workspace_id": "  "}"#, r#"{"workspace_id": 7}"#, "[1]"] {
        pair(blank);
        assert_eq!(
            call(&connection, cloud_workspace_id, json!({})).unwrap(),
            Value::Null
        );
    }
    pair("not json");
    assert!(matches!(
        call(&connection, cloud_workspace_id, json!({})),
        Err(StoreError::Value(_))
    ));
}
