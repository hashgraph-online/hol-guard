//! The `sync_state` reads and writes answer as `store_cloud_events.py` did.

use serde_json::json;

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

#[test]
fn a_written_payload_reads_back_and_a_missing_one_is_null() {
    let connection = store();
    assert_eq!(
        call(&connection, get, json!({"state_key": "prefs"})).unwrap(),
        Value::Null
    );
    let payload = json!({"sponsored_discovery_enabled": false});
    call(
        &connection,
        set,
        json!({"state_key": "prefs", "payload": payload, "now": "t0"}),
    )
    .unwrap();
    assert_eq!(
        call(&connection, get, json!({"state_key": "prefs"})).unwrap(),
        payload
    );
    call(
        &connection,
        set,
        json!({"state_key": "prefs", "payload": [1, 2], "now": "t1"}),
    )
    .unwrap();
    assert_eq!(
        call(&connection, get, json!({"state_key": "prefs"})).unwrap(),
        json!([1, 2])
    );
}

#[test]
fn a_scalar_row_reads_as_null() {
    let connection = store();
    connection
        .execute("insert into sync_state values ('n', '7', 't0')", [])
        .unwrap();
    assert_eq!(
        call(&connection, get, json!({"state_key": "n"})).unwrap(),
        Value::Null
    );
}

#[test]
fn credential_rows_and_scalar_payloads_are_refused() {
    let connection = store();
    for key in ["oauth_local_credentials", "oauth_local_credentials:ws"] {
        assert!(call(
            &connection,
            set,
            json!({"state_key": key, "payload": {}, "now": "t0"}),
        )
        .is_err());
    }
    assert!(call(
        &connection,
        set,
        json!({"state_key": "oauth_local_credentials_other", "payload": {}, "now": "t0"}),
    )
    .is_ok());
    assert!(call(
        &connection,
        set,
        json!({"state_key": "prefs", "payload": 3, "now": "t0"}),
    )
    .is_err());
}
