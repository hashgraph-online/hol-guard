use super::*;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null, \
             updated_at text not null);
             create table guard_devices (device_key text primary key, installation_id text, \
             device_label text);",
        )
        .unwrap();
    connection
}

fn bundle(connection: &Connection, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state values ('policy_bundle', ?1, 't')",
            [payload],
        )
        .unwrap();
}

fn read(connection: &Connection) -> StoreResult<Value> {
    let args = json!({"harness": "codex"});
    list(connection, &Args(args.as_object().unwrap()))
}

#[test]
fn no_cached_bundle_lists_no_exceptions() {
    let connection = store();
    assert_eq!(read(&connection).unwrap(), json!([]));
    for payload in ["{}", "[1]", "null"] {
        bundle(&connection, payload);
        assert_eq!(read(&connection).unwrap(), json!([]), "{payload}");
    }
}

#[test]
fn a_bundle_the_store_cannot_parse_goes_to_the_daemon() {
    let connection = store();
    bundle(&connection, "not json");
    assert!(read(&connection).is_err());
}

#[cfg(unix)]
#[test]
fn an_unsigned_bundle_lists_no_exceptions() {
    let connection = store();
    bundle(
        &connection,
        r#"{"bundleVersion": 1, "cloudExceptions": [{"id": "x", "harness": "codex"}]}"#,
    );
    assert_eq!(read(&connection).unwrap(), json!([]));
}

#[test]
fn only_the_fields_the_owner_reads_cross_over() {
    let bundle = json!({"bundleHash": "h", "decisions": [], "acknowledgements": []});
    let kept = subset(bundle.as_object().unwrap(), &BUNDLE_KEYS);
    assert_eq!(
        Value::Object(kept),
        json!({"bundleHash": "h", "acknowledgements": []})
    );
}
