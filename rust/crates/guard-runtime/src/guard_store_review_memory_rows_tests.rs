//! The policy-memory snapshot pairs the stored version with the registry a
//! plan replaces, and names a row it cannot parse.

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

fn read(connection: &Connection) -> StoreResult<Value> {
    let args = Map::new();
    dispatch(connection, "review_policy_memory_rows", &Args(&args))
}

#[test]
fn an_empty_store_holds_no_cursor() {
    assert_eq!(
        read(&store()).unwrap(),
        json!({"registry": null, "policy_version": null, "unreadable": []})
    );
}

#[test]
fn stored_rows_come_back_together() {
    let connection = store();
    let registry = json!([{"ruleId": "rule-a", "decision": {"action": "allow"}}]);
    put(&connection, REGISTRY_KEY, registry.to_string());
    put(&connection, VERSION_KEY, r#"{"policyVersion":"  v7 "}"#);
    assert_eq!(
        read(&connection).unwrap(),
        json!({"registry": registry, "policy_version": "v7", "unreadable": []})
    );
}

#[test]
fn an_object_registry_comes_back_as_stored() {
    let connection = store();
    put(&connection, REGISTRY_KEY, r#"{"legacy":true}"#);
    assert_eq!(
        read(&connection).unwrap()["registry"],
        json!({"legacy": true})
    );
}

#[test]
fn a_scalar_row_reads_as_absent() {
    let connection = store();
    put(&connection, REGISTRY_KEY, "7");
    put(&connection, VERSION_KEY, r#""v7""#);
    assert_eq!(
        read(&connection).unwrap(),
        json!({"registry": null, "policy_version": null, "unreadable": []})
    );
}

#[test]
fn a_version_without_text_reads_as_absent() {
    for payload in [
        r#"{}"#,
        r#"{"policyVersion":null}"#,
        r#"{"policyVersion":7}"#,
        r#"{"policyVersion":" \u001f  "}"#,
    ] {
        let connection = store();
        put(&connection, VERSION_KEY, payload);
        assert_eq!(
            read(&connection).unwrap()["policy_version"],
            Value::Null,
            "{payload}"
        );
    }
}

#[test]
fn a_version_keeps_inner_text_and_drops_python_whitespace() {
    let connection = store();
    put(
        &connection,
        VERSION_KEY,
        r#"{"policyVersion":"\u001cv 7 "}"#,
    );
    assert_eq!(read(&connection).unwrap()["policy_version"], json!("v 7"));
}

#[test]
fn a_damaged_cell_is_named_without_hiding_the_other_row() {
    let connection = store();
    put(&connection, REGISTRY_KEY, "not json{");
    put(&connection, VERSION_KEY, vec![0xff_u8, 0xfe]);
    put(&connection, "unrelated", r#"{"policyVersion":"x"}"#);
    assert_eq!(
        read(&connection).unwrap(),
        json!({"registry": null, "policy_version": null,
               "unreadable": ["registry", "policy_version"]})
    );
    let connection = store();
    put(&connection, VERSION_KEY, vec![0xff_u8]);
    put(&connection, REGISTRY_KEY, "[]");
    assert_eq!(
        read(&connection).unwrap(),
        json!({"registry": [], "policy_version": null, "unreadable": ["policy_version"]})
    );
}

#[test]
fn a_utf8_blob_cell_reads_like_text() {
    let connection = store();
    put(
        &connection,
        VERSION_KEY,
        br#"{"policyVersion":"v2"}"#.to_vec(),
    );
    assert_eq!(read(&connection).unwrap()["policy_version"], json!("v2"));
}

#[test]
fn the_method_is_a_snapshot_routed_here() {
    assert!(handles("review_policy_memory_rows"));
    assert!(!handles("review_policy_memory_plan"));
    assert!(matches!(
        method_kind("review_policy_memory_rows"),
        Some(Kind::Snapshot)
    ));
}
