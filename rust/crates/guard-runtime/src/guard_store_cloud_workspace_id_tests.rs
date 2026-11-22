use super::*;

use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json, updated_at text);",
        )
        .expect("schema");
    connection
}

fn record(connection: &Connection, payload: rusqlite::types::Value) {
    connection
        .execute(
            "insert into sync_state values ('oauth_local_credentials', ?1, 't')",
            [payload],
        )
        .expect("record");
}

fn text(connection: &Connection, payload: &str) {
    record(connection, rusqlite::types::Value::Text(payload.to_owned()));
}

#[test]
fn the_method_is_a_routed_read() {
    assert!(handles("cloud_workspace_id"));
    assert!(!handles("cloud_workspace"));
    assert!(matches!(
        method_kind("cloud_workspace_id"),
        Some(Kind::Read)
    ));
}

#[test]
fn no_record_means_no_workspace() {
    assert_eq!(
        dispatch(&store()).expect("read"),
        json!({"state": "present", "workspace_id": null})
    );
}

#[test]
fn the_workspace_id_comes_back_alone() {
    let connection = store();
    text(
        &connection,
        r#"{"workspace_id": " ws-1 ", "credentials_sha256": "abc", "refresh": "x"}"#,
    );
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"state": "present", "workspace_id": " ws-1 "})
    );
}

#[test]
fn a_blank_or_missing_or_non_text_id_is_no_workspace() {
    for payload in [
        r#"{"workspace_id": "  "}"#,
        r#"{"workspace_id": 7}"#,
        r#"{"other": "ws"}"#,
        r#"["ws"]"#,
        "5",
    ] {
        let connection = store();
        text(&connection, payload);
        assert_eq!(
            dispatch(&connection).expect("read")["workspace_id"],
            Value::Null,
            "{payload}"
        );
    }
}

#[test]
fn an_undecodable_record_is_malformed() {
    let connection = store();
    text(&connection, "{not json");
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"state": "malformed"})
    );
    let connection = store();
    record(&connection, rusqlite::types::Value::Blob(b"{}".to_vec()));
    assert_eq!(
        dispatch(&connection).expect("read"),
        json!({"state": "malformed"})
    );
}
