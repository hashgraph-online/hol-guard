use rusqlite::Connection;
use serde_json::{json, Value};

use super::{dispatch, handles};
use crate::guard_store_op_kind::{method_kind, Kind};

fn store() -> Connection {
    let connection = Connection::open_in_memory().expect("memory store");
    connection
        .execute_batch(
            "create table policy_decisions (source text not null);
             create table guard_local_once_approvals (approval_id text);
             create table extension_control_authority_snapshot (
               singleton integer primary key, revision integer, snapshot_digest text);",
        )
        .expect("schema");
    connection
}

fn presence(connection: &Connection) -> Value {
    dispatch(connection, "policy_row_presence").expect("presence")
}

#[test]
fn both_reads_are_routed_as_snapshots() {
    for method in ["policy_row_presence", "extension_control_authority_head"] {
        assert!(handles(method));
        assert!(matches!(method_kind(method), Some(Kind::Snapshot)));
    }
    assert!(!handles("policy_rows_fingerprint"));
}

#[test]
fn an_empty_store_has_no_saved_rows() {
    assert_eq!(
        presence(&store()),
        json!({"local_policy": false, "remote_policy": false, "local_once": false,
               "policy_bundle": false})
    );
}

#[test]
fn each_kind_of_saved_row_is_reported_on_its_own() {
    let connection = store();
    connection
        .execute("insert into policy_decisions values ('local')", [])
        .expect("local");
    assert_eq!(
        presence(&connection),
        json!({"local_policy": true, "remote_policy": false, "local_once": false,
               "policy_bundle": false})
    );
    connection
        .execute("delete from policy_decisions", [])
        .expect("clear");
    connection
        .execute("insert into policy_decisions values ('policy-bundle')", [])
        .expect("bundle");
    connection
        .execute("insert into guard_local_once_approvals values ('a')", [])
        .expect("once");
    assert_eq!(
        presence(&connection),
        json!({"local_policy": false, "remote_policy": true, "local_once": true,
               "policy_bundle": true})
    );
}

#[test]
fn the_authority_head_is_null_until_a_snapshot_is_stored() {
    let connection = store();
    assert_eq!(
        dispatch(&connection, "extension_control_authority_head").expect("head"),
        Value::Null
    );
    connection
        .execute(
            "insert into extension_control_authority_snapshot values (1, 7, 'abc')",
            [],
        )
        .expect("snapshot");
    assert_eq!(
        dispatch(&connection, "extension_control_authority_head").expect("head"),
        json!({"revision": 7, "snapshot_digest": "abc"})
    );
}
