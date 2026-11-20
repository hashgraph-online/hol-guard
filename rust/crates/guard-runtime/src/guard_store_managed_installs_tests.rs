//! The rows answer as `store_cloud_events.py` did: one per harness, the
//! manifest text kept byte for byte, and a later write replacing the row.

use super::*;
use rusqlite::Connection;

fn store() -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table managed_installs (
               harness text primary key, active integer not null, workspace text,
               manifest_json text not null, updated_at text not null);
             create table sync_state (
               state_key text primary key, payload_json text not null, updated_at text);",
        )
        .unwrap();
    connection
}

fn call(
    connection: &Connection,
    op: fn(&Connection, &Args<'_>) -> StoreResult<Value>,
    args: Value,
) -> Value {
    let Value::Object(args) = args else {
        unreachable!()
    };
    op(connection, &Args(&args)).unwrap()
}

#[test]
fn a_write_is_read_back_with_its_manifest_text_unchanged() {
    let connection = store();
    let manifest = "{\"b\": 1, \"a\": \"\\u00e9\"}";
    call(
        &connection,
        set,
        json!({"harness": "codex", "active": true, "workspace": "/w",
               "manifest_json": manifest, "now": "2026-01-01T00:00:00+00:00"}),
    );
    let row = call(&connection, get, json!({"harness": "codex"}));
    assert_eq!(
        row,
        json!({"harness": "codex", "active": true, "workspace": "/w",
               "manifest_json": manifest, "updated_at": "2026-01-01T00:00:00+00:00"})
    );
}

#[test]
fn a_later_write_replaces_the_row_and_the_list_is_by_harness() {
    let connection = store();
    for (harness, active) in [("cursor", true), ("codex", true), ("codex", false)] {
        call(
            &connection,
            set,
            json!({"harness": harness, "active": active, "workspace": null,
                   "manifest_json": "{}", "now": "t"}),
        );
    }
    let rows = call(&connection, list, json!({}));
    let names: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["harness"].clone(),
                row["active"].clone(),
                row["workspace"].clone(),
            )
        })
        .collect();
    assert_eq!(
        names,
        vec![
            (json!("codex"), json!(false), Value::Null),
            (json!("cursor"), json!(true), Value::Null),
        ]
    );
}

#[test]
fn a_harness_with_no_row_reads_as_null() {
    assert_eq!(
        call(&store(), get, json!({"harness": "codex"})),
        Value::Null
    );
}

#[test]
fn every_write_moves_the_revision_and_a_bump_moves_it_too() {
    let connection = store();
    assert_eq!(call(&connection, revision, json!({})), json!(0));
    call(
        &connection,
        set,
        json!({"harness": "codex", "active": true, "workspace": null,
               "manifest_json": "{}", "now": "2026-01-01T00:00:00+00:00"}),
    );
    assert_eq!(call(&connection, revision, json!({})), json!(1));
    let bumped = call(
        &connection,
        bump,
        json!({"now": "2026-01-01T00:00:01+00:00"}),
    );
    assert_eq!(bumped, json!(2));
    assert_eq!(call(&connection, revision, json!({})), json!(2));
}

#[test]
fn hook_admission_uses_one_snapshot_for_direct_and_fallback_rows() {
    let connection = store();
    call(
        &connection,
        set,
        json!({"harness": "codex", "active": true, "workspace": null,
               "manifest_json": "{}", "now": "t"}),
    );
    assert_eq!(
        call(&connection, hook_admission, json!({"harness": "codex"}),),
        json!({"unmanaged": false, "revision": 1}),
    );
    assert_eq!(
        call(&connection, hook_admission, json!({"harness": "pi"}),),
        json!({"unmanaged": true, "revision": 1}),
    );
}

#[test]
fn hook_admission_holds_an_inactive_direct_row() {
    let connection = store();
    call(
        &connection,
        set,
        json!({"harness": "pi", "active": false, "workspace": null,
               "manifest_json": "{}", "now": "t"}),
    );
    assert_eq!(
        call(&connection, hook_admission, json!({"harness": "pi"}))["unmanaged"],
        true
    );
}

#[test]
fn hook_admission_uses_a_snapshot_transaction() {
    assert!(crate::guard_store_op::method_is_snapshot_for_test(
        "hook_managed_install_admission"
    ));
}
