//! The activation view: stored text for each named row, the authority
//! snapshot, and the remote rows in the resident's column order.

use serde_json::{json, Map, Value};

use super::super::super::tests::request_store;
use super::policy_activation_view;
use crate::guard_store_args::Args;
use crate::guard_store_op_kind::{method_kind, Kind};

fn view(
    connection: &rusqlite::Connection,
    keys: Value,
) -> crate::guard_store_db::StoreResult<Value> {
    let mut args = Map::new();
    args.insert("state_keys".to_owned(), keys);
    policy_activation_view(connection, &Args(&args))
}

fn seeded() -> rusqlite::Connection {
    let connection = request_store();
    connection
        .execute_batch(
            "create table if not exists extension_control_authority_snapshot (
               singleton integer primary key, revision integer not null,
               snapshot_digest text not null);
             delete from policy_decisions;
             insert into sync_state (state_key, payload_json, updated_at) values
             ('policy_bundle', '{\"b\":  1}', '2026-10-16T09:00:00Z');
             insert into policy_decisions (harness, scope, action, source, updated_at) values
             ('codex', 'global', 'allow', 'manual', '2026-10-16T09:00:01Z'),
             ('codex', 'global', 'block', 'cloud-sync', '2026-10-16T09:00:02Z');",
        )
        .unwrap();
    connection
}

#[test]
fn rows_come_back_as_stored_text_and_a_missing_row_as_null() {
    let reply = view(&seeded(), json!(["policy_bundle", "policy_bundle_ack"])).unwrap();
    assert_eq!(
        reply["sync_state"],
        json!({"policy_bundle": "{\"b\":  1}", "policy_bundle_ack": null})
    );
    assert_eq!(reply["authority"], Value::Null);
}

#[test]
fn only_remote_rows_are_read_in_the_resident_column_order() {
    let reply = view(&seeded(), json!(["policy_bundle"])).unwrap();
    let rows = reply["remote_rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    let row = rows[0].as_array().unwrap();
    assert_eq!(row.len(), 18);
    assert_eq!(row[0], json!("codex"));
    assert_eq!(row[6], json!("block"));
    assert_eq!(row[9], json!("cloud-sync"));
    assert_eq!(row[11], json!("2026-10-16T09:00:02Z"));
}

#[test]
fn the_authority_snapshot_is_read() {
    let connection = seeded();
    connection
        .execute(
            "insert into extension_control_authority_snapshot (singleton, revision, snapshot_digest) \
             values (1, 7, 'digest')",
            [],
        )
        .unwrap();
    let reply = view(&connection, json!(["policy_bundle"])).unwrap();
    assert_eq!(
        reply["authority"],
        json!({"revision": 7, "snapshot_digest": "digest"})
    );
}

#[test]
fn a_malformed_key_list_is_refused() {
    let connection = seeded();
    let too_many: Vec<String> = (0..17).map(|index| format!("k{index}")).collect();
    for keys in [
        json!([]),
        json!(["a", "a"]),
        json!([""]),
        json!("a"),
        json!([1]),
        json!(too_many),
    ] {
        assert!(view(&connection, keys).is_err());
    }
}

#[test]
fn the_view_is_read_as_one_snapshot() {
    assert!(matches!(
        method_kind("policy_activation_view"),
        Some(Kind::Snapshot)
    ));
}
