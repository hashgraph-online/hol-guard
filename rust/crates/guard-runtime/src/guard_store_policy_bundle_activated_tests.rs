//! The activation bookkeeping writes what the runner's Python did.

use serde_json::json;

use super::*;
use crate::guard_store_receipt_redaction::tests::Memory;

const T1: &str = "2026-08-03T00:01:00Z";

fn v2(hash: &str, level: Option<&str>) -> Value {
    let mut bundle = json!({"contractVersion": V2_CONTRACT, "bundleHash": hash});
    if let Some(level) = level {
        bundle["receiptRedactionLevel"] = json!(level);
    }
    bundle
}

#[test]
fn a_new_canonical_bundle_keeps_the_one_it_replaces() {
    let mut store = Memory::default();
    store
        .rows
        .insert(CANONICAL_LAST_GOOD.to_owned(), v2("old", None));
    record(&mut store, &v2("new", None), None, "full", T1).unwrap();
    assert_eq!(store.rows[CANONICAL_LAST_GOOD], v2("new", None));
    assert_eq!(store.rows[CANONICAL_PREVIOUS_GOOD], v2("old", None));
    assert!(!store.rows.contains_key(LEGACY_LAST_GOOD));
}

#[test]
fn the_same_canonical_bundle_leaves_the_previous_copy_alone() {
    let mut store = Memory::default();
    store
        .rows
        .insert(CANONICAL_LAST_GOOD.to_owned(), v2("same", None));
    record(&mut store, &v2("same", None), None, "full", T1).unwrap();
    assert!(!store.rows.contains_key(CANONICAL_PREVIOUS_GOOD));
}

#[test]
fn a_legacy_bundle_is_kept_apart_from_the_canonical_copy() {
    let mut store = Memory::default();
    let legacy = json!({"bundleHash": "legacy"});
    record(&mut store, &legacy, None, "full", T1).unwrap();
    assert_eq!(store.rows[LEGACY_LAST_GOOD], legacy);
    assert!(!store.rows.contains_key(CANONICAL_LAST_GOOD));
}

#[test]
fn a_restored_bundle_records_the_rollback_event() {
    let mut store = Memory::default();
    record(
        &mut store,
        &v2("h", None),
        Some("invalid_signature"),
        "full",
        T1,
    )
    .unwrap();
    assert_eq!(
        store.events,
        vec![(
            ROLLBACK_EVENT.to_owned(),
            "{\"reason\": \"invalid_signature\", \"restored\": \"policy_bundle_last_good\"}"
                .to_owned()
        )]
    );
}

#[test]
fn the_bundle_level_is_persisted_and_an_absent_level_resets() {
    let mut store = Memory::default();
    record(&mut store, &v2("h", Some("none")), None, "full", T1).unwrap();
    assert_eq!(
        store.rows["cloud_receipt_redaction_level"],
        json!({"level": "none", "updated_at": T1})
    );
    assert!(store
        .rows
        .contains_key("cloud_receipt_redaction_relaxed_resync_v1"));
    record(&mut store, &v2("h", Some("bogus")), None, "partial", T1).unwrap();
    assert_eq!(
        store.rows["cloud_receipt_redaction_level"],
        json!({"level": "partial", "updated_at": T1})
    );
    assert!(!store
        .rows
        .contains_key("cloud_receipt_redaction_relaxed_resync_v1"));
}

#[test]
fn the_method_rejects_a_missing_bundle_and_an_invalid_local_level() {
    let connection = Connection::open_in_memory().unwrap();
    let run = |args: Value| {
        let Value::Object(args) = args else {
            unreachable!()
        };
        method(&connection, "hol-guard", &Args(&args))
    };
    assert!(run(json!({"local_level": "full", "now": T1})).is_err());
    assert!(run(json!({"bundle": {}, "local_level": "loose", "now": T1})).is_err());
}

#[test]
fn a_failed_level_change_rolls_back_the_bundle_and_rollback_event() {
    // Without the Review outbox tables the projection requeue fails after the
    // last-good copy and the rollback event are written; the store
    // transaction must undo both.
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key,
               payload_json text not null, updated_at text not null);
             create table guard_events (id integer primary key,
               event_name text not null, payload_json text not null,
               occurred_at text not null);
             insert into sync_state values
               ('cloud_receipt_redaction_level', '{\"level\": \"full\"}', 't0');",
        )
        .unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    let Value::Object(args) = json!({
        "bundle": v2("h", Some("none")),
        "rollback_reason": "invalid_signature",
        "local_level": "full",
        "now": T1,
    }) else {
        unreachable!()
    };
    assert!(method(&connection, "hol-guard", &Args(&args)).is_err());
    connection.execute_batch("ROLLBACK").unwrap();
    let count = |sql: &str| -> i64 { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
    assert_eq!(count("select count(*) from guard_events"), 0);
    assert_eq!(
        count("select count(*) from sync_state where state_key like 'policy_bundle_%'"),
        0
    );
    assert_eq!(
        count(
            "select count(*) from sync_state where state_key = 'cloud_receipt_redaction_level' \
             and payload_json = '{\"level\": \"full\"}'"
        ),
        1
    );
}
