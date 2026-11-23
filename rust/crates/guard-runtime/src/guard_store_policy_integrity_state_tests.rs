//! The published policy integrity state: the legacy-row count that gates the
//! cutover, and a state write that happens only on a change.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::super::tests::{request_store, NOW};
use super::run;
use crate::guard_store_args::Args;

fn call(connection: &Connection, method: &str, args: Value) -> Value {
    let args: Map<String, Value> = args.as_object().cloned().unwrap_or_default();
    run(connection, method, &Args(&args)).unwrap()
}

fn stored(connection: &Connection) -> (String, String) {
    connection
        .query_row(
            "select payload_json, updated_at from sync_state where state_key = 'policy_integrity'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn state() -> Value {
    json!({
        "backend": "file",
        "cutover_complete": true,
        "degraded_reasons": [],
        "enforcement": "enforce",
        "generation": 3,
        "key_id": "k1",
        "mode": "protected",
    })
}

#[test]
fn signed_local_rows_are_not_counted_as_legacy() {
    let connection = request_store();
    let reply = call(&connection, "count_legacy_policy_rows", json!({}));
    assert_eq!(reply, json!({"legacy_rows": 0}));
}

#[test]
fn unsigned_local_rows_are_legacy_but_remote_rows_are_not() {
    let connection = request_store();
    connection
        .execute_batch(
            "update policy_decisions set payload_mac = null \
             where decision_id = (select min(decision_id) from policy_decisions); \
             insert into policy_decisions (harness, scope, action, source, updated_at) \
             values ('codex', 'global', 'allow', 'cloud-sync', 'x');",
        )
        .unwrap();
    let reply = call(&connection, "count_legacy_policy_rows", json!({}));
    assert_eq!(reply, json!({"legacy_rows": 1}));
}

#[test]
fn a_new_state_is_written_in_sorted_compact_json() {
    let connection = request_store();
    let reply = call(
        &connection,
        "record_policy_integrity_state",
        json!({"payload": state(), "now": NOW}),
    );
    assert_eq!(reply, json!({"changed": true}));
    let (payload, updated_at) = stored(&connection);
    assert_eq!(
        payload,
        "{\"backend\":\"file\",\"cutover_complete\":true,\"degraded_reasons\":[],\
         \"enforcement\":\"enforce\",\"generation\":3,\"key_id\":\"k1\",\"mode\":\"protected\"}"
    );
    assert_eq!(updated_at, NOW);
}

#[test]
fn an_unchanged_state_is_left_as_stored() {
    let connection = request_store();
    call(
        &connection,
        "record_policy_integrity_state",
        json!({"payload": state(), "now": NOW}),
    );
    let reply = call(
        &connection,
        "record_policy_integrity_state",
        json!({"payload": state(), "now": "2026-10-16T10:00:00Z"}),
    );
    assert_eq!(reply, json!({"changed": false}));
    assert_eq!(stored(&connection).1, NOW);
}

#[test]
fn a_state_without_a_payload_object_is_refused() {
    let connection = request_store();
    let args: Map<String, Value> = json!({"payload": [], "now": NOW})
        .as_object()
        .cloned()
        .unwrap();
    assert!(run(&connection, "record_policy_integrity_state", &Args(&args)).is_err());
}
