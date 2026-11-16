//! Pins `apply_review_memory`: a publish replaces the remote decisions and
//! writes the memory state in one transaction, keeps local decisions, and a
//! request that names a key or row it may not write is refused with nothing
//! written, and a write that fails partway leaves everything as it was.

use std::collections::BTreeMap;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlReviewMemoryV1};
use serde_json::{json, Value};

use super::super::tests::{catalog, local, run, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";
const REGISTRY: &str = "guard_review_memory_registry";
const VERSION: &str = "guard_review_memory_policy_version";
const ACK: &str = "guard_review_memory_last_ack";

/// Revision 1 committed, one remote and one local decision and an older
/// memory registry.
fn home() -> Home {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.db
        .execute_batch(
            "drop table sync_state;
             create table sync_state (
                state_key text primary key, payload_json text not null, updated_at text not null);
             create table policy_decisions (
                harness, scope, artifact_id, artifact_hash, workspace, publisher, action,
                reason, owner, source, expires_at, updated_at, integrity_version,
                integrity_generation, payload_hash, payload_mac, integrity_key_id, signed_at);
             insert into policy_decisions (artifact_id, source)
                values ('stale', 'cloud-signed-memory'), ('mine', 'local');
             insert into sync_state values ('guard_review_memory_registry', '[]', 't0');",
        )
        .unwrap();
    home
}

fn publish(home: &Home, memory: ExtensionControlReviewMemoryV1) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        review_memory: Some(memory),
        ..home.request("apply_review_memory", &catalog('a'))
    })
}

fn row(artifact_id: &str, source: &str) -> Vec<Value> {
    let mut row = vec![Value::Null; 18];
    row[0] = json!("codex");
    row[2] = json!(artifact_id);
    row[6] = json!("allow");
    row[9] = json!(source);
    row[12] = json!(2);
    row
}

fn memory() -> ExtensionControlReviewMemoryV1 {
    ExtensionControlReviewMemoryV1 {
        payloads: BTreeMap::from([
            (REGISTRY.to_owned(), r#"[{"id": "m1"}]"#.to_owned()),
            (VERSION.to_owned(), r#"{"version": "v2"}"#.to_owned()),
            (ACK.to_owned(), r#"{"sequence": 2}"#.to_owned()),
        ]),
        rows: vec![row("fresh", "cloud-signed-memory")],
    }
}

/// Every stored `(state_key, payload_json, updated_at)` and decision.
type Snapshot = (Vec<(String, String, String)>, Vec<(String, String)>);

fn snapshot(home: &Home) -> Snapshot {
    let mut states = home
        .db
        .prepare("select * from sync_state order by state_key")
        .unwrap();
    let states = states
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut decisions = home
        .db
        .prepare("select artifact_id, source from policy_decisions order by artifact_id")
        .unwrap();
    let decisions = decisions
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    (states, decisions)
}

#[test]
fn a_publish_replaces_the_remote_decisions_and_writes_the_memory_state() {
    let home = home();
    assert_eq!(publish(&home, memory()), json!({ "applied": true }));
    let (states, decisions) = snapshot(&home);
    assert_eq!(
        states,
        [
            (
                ACK.to_owned(),
                r#"{"sequence": 2}"#.to_owned(),
                NOW.to_owned()
            ),
            (
                VERSION.to_owned(),
                r#"{"version": "v2"}"#.to_owned(),
                NOW.to_owned()
            ),
            (
                REGISTRY.to_owned(),
                r#"[{"id": "m1"}]"#.to_owned(),
                NOW.to_owned()
            ),
        ]
    );
    assert_eq!(
        decisions,
        [
            ("fresh".to_owned(), "cloud-signed-memory".to_owned()),
            ("mine".to_owned(), "local".to_owned()),
        ]
    );
}

#[test]
fn a_publish_naming_what_it_may_not_write_is_refused() {
    let home = home();
    let before = snapshot(&home);
    let mut unknown_payload = memory();
    unknown_payload
        .payloads
        .insert("policy_bundle".to_owned(), "{}".to_owned());
    let mut missing_payload = memory();
    missing_payload.payloads.remove(ACK);
    let mut unparsed = memory();
    unparsed
        .payloads
        .insert(REGISTRY.to_owned(), "{not json".to_owned());
    let mut registry_object = memory();
    registry_object
        .payloads
        .insert(REGISTRY.to_owned(), "{}".to_owned());
    let mut version_list = memory();
    version_list
        .payloads
        .insert(VERSION.to_owned(), "[]".to_owned());
    let mut ack_scalar = memory();
    ack_scalar.payloads.insert(ACK.to_owned(), "2".to_owned());
    let mut local_row = memory();
    local_row.rows.push(row("forged", "local"));
    let mut short_row = memory();
    short_row
        .rows
        .push(row("short", "cloud-signed-memory")[..17].to_vec());
    for invalid in [
        unknown_payload,
        missing_payload,
        unparsed,
        registry_object,
        version_list,
        ack_scalar,
        local_row,
        short_row,
    ] {
        let refused = publish(&home, invalid);
        assert_eq!(refused["fault"], json!("tampered"), "{refused}");
        assert_eq!(refused["reason"], json!("invalid review memory request"));
    }
    assert_eq!(snapshot(&home), before);
}

#[test]
fn a_write_that_fails_after_the_decisions_and_two_states_are_written_changes_nothing() {
    let home = home();
    home.db
        .execute_batch(
            "create trigger fail_registry before insert on sync_state
             when new.state_key = 'guard_review_memory_registry'
             begin select raise(abort, 'interrupted'); end;",
        )
        .unwrap();
    let before = snapshot(&home);
    let failed = publish(&home, memory());
    assert!(failed.get("fault").is_some(), "{failed}");
    assert_eq!(snapshot(&home), before);
}
