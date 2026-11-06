//! Pins `apply_policy`: an activation replaces the remote decisions and
//! writes its payloads in one transaction, writes nothing once the snapshot
//! or an observed value moved or the continuity is refused, and a request
//! that names a key or row it may not write is refused.

use std::collections::BTreeMap;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlPolicyApplyV1};
use serde_json::{json, Value};

use super::super::tests::{catalog, local, run, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";
const CHECKPOINT: &str = "policy_bundle_acceptance_checkpoint";

/// Revision 1 committed, one remote and one local decision, an active
/// managed activation and a stored checkpoint.
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
                values ('stale', 'policy-bundle'), ('mine', 'local');
             insert into sync_state values
                ('managed_controls_active', '{\"active\": true}', 't0'),
                ('managed_controls_negotiated_capabilities', '[\"cap\"]', 't0'),
                ('policy_bundle_acceptance_checkpoint', '{\"sequence\": 1}', 't0');",
        )
        .unwrap();
    home
}

fn base(home: &Home) -> (i64, String) {
    home.db
        .query_row(
            "select revision, snapshot_digest from extension_control_authority_snapshot",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn apply(home: &Home, apply: ExtensionControlPolicyApplyV1) -> Value {
    let (revision, digest) = base(home);
    run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        policy_apply: Some(ExtensionControlPolicyApplyV1 {
            base_revision: Some(revision),
            base_snapshot_digest: Some(digest),
            ..apply
        }),
        ..home.request("apply_policy", &catalog('a'))
    })
}

fn row(artifact_id: &str, source: &str) -> Vec<Value> {
    let mut row = vec![Value::Null; 18];
    row[0] = json!("codex");
    row[2] = json!(artifact_id);
    row[6] = json!("block");
    row[9] = json!(source);
    row[12] = json!(2);
    row
}

fn observed() -> BTreeMap<String, Option<String>> {
    BTreeMap::from([
        (CHECKPOINT.to_owned(), Some(r#"{"sequence": 1}"#.to_owned())),
        ("policy_bundle_ack".to_owned(), None),
    ])
}

fn activation() -> ExtensionControlPolicyApplyV1 {
    ExtensionControlPolicyApplyV1 {
        observed: observed(),
        payloads: BTreeMap::from([
            ("policy".to_owned(), "{}".to_owned()),
            (CHECKPOINT.to_owned(), r#"{"sequence": 2}"#.to_owned()),
        ]),
        retire_managed: true,
        rows: vec![
            row("fresh", "policy-bundle"),
            row("pack", "team-policy-pack"),
        ],
        ..ExtensionControlPolicyApplyV1::default()
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
fn an_activation_replaces_the_remote_decisions_and_writes_its_state() {
    let home = home();
    let applied = apply(&home, activation());
    assert_eq!(applied, json!({ "applied": true }));
    let (states, decisions) = snapshot(&home);
    assert_eq!(
        states,
        [
            (
                CHECKPOINT.to_owned(),
                r#"{"sequence": 2}"#.to_owned(),
                NOW.to_owned()
            ),
            ("policy".to_owned(), "{}".to_owned(), NOW.to_owned()),
        ]
    );
    assert_eq!(
        decisions,
        [
            ("fresh".to_owned(), "policy-bundle".to_owned()),
            ("mine".to_owned(), "local".to_owned()),
            ("pack".to_owned(), "team-policy-pack".to_owned()),
        ]
    );
    let version: i64 = home
        .db
        .query_row(
            "select integrity_version from policy_decisions where artifact_id = 'fresh'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 2);
}

#[test]
fn an_activation_over_moved_state_writes_nothing() {
    let home = home();
    let before = snapshot(&home);
    let mut stale = activation();
    stale
        .observed
        .insert(CHECKPOINT.to_owned(), Some(r#"{"sequence": 0}"#.to_owned()));
    assert_eq!(apply(&home, stale), json!({ "changed": true }));
    let mut appeared = activation();
    appeared.observed.insert(CHECKPOINT.to_owned(), None);
    assert_eq!(apply(&home, appeared), json!({ "changed": true }));
    let moved = run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        policy_apply: Some(ExtensionControlPolicyApplyV1 {
            base_revision: Some(1),
            base_snapshot_digest: Some(catalog('d')),
            ..activation()
        }),
        ..home.request("apply_policy", &catalog('a'))
    });
    assert_eq!(moved, json!({ "changed": true }));
    assert_eq!(snapshot(&home), before);
}

#[test]
fn a_refused_continuity_rejects_the_activation_with_nothing_written() {
    let home = home();
    let before = snapshot(&home);
    let continuity = json!({ "updates": [], "provider_updates": { "cli": [] } });
    let rejected = apply(
        &home,
        ExtensionControlPolicyApplyV1 {
            continuity: Some(continuity.as_object().unwrap().clone()),
            ..activation()
        },
    );
    assert_eq!(
        rejected,
        json!({ "rejected": "custom_extension_continuity_changed_during_activation" })
    );
    assert_eq!(snapshot(&home), before);
}

#[test]
fn an_activation_naming_what_it_may_not_write_is_refused() {
    let home = home();
    let before = snapshot(&home);
    let mut unknown_payload = activation();
    unknown_payload
        .payloads
        .insert("approval_gate".to_owned(), "{}".to_owned());
    let mut unparsed = activation();
    unparsed
        .payloads
        .insert("policy".to_owned(), "{not json".to_owned());
    let mut retired_and_written = activation();
    retired_and_written
        .payloads
        .insert("managed_controls_active".to_owned(), "{}".to_owned());
    let mut unknown_observed = activation();
    unknown_observed
        .observed
        .insert("approval_gate".to_owned(), None);
    let mut local_row = activation();
    local_row.rows.push(row("forged", "local"));
    let mut short_row = activation();
    short_row
        .rows
        .push(row("short", "cloud-sync")[..17].to_vec());
    let mut float_row = activation();
    let mut float = row("float", "cloud-sync");
    float[12] = json!(2.5);
    float_row.rows.push(float);
    for invalid in [
        unknown_payload,
        unparsed,
        retired_and_written,
        unknown_observed,
        local_row,
        short_row,
        float_row,
    ] {
        let refused = apply(&home, invalid);
        assert_eq!(refused["fault"], json!("tampered"), "{refused}");
        assert_eq!(
            refused["reason"],
            json!("invalid policy activation request")
        );
    }
    assert_eq!(snapshot(&home), before);
}
