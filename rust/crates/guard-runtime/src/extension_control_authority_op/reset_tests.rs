//! Pins `reset`: the snapshot, transitions, proofs and pending pack
//! reservations are archived under one id and removed in one transaction,
//! the reset event records the provenance, and the catalog manifests go only
//! when the caller lost the key that authenticated them.

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlResetV1};
use serde_json::{json, Value};

use super::super::tests::{catalog, local, run, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";
const REASON: &str = "authenticated-recovery-unverifiable";

fn home() -> Home {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    home.db
        .execute_batch(
            "create table extension_control_authority_recovery_archive (
                archive_id text primary key, reason text not null, archived_at text not null,
                previous_revision integer, previous_catalog_digest text,
                snapshot_row_json text, transition_rows_json text not null,
                proof_rows_json text not null);
             create table extension_command_pack_pending (
                control_revision integer primary key, record_digest text not null);
             create table extension_control_pack_reservation_archive (
                archive_id text primary key, rows_json text not null);
             insert into extension_command_pack_pending values (2, 'pack');
             insert into extension_control_authority_proof values ('proof', 'mutation', 2, 't0', null);
             insert into extension_control_catalog_manifest values ('c', '{}', '{}', 'd', 'm', 't0');",
        )
        .unwrap();
    home
}

fn reset(home: &Home, drop_manifest: bool) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        reset: Some(ExtensionControlResetV1 {
            reason: REASON.to_owned(),
            drop_manifest,
        }),
        ..home.request("reset", &catalog('b'))
    })
}

fn count(home: &Home, table: &str) -> i64 {
    home.db
        .query_row(&format!("select count(*) from {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn text(home: &Home, sql: &str) -> String {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn a_reset_archives_the_authority_and_empties_it() {
    let home = home();
    let snapshot_digest = text(
        &home,
        "select snapshot_digest from extension_control_authority_snapshot",
    );
    let reply = reset(&home, false);
    let archive_id = reply["archive_id"].as_str().unwrap().to_owned();
    assert_eq!(reply["reset"], json!(true), "{reply}");
    for table in [
        "extension_control_authority_snapshot",
        "extension_control_authority_transition",
        "extension_control_authority_proof",
        "extension_command_pack_pending",
    ] {
        assert_eq!(count(&home, table), 0, "{table}");
    }
    assert_eq!(count(&home, "extension_control_catalog_manifest"), 1);
    let archived: Value = serde_json::from_str(&text(
        &home,
        "select snapshot_row_json from extension_control_authority_recovery_archive",
    ))
    .unwrap();
    assert_eq!(archived["revision"], json!(1));
    assert_eq!(archived["snapshot_digest"], json!(snapshot_digest));
    let transitions: Value = serde_json::from_str(&text(
        &home,
        "select transition_rows_json from extension_control_authority_recovery_archive",
    ))
    .unwrap();
    assert_eq!(transitions.as_array().unwrap().len(), 2);
    let proofs: Value = serde_json::from_str(&text(
        &home,
        "select proof_rows_json from extension_control_authority_recovery_archive",
    ))
    .unwrap();
    assert_eq!(proofs[0]["proof_id_hash"], json!("proof"));
    assert_eq!(proofs[0]["consumed_at"], Value::Null);
    let reservations = text(
        &home,
        "select rows_json from extension_control_pack_reservation_archive",
    );
    assert_eq!(
        reservations,
        r#"[{"control_revision":2,"record_digest":"pack"}]"#
    );
    let event: Value = serde_json::from_str(&text(
        &home,
        "select payload_json from guard_events where event_name = 'extension_control_authority_reset'",
    ))
    .unwrap();
    assert_eq!(
        event,
        json!({
            "reason": REASON,
            "archive_id": archive_id,
            "previous_revision": 1,
            "previous_catalog_digest": catalog('a'),
            "previous_snapshot_digest": snapshot_digest,
            "previous_layers_bytes": event["previous_layers_bytes"],
            "previous_transition_count": 2,
            "catalog_digest": catalog('b'),
        })
    );
    assert!(event["previous_layers_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn a_reset_after_a_lost_key_drops_the_catalog_manifests() {
    let home = home();
    reset(&home, true);
    assert_eq!(count(&home, "extension_control_catalog_manifest"), 0);
}

#[test]
fn a_reset_with_nothing_to_archive_records_a_missing_snapshot() {
    let home = Home::new();
    home.db
        .execute_batch(
            "create table extension_control_authority_recovery_archive (
                archive_id text primary key, reason text not null, archived_at text not null,
                previous_revision integer, previous_catalog_digest text,
                snapshot_row_json text, transition_rows_json text not null,
                proof_rows_json text not null);",
        )
        .unwrap();
    let reply = reset(&home, false);
    assert_eq!(reply["reset"], json!(true), "{reply}");
    assert_eq!(
        text(
            &home,
            "select snapshot_row_json from extension_control_authority_recovery_archive"
        ),
        "null"
    );
    let event: Value =
        serde_json::from_str(&text(&home, "select payload_json from guard_events")).unwrap();
    assert_eq!(event["previous_revision"], Value::Null);
    assert_eq!(event["previous_layers_bytes"], json!(0));
}

#[test]
fn a_reset_without_its_reason_writes_nothing() {
    let home = home();
    let refused = run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        ..home.request("reset", &catalog('b'))
    });
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert_eq!(count(&home, "extension_control_authority_transition"), 2);
    assert_eq!(
        count(&home, "extension_control_authority_recovery_archive"),
        0
    );
}

#[test]
fn an_abandoned_bootstrap_removes_only_a_revision_zero_snapshot() {
    let home = home();
    let abandon = |home: &Home| run(&home.request("abandon_bootstrap", &catalog('a')));
    assert_eq!(abandon(&home), json!({ "abandoned": false }));
    assert_eq!(count(&home, "extension_control_authority_snapshot"), 1);
    home.db
        .execute(
            "update extension_control_authority_snapshot set revision = 0",
            [],
        )
        .unwrap();
    assert_eq!(abandon(&home), json!({ "abandoned": true }));
    assert_eq!(count(&home, "extension_control_authority_snapshot"), 0);
}
