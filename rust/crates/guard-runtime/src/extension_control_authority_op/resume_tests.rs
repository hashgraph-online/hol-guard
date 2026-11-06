//! Pins the resume op: the verdict and its writes in one transaction, then the
//! committed anchor, the last-good export and the change event.

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlRetryProofV1};
use rusqlite::params;
use serde_json::{json, Value};

use super::super::seals::LAST_GOOD_FILE_NAME;
use super::super::tests::{anchor, catalog, local, run, with_cloud_events, Home};
use super::{anchor_ref, resolved_home};
use crate::encrypted_secret_store::EncryptedFileSecretStore;

const NOW: &str = "2026-10-21T00:05:00+00:00";

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn snapshot_digest(home: &Home, revision: i64) -> String {
    home.db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = ?",
            params![revision],
            |row| row.get(0),
        )
        .unwrap()
}

fn resume(home: &Home, revision: i64, anchor_json: String) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json),
        revision: Some(revision),
        now: Some(NOW.to_owned()),
        ..home.request("resume", &catalog('a'))
    })
}

fn vault_anchor(home: &Home) -> Option<String> {
    let resolved = resolved_home(&home.root.to_string_lossy());
    EncryptedFileSecretStore::new(&resolved).get_secret(&anchor_ref(&resolved))
}

#[test]
fn resume_commits_a_pending_row_and_seals_its_committed_anchor() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    let reply = resume(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(
        reply["resumed"],
        json!({"revision": 2, "catalog_digest": catalog('a')}),
        "{reply}"
    );
    assert_eq!(
        count(
            &home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        2
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition \
             where revision = 2 and phase = 'committed' and committed_at = '2026-10-21T00:05:00+00:00'"
        ),
        1
    );
    let sealed = reply["anchor_json"].as_str().unwrap().to_owned();
    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap();
    assert_eq!(
        parse(&sealed),
        parse(&anchor(2, &snapshot_digest(&home, 2), "committed"))
    );
    assert_eq!(vault_anchor(&home), Some(sealed));
    assert!(home.root.join(LAST_GOOD_FILE_NAME).is_file());
    let (event_type, payload): (String, String) = home
        .db
        .query_row(
            "select event_type, payload_json from guard_cloud_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(event_type, "policy.changed");
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["payload"]["revision"], json!(2));
    assert_eq!(payload["payload"]["previousRevision"], json!(1));
    // The row is finished: a second resume writes nothing new.
    let again = resume(&home, 2, anchor(2, &snapshot_digest(&home, 2), "committed"));
    assert_eq!(again["resumed"]["revision"], json!(2), "{again}");
    assert_eq!(count(&home, "select count(*) from guard_cloud_events"), 1);
}

#[test]
fn resume_marks_a_row_whose_snapshot_already_moved() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    home.db
        .execute_batch(
            "insert or replace into extension_control_authority_snapshot
             select 1, revision, catalog_digest, layers_json,
                    (select snapshot_digest from extension_control_authority_transition where revision = 1),
                    snapshot_json, snapshot_digest, snapshot_mac, created_at
             from extension_control_authority_transition where revision = 2;",
        )
        .unwrap();
    let reply = resume(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(reply["resumed"]["revision"], json!(2), "{reply}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition \
             where revision = 2 and phase = 'committed'"
        ),
        1
    );
}

#[test]
fn resume_abandons_a_row_the_anchor_never_reached() {
    let home = with_cloud_events(Home::new());
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    home.db
        .execute_batch(
            "create table extension_command_pack_pending (control_revision integer primary key);
             insert into extension_command_pack_pending values (2);",
        )
        .unwrap();
    let reply = resume(&home, 2, head);
    assert_eq!(reply["outcome"], json!("abandon"), "{reply}");
    assert_eq!(reply["resumed"], Value::Null);
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition"
        ),
        1
    );
    assert_eq!(
        count(&home, "select count(*) from extension_command_pack_pending"),
        0
    );
    assert_eq!(vault_anchor(&home), None);
}

#[test]
fn resume_leaves_a_pack_bound_row_to_the_pack_finisher() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    home.db
        .execute_batch(
            "create table extension_command_pack_pending (control_revision integer primary key);
             insert into extension_command_pack_pending values (2);",
        )
        .unwrap();
    let reply = resume(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(reply["pack_bound"], json!(true), "{reply}");
    assert_eq!(reply["outcome"], json!("commit_pending"));
    assert_eq!(
        count(
            &home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition where phase = 'prepared'"
        ),
        1
    );
    assert_eq!(count(&home, "select count(*) from guard_cloud_events"), 0);
    assert_eq!(vault_anchor(&home), None);
}

#[test]
fn resume_reports_an_absent_row_and_refuses_without_a_key() {
    let home = with_cloud_events(Home::new());
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    assert_eq!(resume(&home, 2, head.clone())["outcome"], json!("absent"));
    let refused = run(&ExtensionControlAuthorityRequestV1 {
        key_b64: None,
        anchor_json: Some(head),
        revision: Some(2),
        now: Some(NOW.to_owned()),
        ..home.request("resume", &catalog('a'))
    });
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
}

fn reserve_proof(home: &Home, revision: i64) {
    home.db
        .execute(
            "insert into extension_control_authority_proof
             (proof_id_hash, mutation_digest, transition_revision, reserved_at)
             values ('proof-hash', 'mutation', ?, 't0')",
            params![revision],
        )
        .unwrap();
}

fn finish_commit(home: &Home, revision: i64, anchor_json: String) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json),
        revision: Some(revision),
        now: Some(NOW.to_owned()),
        proof_hash: Some("proof-hash".to_owned()),
        ..home.request("resume", &catalog('a'))
    })
}

#[test]
fn resume_consumes_the_proof_of_the_commit_that_prepared_the_row() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    reserve_proof(&home, 2);
    let reply = finish_commit(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(reply["resumed"]["revision"], json!(2), "{reply}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof \
             where proof_id_hash = 'proof-hash' and consumed_at is not null"
        ),
        1
    );
}

#[test]
fn resume_refuses_a_commit_whose_proof_is_already_consumed_or_row_moved() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    reserve_proof(&home, 2);
    home.db
        .execute_batch("update extension_control_authority_proof set consumed_at = 't1';")
        .unwrap();
    let anchored = anchor(2, &snapshot_digest(&home, 2), "anchored");
    let refused = finish_commit(&home, 2, anchored.clone());
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    // The refusal rolled the snapshot back with it.
    assert_eq!(
        count(
            &home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
    // A row some other writer already moved the snapshot to is refused too.
    home.db
        .execute_batch(
            "update extension_control_authority_proof set consumed_at = null;
             insert or replace into extension_control_authority_snapshot
             select 1, revision, catalog_digest, layers_json,
                    (select snapshot_digest from extension_control_authority_transition where revision = 1),
                    snapshot_json, snapshot_digest, snapshot_mac, created_at
             from extension_control_authority_transition where revision = 2;",
        )
        .unwrap();
    let moved = finish_commit(&home, 2, anchored);
    assert_eq!(moved["fault"], json!("tampered"), "{moved}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof where consumed_at is null"
        ),
        1
    );
    assert_eq!(count(&home, "select count(*) from guard_cloud_events"), 0);
}

fn retry(home: &Home, revision: i64, anchor_json: String) -> Value {
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json),
        revision: Some(revision),
        now: Some(NOW.to_owned()),
        retry_proof: Some(ExtensionControlRetryProofV1 {
            proof_hash: "proof-hash".to_owned(),
            mutation_digest: "mutation".to_owned(),
        }),
        ..home.request("resume", &catalog('a'))
    })
}

#[test]
fn retry_records_its_proof_in_the_transaction_that_commits_its_row() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    let reply = retry(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(reply["resumed"]["revision"], json!(2), "{reply}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof \
             where proof_id_hash = 'proof-hash' and transition_revision = 2 \
             and consumed_at = '2026-10-21T00:05:00+00:00'"
        ),
        1
    );
    // A reserved proof is stamped once and keeps its first stamp.
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    reserve_proof(&home, 2);
    let reply = retry(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(reply["resumed"]["revision"], json!(2), "{reply}");
    let again = retry(&home, 2, anchor(2, &snapshot_digest(&home, 2), "committed"));
    assert_eq!(again["resumed"]["revision"], json!(2), "{again}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof \
             where reserved_at = 't0' and consumed_at = '2026-10-21T00:05:00+00:00'"
        ),
        1
    );
}

#[test]
fn retry_releases_its_proof_with_an_abandoned_row() {
    let home = with_cloud_events(Home::new());
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    reserve_proof(&home, 2);
    let reply = retry(&home, 2, head);
    assert_eq!(reply["outcome"], json!("abandon"), "{reply}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof"
        ),
        0
    );
}

#[test]
fn retry_refuses_a_proof_reserved_for_another_row_with_nothing_committed() {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    reserve_proof(&home, 3);
    let refused = retry(&home, 2, anchor(2, &snapshot_digest(&home, 2), "anchored"));
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert_eq!(
        count(
            &home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof where consumed_at is null"
        ),
        1
    );
    assert_eq!(count(&home, "select count(*) from guard_cloud_events"), 0);
}
