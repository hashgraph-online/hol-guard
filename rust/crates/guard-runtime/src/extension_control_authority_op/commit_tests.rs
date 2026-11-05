//! Pins `commit_prepare`: the plan and the rows it prepares in one transaction,
//! and the commit finished by `resume` with the proof it reserved. Pins
//! `bootstrap`: the revision-zero snapshot and its committed anchor, and
//! `write_manifest`: the sealed catalog manifest it records or replaces.

use guard_contracts::ExtensionControlAuthorityRequestV1;
use serde_json::{json, Value};

use super::super::plans_tests::{commit, view, LATER};
use super::super::resume::{anchor_ref, resolved_home};
use super::super::tests::{anchor, catalog, local, manifest, run, with_cloud_events, Home};
use crate::encrypted_secret_store::EncryptedFileSecretStore;

fn prepare(home: &Home, anchor_json: &str, pack: Option<String>) -> Value {
    let mut commit = commit(2, 1);
    commit.pack_record_digest = pack;
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json.to_owned()),
        view: Some(view("protected", 1)),
        now: Some(LATER.to_owned()),
        commit: Some(commit),
        ..home.request("commit_prepare", &catalog('a'))
    })
}

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn commit_prepare_writes_the_row_and_proof_that_resume_then_commits() {
    let home = with_cloud_events(Home::new());
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let reply = prepare(&home, &head, None);
    let plan = &reply["plan"];
    assert_eq!(plan["outcome"], json!("prepare"), "{reply}");
    assert_eq!(plan["prepared"], json!(true));
    let digest = plan["snapshot"]["digest"].as_str().unwrap().to_owned();
    let proof = plan["hashes"]["proof"].as_str().unwrap().to_owned();
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition \
             where revision = 2 and phase = 'prepared'"
        ),
        1
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof \
             where transition_revision = 2 and consumed_at is null"
        ),
        1
    );
    // A retry finds its own row and prepares nothing more.
    let again = prepare(&home, &head, None);
    assert_eq!(again["plan"]["prepared"], Value::Null, "{again}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition"
        ),
        2
    );
    let committed = run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor(2, &digest, "anchored")),
        revision: Some(2),
        now: Some(LATER.to_owned()),
        proof_hash: Some(proof),
        ..home.request("resume", &catalog('a'))
    });
    assert_eq!(committed["resumed"]["revision"], json!(2), "{committed}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof where consumed_at is not null"
        ),
        1
    );
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
fn commit_prepare_leaves_a_pack_bound_commit_to_the_caller() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let reply = prepare(&home, &head, Some("p".repeat(64)));
    assert_eq!(reply["plan"]["outcome"], json!("prepare"), "{reply}");
    assert_eq!(reply["plan"]["prepared"], Value::Null);
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_transition"
        ),
        1
    );
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_proof"
        ),
        0
    );
}

#[test]
fn bootstrap_seals_revision_zero_and_its_committed_anchor_once() {
    let home = Home::new();
    let bootstrap = || {
        run(&ExtensionControlAuthorityRequestV1 {
            now: Some(LATER.to_owned()),
            ..home.request("bootstrap", &catalog('a'))
        })
    };
    let reply = bootstrap();
    assert_eq!(
        reply["resumed"],
        json!({"revision": 0, "catalog_digest": catalog('a')}),
        "{reply}"
    );
    let digest: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_snapshot \
             where singleton = 1 and revision = 0 and previous_digest is null",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let sealed = reply["anchor_json"].as_str().unwrap().to_owned();
    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap();
    assert_eq!(parse(&sealed), parse(&anchor(0, &digest, "committed")));
    let resolved = resolved_home(&home.root.to_string_lossy());
    assert_eq!(
        EncryptedFileSecretStore::new(&resolved).get_secret(&anchor_ref(&resolved)),
        Some(sealed)
    );
    let again = bootstrap();
    assert_eq!(again["fault"], json!("tampered"), "{again}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_authority_snapshot"
        ),
        1
    );
}

#[test]
fn write_manifest_records_then_replaces_the_sealed_manifest() {
    let home = Home::new();
    let write = |fingerprint: &str, replace: Option<bool>, digest: &str| {
        run(&ExtensionControlAuthorityRequestV1 {
            now: Some(LATER.to_owned()),
            current_manifest: Some(manifest(fingerprint)),
            manifest_replace: replace,
            ..home.request("write_manifest", digest)
        })
    };
    let loaded = || run(&home.request("load_manifest", &catalog('a')))["manifest"].clone();
    assert_eq!(write("1", None, &catalog('a'))["written"], json!(true));
    assert_eq!(loaded(), json!(manifest("1")));
    // A second first record for the same catalog is refused.
    assert!(write("2", None, &catalog('a'))["fault"].is_string());
    assert_eq!(
        write("2", Some(true), &catalog('a'))["written"],
        json!(true)
    );
    assert_eq!(loaded(), json!(manifest("2")));
    // Nothing recorded for the catalog: nothing to replace.
    let refused = write("3", Some(true), &catalog('b'));
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert_eq!(
        count(
            &home,
            "select count(*) from extension_control_catalog_manifest"
        ),
        1
    );
}
