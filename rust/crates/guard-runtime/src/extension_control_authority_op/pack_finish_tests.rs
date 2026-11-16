//! Pins the pack half of `resume`: the pending activation installed with the
//! anchored row once the floor has moved, the floor named when it has not,
//! and a pending record that does not authenticate refused by name.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    ExtensionControlAuthorityRequestV1, ExtensionControlCatalogMigrationV1,
    ExtensionControlMigrationRecordV1, ExtensionControlPackFinishV1,
};
use rusqlite::params;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::layers::layers_to_values;
use super::super::tests::{anchor, catalog, local, run, with_cloud_events, Home, KEY};

const NOW: &str = "2026-10-21T00:05:00+00:00";
const SOURCE: &str = "1111111111111111111111111111111111111111";

fn key_hex() -> String {
    hex::encode(KEY)
}

pub(in super::super) fn seal(purpose: &str, payload: Value) -> Value {
    crate::pack_lifecycle::evaluate(&json!({
        "kind": "record", "operation": "seal", "purpose": purpose,
        "key": key_hex(), "payload": payload,
    }))
    .unwrap()
}

/// A protected lifecycle floor enrolled for one installed release.
pub(in super::super) fn floor(version: &str) -> String {
    let publication = serde_json::to_string(&json!({"authority_epoch": 3,
        "engine": "a".repeat(64), "source_sha": SOURCE,
        "policy": {"revocations": {"epoch": 2, "revoked": []}}}))
    .unwrap();
    let identity = json!({"profile": "installed", "source": SOURCE,
        "engine": "a".repeat(64),
        "root": hex::encode(Sha256::digest(publication.as_bytes())),
        "version": version, "authority": 3, "revocation": 2});
    crate::pack_lifecycle::enrolled_floor(&identity, &KEY)
}

fn reference() -> Value {
    json!({"sha256": "a".repeat(64), "length": 10, "expanded_length": 10, "kind": "data"})
}

pub(in super::super) fn activation() -> Value {
    json!({
        "schema": "guard.command-pack-activation.v2", "revision": 1, "previous_digest": null,
        "program_digest": "1".repeat(64), "catalog_digest": catalog('a'),
        "trust_digest": "3".repeat(64), "engine": "4".repeat(64), "source_sha": "5".repeat(40),
        "publication_id": "0.0", "root_digest": "a".repeat(64), "authority_epoch": 1,
        "revocation_epoch": 0, "issued_at": null, "expires_at": null, "selection": reference(),
        "selected_count": 1, "registry": reference(), "registry_count": 1, "executables": null,
        "executable_count": 0, "distribution": reference(), "authority_profile": "installed",
    })
}

/// The pack tables of a schema-v6 store, over a retained legacy baseline.
pub(in super::super) fn pack_tables(home: &Home) {
    let checksum = hex::encode(Sha256::digest(
        b"hol-guard.extension-control-authority.schema.v6",
    ));
    home.db
        .execute_batch(
            "create table extension_control_schema_migration (
                singleton integer primary key, version integer not null, checksum text not null);
             create table extension_command_pack_activation (
                singleton integer primary key, revision integer not null, record_json text not null,
                record_digest text not null, record_mac text not null, recorded_at text not null);
             create table extension_command_pack_pending (
                control_revision integer primary key, record_json text not null,
                record_digest text not null, record_mac text not null, link_json text not null,
                link_digest text not null, link_mac text not null);",
        )
        .unwrap();
    home.db
        .execute(
            "insert into extension_control_schema_migration values (1, 6, ?)",
            [checksum],
        )
        .unwrap();
    let baseline = seal(
        "baseline",
        json!({"schema": "guard.command-pack-legacy-baseline.v1", "revision": 0,
            "program_digest": "1".repeat(64), "catalog_digest": catalog('a'),
            "trust_digest": "3".repeat(64)}),
    );
    home.db
        .execute(
            "insert into extension_command_pack_activation values (1, 0, ?, ?, ?, 't0')",
            params![
                baseline["record"].as_str(),
                baseline["digest"].as_str(),
                baseline["mac"].as_str()
            ],
        )
        .unwrap();
}

struct Pack {
    home: Home,
    digest: String,
    before: String,
    after: String,
}

/// Revision 1 committed over a retained baseline, and revision 2 prepared to
/// activate a pending command pack reserved for it.
fn pack() -> Pack {
    pack_with(|_| {})
}

/// `pack`, with the reserved link's payload adjusted before it is sealed.
fn pack_with(adjust: impl FnOnce(&mut Value)) -> Pack {
    let home = with_cloud_events(Home::new());
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let record = seal("activation", activation());
    let digest = record["digest"].as_str().unwrap().to_owned();
    home.commit_bound(
        2,
        &catalog('a'),
        &[local(&catalog('a'))],
        "prepared",
        Some(&digest),
        true,
    );
    pack_tables(&home);
    let (before, after) = (floor("3.55.1"), floor("3.56.0"));
    let snapshot: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut payload = json!({"control_revision": 2, "snapshot_digest": snapshot,
        "catalog_digest": catalog('a'), "pack_record_digest": digest, "admitted_at": 1500,
        "lifecycle_before": before, "lifecycle_after": after});
    adjust(&mut payload);
    let link = seal("link", payload);
    home.db
        .execute(
            "insert into extension_command_pack_pending values (2, ?, ?, ?, ?, ?, ?)",
            params![
                record["record"].as_str(),
                digest,
                record["mac"].as_str(),
                link["record"].as_str(),
                link["digest"].as_str(),
                link["mac"].as_str()
            ],
        )
        .unwrap();
    Pack {
        home,
        digest,
        before,
        after,
    }
}

fn resume(pack: &Pack, floor: Option<&str>) -> Value {
    resume_with(pack, floor, None)
}

/// `resume`, finishing a catalog migration from `previous_revision`.
fn resume_migration(pack: &Pack, previous_revision: i64) -> Value {
    resume_with(pack, Some(pack.after.as_str()), Some(previous_revision))
}

fn resume_with(pack: &Pack, floor: Option<&str>, migrated_from: Option<i64>) -> Value {
    let snapshot: String = pack
        .home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor(2, &snapshot, "anchored")),
        revision: Some(2),
        now: Some(NOW.to_owned()),
        pack_finish: floor.map(|floor| ExtensionControlPackFinishV1 {
            key_b64: Base64UrlUnpadded::encode_string(&KEY),
            floor: Some(floor.to_owned()),
            ..ExtensionControlPackFinishV1::default()
        }),
        catalog_migration: migrated_from.map(|previous_revision| {
            ExtensionControlCatalogMigrationV1 {
                previous_revision,
                previous_catalog_digest: catalog('b'),
                layers: layers_to_values(&[local(&catalog('a'))]),
                installed_upgrade: None,
            }
        }),
        migration_record: migrated_from.map(|_| ExtensionControlMigrationRecordV1 {
            provenance: json!({"writer_version": "2.0.0", "trigger": "catalog-migration"}),
            downgraded_from: None,
            retired_target_ids: Vec::new(),
        }),
        ..pack.home.request("resume", &catalog('a'))
    })
}

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn resume_installs_the_pending_activation_once_the_floor_has_moved() {
    let pack = pack();
    let bound = resume(&pack, None);
    assert_eq!(bound["pack_bound"], json!(true), "{bound}");

    let owed = resume(&pack, Some(&pack.before));
    assert_eq!(
        owed["pack_floor_owed"],
        json!({"before": pack.before, "after": pack.after}),
        "{owed}"
    );
    let unmoved = "select revision from extension_command_pack_activation where singleton = 1";
    assert_eq!(count(&pack.home, unmoved), 0);
    assert_eq!(
        count(
            &pack.home,
            "select count(*) from extension_command_pack_pending"
        ),
        1
    );

    let finished = resume(&pack, Some(&pack.after));
    assert_eq!(finished["resumed"]["revision"], json!(2), "{finished}");
    let installed: (i64, String) = pack
        .home
        .db
        .query_row(
            "select revision, record_digest from extension_command_pack_activation",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(installed, (1, pack.digest.clone()));
    assert_eq!(
        count(
            &pack.home,
            "select count(*) from extension_command_pack_pending"
        ),
        0
    );
    assert_eq!(
        count(
            &pack.home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        2
    );
}

#[test]
fn resume_refuses_a_pending_activation_that_does_not_authenticate() {
    let pack = pack();
    pack.home
        .db
        .execute(
            "update extension_command_pack_pending set link_mac = ?",
            ["0".repeat(64)],
        )
        .unwrap();
    let refused = resume(&pack, Some(&pack.after));
    assert_eq!(refused["fault"], json!("pack"), "{refused}");
    assert_eq!(
        refused["reason"],
        json!("native_command_pack_transition_mismatch")
    );
    assert_eq!(
        count(
            &pack.home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
}

#[test]
fn resume_refuses_a_floor_the_pending_activation_was_not_prepared_against() {
    let pack = pack();
    let other = resume(&pack, Some(&floor("3.57.0")));
    assert_eq!(other["fault"], json!("pack"), "{other}");
    assert_eq!(
        other["reason"],
        json!("pack_lifecycle_prepared_floor_conflict")
    );
    assert_eq!(
        count(
            &pack.home,
            "select count(*) from extension_command_pack_pending"
        ),
        1
    );
    assert_eq!(
        count(
            &pack.home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
}

#[test]
fn resume_names_the_legacy_evidence_a_link_sealed_before_lifecycle_binding_needs() {
    let pack = pack_with(|payload| {
        let link = payload.as_object_mut().unwrap();
        link.remove("lifecycle_before");
        link.remove("lifecycle_after");
    });
    let owed = resume(&pack, Some(&pack.after));
    assert_eq!(owed["pack_legacy_owed"], json!(true), "{owed}");
    assert_eq!(
        count(
            &pack.home,
            "select count(*) from extension_command_pack_pending"
        ),
        1
    );
    assert_eq!(
        count(
            &pack.home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
}

#[test]
fn resume_refuses_an_activation_prepared_under_another_security_scope() {
    let pack = pack_with(|payload| payload["security_digest"] = json!("5".repeat(64)));
    let refused = resume(&pack, Some(&pack.after));
    assert_eq!(refused["fault"], json!("pack"), "{refused}");
    assert_eq!(
        refused["reason"],
        json!("active_security_prepared_scope_conflict")
    );
    assert_eq!(
        count(
            &pack.home,
            "select count(*) from extension_command_pack_pending"
        ),
        1
    );
    assert_eq!(
        count(
            &pack.home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
}

#[test]
fn resume_records_a_pack_migration_in_the_transaction_that_commits_it() {
    let pack = pack();
    let finished = resume_migration(&pack, 1);
    assert_eq!(finished["resumed"]["revision"], json!(2), "{finished}");
    let payload: String = pack
        .home
        .db
        .query_row(
            "select payload_json from guard_events \
             where event_name = 'extension_control_authority_catalog_migrated'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["previous_revision"], json!(1));
    assert_eq!(payload["revision"], json!(2));
    assert_eq!(payload["provenance"]["trigger"], json!("catalog-migration"));
    // A migration queues no change event, whichever op commits it.
    assert_eq!(
        count(&pack.home, "select count(*) from guard_cloud_events"),
        0
    );
}

#[test]
fn resume_refuses_a_migration_record_for_another_source_with_nothing_committed() {
    let pack = pack();
    let refused = resume_migration(&pack, 0);
    assert_eq!(refused["fault"], json!("tampered"), "{refused}");
    assert_eq!(
        count(
            &pack.home,
            "select count(*) from extension_command_pack_pending"
        ),
        1
    );
    assert_eq!(
        count(
            &pack.home,
            "select revision from extension_control_authority_snapshot where singleton = 1"
        ),
        1
    );
    assert_eq!(count(&pack.home, "select count(*) from guard_events"), 0);
}
