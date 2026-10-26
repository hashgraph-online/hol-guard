use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_command::extension_control::{
    ControlLayerKind, ControlState, ControlTarget, ControlTargetKind, ExtensionControl,
    ExtensionControlLayer, CONTROL_SCHEMA_VERSION,
};
use guard_contracts::{
    ExtensionControlAuthorityRequestV1, EXTENSION_CONTROL_AUTHORITY_REQUEST_SCHEMA,
};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::evaluate;
use super::layers::{layers_to_json, manifest_sha256, Manifest};
use super::records::{
    authenticated_record, canonical, private_hash, ANCHOR_PURPOSE, CATALOG_MANIFEST_PURPOSE,
    SNAPSHOT_PURPOSE, TRANSITION_PURPOSE,
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
pub(super) const KEY: [u8; 32] = [7u8; 32];
pub(super) const AT: &str = "2026-10-21T00:00:00+00:00";
const TARGET: &str = "command.npm.install";

pub(super) fn catalog(byte: char) -> String {
    byte.to_string().repeat(64)
}

pub(super) struct Home {
    pub(super) root: PathBuf,
    pub(super) db: Connection,
}

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-ext-authority-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

impl Home {
    pub(super) fn new() -> Self {
        let root = root();
        let db = Connection::open(root.join("guard.db")).unwrap();
        db.execute_batch(
            "create table extension_control_authority_snapshot (
                singleton integer primary key, revision integer not null, catalog_digest text not null,
                layers_json text not null, previous_digest text, snapshot_json text not null,
                snapshot_digest text not null, snapshot_mac text not null, committed_at text not null);
             create table extension_control_authority_transition (
                revision integer primary key, previous_revision integer not null, phase text not null,
                actor_id_hash text not null, idempotency_key_hash text not null, nonce_hash text not null,
                catalog_digest text not null, layers_json text not null, snapshot_json text not null,
                snapshot_digest text not null, snapshot_mac text not null, transition_json text not null,
                transition_digest text not null, transition_mac text not null, created_at text not null,
                committed_at text);
             create table extension_control_catalog_manifest (
                catalog_digest text primary key, manifest_json text not null, record_json text not null,
                record_digest text not null, record_mac text not null, recorded_at text not null);
             create table sync_state (state_key text primary key, payload_json text not null);
             create table guard_events (event_name text not null, payload_json text not null);
             create table extension_control_authority_proof (
                proof_id_hash text primary key, mutation_digest text not null,
                transition_revision integer not null, reserved_at text not null, consumed_at text);",
        )
        .unwrap();
        Self { root, db }
    }

    pub(super) fn request(
        &self,
        op: &str,
        catalog_digest: &str,
    ) -> ExtensionControlAuthorityRequestV1 {
        ExtensionControlAuthorityRequestV1 {
            schema: EXTENSION_CONTROL_AUTHORITY_REQUEST_SCHEMA.to_owned(),
            store_path: self.root.join("guard.db").to_string_lossy().into_owned(),
            guard_home: self.root.to_string_lossy().into_owned(),
            op: op.to_owned(),
            key_b64: Some(Base64UrlUnpadded::encode_string(&KEY)),
            catalog_digest: Some(catalog_digest.to_owned()),
            ..Default::default()
        }
    }

    /// Commits `layers` as `revision` the way the Python writer does and
    /// returns the anchor JSON for it.
    pub(super) fn commit(
        &self,
        revision: i64,
        catalog_digest: &str,
        layers: &[ExtensionControlLayer],
        phase: &str,
    ) -> String {
        self.commit_bound(revision, catalog_digest, layers, phase, None)
    }

    pub(super) fn commit_bound(
        &self,
        revision: i64,
        catalog_digest: &str,
        layers: &[ExtensionControlLayer],
        phase: &str,
        retained_pack: Option<&str>,
    ) -> String {
        let layers_json = layers_to_json(layers).unwrap();
        let previous_digest = if revision == 1 {
            catalog('0')
        } else {
            self.db
                .query_row(
                    "select snapshot_digest from extension_control_authority_transition where revision = ?",
                    params![revision - 1],
                    |row| row.get::<_, String>(0),
                )
                .unwrap()
        };
        let mut snapshot = object(json!({
            "revision": revision,
            "catalog_digest": catalog_digest,
            "layers_json": layers_json,
            "previous_digest": previous_digest,
            "committed_at": AT,
        }));
        if let Some(pack) = retained_pack {
            snapshot.insert("command_pack_record_digest".to_owned(), json!(pack));
        }
        let (snapshot_json, snapshot_digest, snapshot_mac) =
            authenticated_record(&snapshot, &KEY, SNAPSHOT_PURPOSE).unwrap();
        let hashes = [
            private_hash(&format!("actor-{revision}"), &KEY, "actor"),
            private_hash(&format!("idem-{revision}"), &KEY, "idempotency"),
            private_hash(&format!("nonce-{revision}"), &KEY, "nonce"),
        ];
        let transition = object(json!({
            "revision": revision,
            "previous_revision": revision - 1,
            "previous_digest": previous_digest,
            "snapshot_digest": snapshot_digest,
            "catalog_digest": catalog_digest,
            "actor_id_hash": hashes[0],
            "idempotency_key_hash": hashes[1],
            "nonce_hash": hashes[2],
            "created_at": AT,
            "phase": "prepared",
        }));
        let (transition_json, transition_digest, transition_mac) =
            authenticated_record(&transition, &KEY, TRANSITION_PURPOSE).unwrap();
        self.db
            .execute(
                "insert into extension_control_authority_transition values
                 (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    revision,
                    revision - 1,
                    phase,
                    hashes[0],
                    hashes[1],
                    hashes[2],
                    catalog_digest,
                    layers_json,
                    snapshot_json,
                    snapshot_digest,
                    snapshot_mac,
                    transition_json,
                    transition_digest,
                    transition_mac,
                    AT,
                    (phase == "committed").then_some(AT)
                ],
            )
            .unwrap();
        if phase == "committed" {
            self.db
                .execute(
                    "insert or replace into extension_control_authority_snapshot values (1, ?, ?, ?, ?, ?, ?, ?, ?)",
                    params![
                        revision, catalog_digest, layers_json, previous_digest, snapshot_json, snapshot_digest,
                        snapshot_mac, AT
                    ],
                )
                .unwrap();
        }
        anchor(revision, &snapshot_digest, phase)
    }

    fn record_manifest(&self, catalog_digest: &str, manifest: &Manifest) {
        let manifest_json = canonical(&json!(manifest)).unwrap();
        let payload = object(json!({
            "catalog_digest": catalog_digest,
            "manifest_json": manifest_json,
            "recorded_at": AT,
        }));
        let (record, digest, mac) =
            authenticated_record(&payload, &KEY, CATALOG_MANIFEST_PURPOSE).unwrap();
        self.db
            .execute(
                "insert into extension_control_catalog_manifest values (?, ?, ?, ?, ?, ?)",
                params![catalog_digest, manifest_json, record, digest, mac, AT],
            )
            .unwrap();
    }

    pub(super) fn set_state(&self, key: &str, value: &Value) {
        self.db
            .execute(
                "insert or replace into sync_state values (?, ?)",
                params![key, value.to_string()],
            )
            .unwrap();
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(super) fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        unreachable!()
    };
    map
}

pub(super) fn anchor(revision: i64, snapshot_digest: &str, phase: &str) -> String {
    let payload =
        object(json!({ "revision": revision, "snapshot_digest": snapshot_digest, "phase": phase }));
    let (record, digest, mac) = authenticated_record(&payload, &KEY, ANCHOR_PURPOSE).unwrap();
    json!({ "record": record, "digest": digest, "mac": mac }).to_string()
}

pub(super) fn layer(
    kind: ControlLayerKind,
    catalog_digest: &str,
    state: ControlState,
) -> ExtensionControlLayer {
    ExtensionControlLayer {
        schema_version: CONTROL_SCHEMA_VERSION.to_owned(),
        kind,
        catalog_digest: catalog_digest.to_owned(),
        global_lockdown: false,
        controls: vec![ExtensionControl {
            target: ControlTarget::new(ControlTargetKind::Extension, TARGET.to_owned()).unwrap(),
            state,
        }],
    }
}

pub(super) fn local(catalog_digest: &str) -> ExtensionControlLayer {
    layer(
        ControlLayerKind::LocalAdmin,
        catalog_digest,
        ControlState::Enabled,
    )
}

pub(super) fn manifest(fingerprint: &str) -> Manifest {
    Manifest::from([(format!("extension:{TARGET}"), fingerprint.to_owned())])
}

pub(super) fn run(request: &ExtensionControlAuthorityRequestV1) -> Value {
    evaluate(request).unwrap()
}

fn health(result: &Value) -> &str {
    result["view"]["health"].as_str().unwrap()
}

pub(super) fn read_request(
    home: &Home,
    catalog_digest: &str,
    anchor_json: Option<String>,
) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        anchor_json,
        ..home.request("read", catalog_digest)
    }
}

#[test]
fn empty_store_without_anchor_is_unenrolled() {
    let home = Home::new();
    assert_eq!(
        health(&run(&read_request(&home, &catalog('a'), None))),
        "unenrolled"
    );
}

#[test]
fn committed_authority_reads_protected() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let result = run(&read_request(&home, &catalog('a'), Some(anchor)));
    assert_eq!(health(&result), "protected");
    assert_eq!(result["view"]["revision"], json!(1));
    assert_eq!(
        result["view"]["layers"][0]["controls"][0]["target_id"],
        json!(TARGET)
    );
    assert_eq!(result["events"], json!([]));
}

#[test]
fn altered_snapshot_reads_tampered() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.db
        .execute(
            "update extension_control_authority_snapshot set committed_at = 'x'",
            [],
        )
        .unwrap();
    assert_eq!(
        health(&run(&read_request(&home, &catalog('a'), Some(anchor)))),
        "tampered"
    );
}

#[test]
fn lost_database_asks_for_restore_once() {
    let home = Home::new();
    let anchor_json = anchor(3, &catalog('b'), "committed");
    let result = run(&read_request(
        &home,
        &catalog('a'),
        Some(anchor_json.clone()),
    ));
    assert_eq!(result["action"]["action"], json!("restore_last_good"));
    assert_eq!(result["action"]["anchor"]["revision"], json!(3));
    let retried = ExtensionControlAuthorityRequestV1 {
        restore_attempted: true,
        ..read_request(&home, &catalog('a'), Some(anchor_json))
    };
    assert_eq!(health(&run(&retried)), "tampered");
}

#[test]
fn stale_anchor_is_a_rollback() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let ahead = anchor(2, &catalog('c'), "committed");
    assert_eq!(
        health(&run(&read_request(&home, &catalog('a'), Some(ahead)))),
        "tampered"
    );
}

#[test]
fn an_abandoned_prepare_is_asked_about_once_then_stops_holding_the_read_back() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[], "prepared");
    let result = run(&read_request(&home, &catalog('a'), Some(anchor.clone())));
    assert_eq!(result["action"]["action"], json!("roll_back_abandoned"));
    assert_eq!(result["action"]["revision"], json!(1));
    // The caller asked and the row is still here, which is what a reader
    // holding only a shared lease always sees: it may not write. The prepare
    // the anchor never moved past decides nothing, so the committed authority
    // below it is served and keeps enforcing rather than stopping every
    // command on the device.
    let retried = ExtensionControlAuthorityRequestV1 {
        rollback_attempted: true,
        ..read_request(&home, &catalog('a'), Some(anchor))
    };
    let served = run(&retried);
    assert_eq!(health(&served), "protected");
    assert_eq!(served["view"]["revision"], json!(1));
}

#[test]
fn an_interrupted_commit_is_resumed_instead_of_held_for_recovery() {
    let home = Home::new();
    let _ = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let _ = home.commit(2, &catalog('a'), &[], "prepared");
    // The commit sealed the anchor over revision 2 and died before the row
    // said so, which is the shape a crash between those two writes leaves.
    let sealed: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let anchored = anchor(2, &sealed, "anchored");

    let result = run(&read_request(&home, &catalog('a'), Some(anchored.clone())));
    assert_eq!(result["action"]["action"], json!("resume_pending"));
    assert_eq!(result["action"]["revision"], json!(2));
    assert_eq!(result["action"]["current_revision"], json!(1));

    // A caller that could not apply the resume asks again, and the read
    // reports the state it found rather than asking a second time.
    let retried = ExtensionControlAuthorityRequestV1 {
        resume_attempted: true,
        ..read_request(&home, &catalog('a'), Some(anchored.clone()))
    };
    assert_eq!(health(&run(&retried)), "recovery-required");

    // The request that prepared that row settles it under the single-use
    // proof it still holds, so its own read leaves the row alone.
    let owner = ExtensionControlAuthorityRequestV1 {
        rollback_attempted: true,
        ..read_request(&home, &catalog('a'), Some(anchored))
    };
    assert_eq!(health(&run(&owner)), "recovery-required");
}

#[test]
fn a_sealed_head_whose_phase_never_flipped_is_finished_instead_of_held() {
    let home = Home::new();
    let _ = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    // The same interrupted commit one step later: the row and the snapshot
    // both reached the sealed revision and the anchor died before it said the
    // revision was closed, which is what a failed final anchor write leaves.
    let sealed: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let anchored = anchor(1, &sealed, "anchored");

    let result = run(&read_request(&home, &catalog('a'), Some(anchored.clone())));
    assert_eq!(result["action"]["action"], json!("resume_pending"));
    assert_eq!(result["action"]["revision"], json!(1));
    assert_eq!(result["action"]["current_revision"], json!(1));

    // A caller that could not apply the resume asks again, and the read
    // reports the state it found rather than asking a second time.
    let retried = ExtensionControlAuthorityRequestV1 {
        resume_attempted: true,
        ..read_request(&home, &catalog('a'), Some(anchored.clone()))
    };
    assert_eq!(health(&run(&retried)), "recovery-required");

    // The request that prepared that row settles it under its own proof.
    let owner = ExtensionControlAuthorityRequestV1 {
        rollback_attempted: true,
        ..read_request(&home, &catalog('a'), Some(anchored))
    };
    assert_eq!(health(&run(&owner)), "recovery-required");
}

#[test]
fn a_prepared_anchor_over_the_head_is_still_held_for_recovery() {
    let home = Home::new();
    let _ = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let sealed: String = home
        .db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    // Nothing has sealed a head to finish, so this one is left alone.
    let prepared = anchor(1, &sealed, "prepared");
    assert_eq!(
        health(&run(&read_request(&home, &catalog('a'), Some(prepared)))),
        "recovery-required"
    );
}

#[test]
fn catalog_change_needs_a_registry_then_the_manifest_then_migrates() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let plain = read_request(&home, &catalog('b'), Some(anchor.clone()));
    assert_eq!(health(&run(&plain)), "tampered");

    let migrating = ExtensionControlAuthorityRequestV1 {
        migration: true,
        allow_migration: true,
        ..read_request(&home, &catalog('b'), Some(anchor))
    };
    assert_eq!(run(&migrating)["need"], json!("current_manifest"));

    let with_manifest = ExtensionControlAuthorityRequestV1 {
        current_manifest: Some(manifest("fp1")),
        ..migrating.clone()
    };
    let action = &run(&with_manifest)["action"];
    assert_eq!(action["action"], json!("migrate_catalog"));
    assert_eq!(action["previous_catalog_digest"], json!(catalog('a')));
    assert_eq!(action["layers"][0]["catalog_digest"], json!(catalog('b')));
    assert_eq!(action["retired_targets"], json!([]));

    let read_only = ExtensionControlAuthorityRequestV1 {
        allow_migration: false,
        ..with_manifest
    };
    let result = run(&read_only);
    assert_eq!(health(&result), "protected");
    assert_eq!(result["view"]["catalog_digest"], json!(catalog('b')));
}

#[test]
fn a_waiting_prepare_holds_the_catalog_migration_back() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[], "prepared");
    // The rollback was asked for and the row is still inside its retry
    // window, so the source read serves revision 1. A migration planned from
    // that view would take revision 2, which the prepare still holds.
    let request = ExtensionControlAuthorityRequestV1 {
        migration: true,
        allow_migration: true,
        rollback_attempted: true,
        current_manifest: Some(manifest("fp1")),
        ..read_request(&home, &catalog('b'), Some(anchor))
    };
    let result = run(&request);
    assert!(result.get("action").is_none(), "{result}");
    assert_eq!(health(&result), "protected");
    assert_eq!(result["view"]["revision"], json!(1));
    assert_eq!(result["view"]["catalog_digest"], json!(catalog('b')));
}

#[test]
fn migration_retires_targets_the_new_catalog_dropped() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let request = ExtensionControlAuthorityRequestV1 {
        migration: true,
        allow_migration: true,
        current_manifest: Some(Manifest::new()),
        ..read_request(&home, &catalog('b'), Some(anchor))
    };
    assert_eq!(run(&request)["action"]["retired_targets"], json!([TARGET]));
}

#[test]
fn missing_store_is_degraded() {
    let home = Home::new();
    let empty = root();
    let request = ExtensionControlAuthorityRequestV1 {
        store_path: empty.join("guard.db").to_string_lossy().into_owned(),
        guard_home: empty.to_string_lossy().into_owned(),
        ..home.request("read", &catalog('a'))
    };
    let result = run(&request);
    let _ = fs::remove_dir_all(&empty);
    assert_eq!(result["fault"], json!("degraded"));
    assert_eq!(
        result["reason"],
        json!("extension control authority store unavailable")
    );
}

#[test]
fn manifest_round_trips_and_sync_skips_an_unchanged_digest() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.record_manifest(&catalog('a'), &manifest("fp1"));
    let loaded = run(&home.request("load_manifest", &catalog('a')));
    assert_eq!(loaded["manifest"], json!(manifest("fp1")));

    let view = run(&read_request(&home, &catalog('a'), Some(anchor)))["view"].clone();
    let sync = ExtensionControlAuthorityRequestV1 {
        view: Some(view),
        current_manifest_sha256: Some(manifest_sha256(&manifest("fp1")).unwrap()),
        ..home.request("sync_manifest", &catalog('a'))
    };
    assert_eq!(run(&sync)["stale"], Value::Null);

    let changed = ExtensionControlAuthorityRequestV1 {
        current_manifest_sha256: Some(catalog('f')),
        ..sync.clone()
    };
    assert_eq!(run(&changed)["need"], json!("current_manifest"));

    let drifted = ExtensionControlAuthorityRequestV1 {
        current_manifest: Some(manifest("fp2")),
        current_manifest_sha256: None,
        ..sync
    };
    let result = run(&drifted);
    assert_eq!(result["stale"], json!(manifest("fp1")));
    // The control's fingerprint changed, so a read-only caller serves it
    // unbound until the writer migrates.
    assert_eq!(result["view"]["layers"][0]["controls"], json!([]));
}

#[test]
fn read_composed_settles_in_one_round_trip_or_hands_back_the_base_view() {
    let home = Home::new();
    let anchor = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let request = ExtensionControlAuthorityRequestV1 {
        migration: true,
        current_manifest_sha256: Some(manifest_sha256(&manifest("fp1")).unwrap()),
        ..read_request(&home, &catalog('a'), Some(anchor))
    };
    let request = ExtensionControlAuthorityRequestV1 {
        op: "read_composed".to_owned(),
        ..request
    };
    // No manifest is recorded yet, so a writer owes the first one: the base
    // view comes back alone for the separate ops to finish.
    let writer = ExtensionControlAuthorityRequestV1 {
        allow_migration: true,
        ..request.clone()
    };
    let result = run(&writer);
    assert_eq!(health(&result), "protected");
    assert_eq!(result.get("composed"), None);

    home.record_manifest(&catalog('a'), &manifest("fp1"));
    let result = run(&request);
    assert_eq!(result["composed"], result["view"]);
    assert_eq!(result["stale"], Value::Null);

    let drifted = ExtensionControlAuthorityRequestV1 {
        current_manifest: Some(manifest("fp2")),
        current_manifest_sha256: Some(manifest_sha256(&manifest("fp2")).unwrap()),
        ..request
    };
    let result = run(&drifted);
    assert_eq!(result["stale"], json!(manifest("fp1")));
    assert_eq!(
        result["view"]["layers"][0]["controls"][0]["target_id"],
        json!(TARGET)
    );
    assert_eq!(result["composed"]["layers"][0]["controls"], json!([]));
}
