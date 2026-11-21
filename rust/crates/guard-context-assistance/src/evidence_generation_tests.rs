//! Synthetic serializer/filesystem cases. They do not manufacture SDK
//! qualification; the separate actual test covers the opaque export path.
use super::*;
#[path = "evidence_generation_deferred_tests.rs"]
mod deferred_tests;
#[path = "evidence_generation_lifecycle_tests.rs"]
mod lifecycle_tests;
#[path = "evidence_scope_ownership_tests.rs"]
mod ownership_tests;
#[path = "evidence_generation_scope_erasure_tests.rs"]
mod scope_erasure_tests;
use crate::evidence_cache::transfer::TransferData;
use crate::{
    EvidenceGenerationStore, EvidencePreparation, EvidenceScope, EvidenceUpgradeProducer,
    VerifiedNoteTransfer,
};
use std::os::unix::fs::OpenOptionsExt;

fn notes(
    fixture: &Fixture,
    cache: &EvidenceCache,
    from: &EvidenceUpgradeProducer,
) -> (EvidenceSlot, VerifiedNoteTransfer) {
    let scope = EvidenceScope::new("dashboard", &fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 1, NOW).unwrap();
    slot.stage_notes("0", &doc(), NOW).unwrap();
    slot.commit_notes("1", Some(saved("1")), NOW).unwrap();
    let data = TransferData {
        schema: "guard-cigar-reviewed-note-transfer.v1".into(),
        scope_sha256: scope.namespace_sha256().into(),
        source_key: key,
        source_producer_sha256: from.identity_sha256().into(),
        source_release: from.release_binding().unwrap(),
        source_manifest_sha256: format!(
            "{:x}",
            Sha256::digest(std::fs::read(slot.directory.path.join("state.json")).unwrap())
        ),
        source_notes_version: "1".into(),
        source_observed_at_ms: NOW,
        source_created_at_ms: NOW,
        expires_at_ms: slot.expires_at_ms(),
        captured_at_ms: NOW,
        basis_sha256: BTreeMap::from([("file:example".into(), "a".repeat(64))]),
        notes: Some(saved("1")),
    };
    data.validate(NOW).unwrap();
    (slot, VerifiedNoteTransfer { data })
}
fn prepare(
    store: &EvidenceGenerationStore,
    cache: &EvidenceCache,
    from: &EvidenceUpgradeProducer,
    to: &EvidenceUpgradeProducer,
    note: &VerifiedNoteTransfer,
    id: &str,
) -> crate::PreparedEvidenceGeneration {
    store
        .prepare(
            EvidencePreparation {
                request_id: id,
                source: cache,
                snapshot: &cache.upgrade_inventory(NOW).unwrap(),
                from,
                to,
                notes: std::slice::from_ref(note),
            },
            NOW,
        )
        .unwrap()
}
fn generation_path(fixture: &Fixture, id: &str) -> PathBuf {
    fixture
        .0
        .join("context-assistance/evidence-generations")
        .join(id)
}
#[test]
fn generation_absence_stays_absent_and_summary_never_contains_reviewed_text() {
    let fixture = Fixture::new();
    assert!(EvidenceGenerationStore::existing(&fixture.0)
        .unwrap()
        .is_none());
    assert_eq!(
        EvidenceGenerationStore::forget_existing(&fixture.0).unwrap(),
        0
    );
    assert!(!fixture.0.join("context-assistance").exists());
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (_slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "prepare-notes");
    let summary = prepared.describe().unwrap().to_string();
    for private in [
        "human-admitted",
        "file:example",
        fixture.0.to_str().unwrap(),
    ] {
        assert!(!summary.contains(private));
    }
    let scope = EvidenceScope::new("dashboard", &fixture.0).unwrap();
    let id = prepared.id().to_owned();
    drop(prepared);
    drop(store);
    let store = EvidenceGenerationStore::existing(&fixture.0)
        .unwrap()
        .unwrap();
    let loaded = store.load(&id).unwrap().transfer(&scope, &to, NOW).unwrap();
    assert!(loaded.data.notes.unwrap().documents == doc());
    assert!(
        !generation_path(&fixture, &id).join("cache").exists(),
        "metadata reload cannot create/probe an SDK cache"
    );
}
#[test]
fn preparation_is_idempotent_but_reused_requests_cannot_change_target_or_source_snapshot() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (mut slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "same-request");
    assert_eq!(
        prepared.id(),
        prepare(&store, &cache, &from, &to, &note, "same-request").id()
    );
    let snapshot = cache.upgrade_inventory(NOW).unwrap();
    assert!(matches!(
        store.prepare(
            EvidencePreparation {
                request_id: "same-request",
                source: &cache,
                snapshot: &snapshot,
                from: &from,
                to: &from,
                notes: std::slice::from_ref(&note)
            },
            NOW
        ),
        Err(RuntimeError::ContextConflict)
    ));
    slot.stage_notes("1", &[], NOW).unwrap();
    assert!(matches!(
        store.prepare(
            EvidencePreparation {
                request_id: "stale",
                source: &cache,
                snapshot: &snapshot,
                from: &from,
                to: &to,
                notes: std::slice::from_ref(&note)
            },
            NOW
        ),
        Err(RuntimeError::ContextStale)
    ));
    assert_eq!(store.list().unwrap().len(), 1);
}
#[test]
fn prepared_note_mac_refuses_modified_text_moved_records_and_other_home_context() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (_slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "auth-context");
    let path = generation_path(&fixture, prepared.id());
    let original = std::fs::read(path.join("state.json")).unwrap();
    let changed = String::from_utf8(original.clone())
        .unwrap()
        .replace("human-admitted", "tampered-evidence");
    assert_ne!(original, changed.as_bytes());
    std::fs::write(path.join("state.json"), changed).unwrap();
    assert!(matches!(
        store.load(prepared.id()),
        Err(RuntimeError::StorageRepairRequired)
    ));
    std::fs::write(path.join("state.json"), &original).unwrap();
    let other = "e".repeat(64);
    let moved = generation_path(&fixture, &other);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&moved)
        .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(moved.join("state.json"))
        .unwrap();
    std::io::Write::write_all(&mut file, &original).unwrap();
    drop(file);
    assert!(matches!(
        store.load(&other),
        Err(RuntimeError::StorageRepairRequired)
    ));
    let another = Fixture::new();
    let other_store = EvidenceGenerationStore::open(&another.0).unwrap();
    drop(other_store);
    // A same-user file copy still cannot turn another profile into this home.
    let root = fixture.0.join("context-assistance/evidence-generations");
    let target_root = another.0.join("context-assistance/evidence-generations");
    std::fs::copy(
        root.join("authority.key"),
        target_root.join("authority.key"),
    )
    .unwrap();
    let target = target_root.join(prepared.id());
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&target)
        .unwrap();
    std::fs::copy(path.join("state.json"), target.join("state.json")).unwrap();
    let other_store = EvidenceGenerationStore::existing(&another.0)
        .unwrap()
        .unwrap();
    assert!(matches!(
        other_store.load(prepared.id()),
        Err(RuntimeError::StorageRepairRequired)
    ));
}
#[test]
fn preparation_preserves_source_bytes_and_has_separate_bounded_generation_capacity() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (slot, note) = notes(&fixture, &cache, &from);
    let before = std::fs::read(slot.directory.path.join("state.json")).unwrap();
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    for id in ["one", "two", "three"] {
        prepare(&store, &cache, &from, &to, &note, id);
    }
    assert!(matches!(
        store.prepare(
            EvidencePreparation {
                request_id: "four",
                source: &cache,
                snapshot: &cache.upgrade_inventory(NOW).unwrap(),
                from: &from,
                to: &to,
                notes: std::slice::from_ref(&note)
            },
            NOW
        ),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(
        before,
        std::fs::read(slot.directory.path.join("state.json")).unwrap()
    );
    assert_eq!(store.list().unwrap().len(), 3);
}
#[test]
fn source_scope_and_target_identity_cannot_be_substituted_and_live_cache_blocks_removal() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (_slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "scoped-data");
    let wrong = EvidenceScope::new("another-app", &fixture.0).unwrap();
    assert!(matches!(
        prepared.transfer(&wrong, &to, NOW),
        Err(RuntimeError::ScopeDenied)
    ));
    let scope = EvidenceScope::new("dashboard", &fixture.0).unwrap();
    assert!(matches!(
        prepared.transfer(&scope, &from, NOW),
        Err(RuntimeError::ContextConflict)
    ));
    let held = prepared.open_cache().unwrap();
    assert!(matches!(
        store.discard_prepared(prepared.id()),
        Err(RuntimeError::Busy)
    ));
    assert!(matches!(
        EvidenceGenerationStore::forget_existing(&fixture.0),
        Err(RuntimeError::Busy)
    ));
    drop(held);
    store.discard_prepared(prepared.id()).unwrap();
    assert!(store.list().unwrap().is_empty());
}
#[test]
fn original_note_expiry_and_shortened_retention_remove_prepared_text_without_probing() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (_slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "expiry");
    store.sweep(1, NOW + 1_800_000).unwrap();
    let raw = std::fs::read_to_string(generation_path(&fixture, prepared.id()).join("state.json"))
        .unwrap();
    assert!(!raw.contains("human-admitted"));
    assert!(!generation_path(&fixture, prepared.id())
        .join("cache")
        .exists());
    let scope = EvidenceScope::new("dashboard", &fixture.0).unwrap();
    assert!(prepared.transfer(&scope, &to, NOW + 1_800_000).is_err());
}
#[test]
fn missing_or_changed_key_refuses_silent_reapproval_but_explicit_forget_repairs_the_data_role() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (_slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "missing-key");
    let key = fixture
        .0
        .join("context-assistance/evidence-generations/authority.key");
    std::fs::write(&key, [7; 32]).unwrap();
    assert!(matches!(
        store.load(prepared.id()),
        Err(RuntimeError::StorageRepairRequired)
    ));
    std::fs::remove_file(&key).unwrap();
    assert!(EvidenceGenerationStore::open(&fixture.0).is_err());
    assert!(!key.exists());
    assert_eq!(
        EvidenceGenerationStore::forget_existing(&fixture.0).unwrap(),
        1
    );
    let new = EvidenceGenerationStore::open(&fixture.0).unwrap();
    assert!(new.list().unwrap().is_empty());
    assert!(store.load(prepared.id()).is_err());
}
#[test]
fn corrupt_metadata_can_be_explicitly_removed_but_links_never_escape_the_data_root() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::upgrade_tests::producer(false);
    let to = super::upgrade_tests::producer(true);
    let (_slot, note) = notes(&fixture, &cache, &from);
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = prepare(&store, &cache, &from, &to, &note, "unsafe-link");
    let outside = fixture.0.join("outside");
    std::fs::write(&outside, b"preserve this unrelated file").unwrap();
    let state = generation_path(&fixture, prepared.id()).join("state.json");
    std::fs::remove_file(&state).unwrap();
    std::os::unix::fs::symlink(&outside, &state).unwrap();
    assert!(EvidenceGenerationStore::forget_existing(&fixture.0).is_err());
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"preserve this unrelated file"
    );
    std::fs::remove_file(&state).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&state)
        .unwrap();
    std::io::Write::write_all(&mut file, b"{corrupt private note metadata").unwrap();
    drop(file);
    assert_eq!(
        EvidenceGenerationStore::forget_existing(&fixture.0).unwrap(),
        1
    );
}

#[path = "evidence_generation_capture_tests.rs"]
mod capture;
