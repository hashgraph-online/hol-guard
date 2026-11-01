//! Durable erasure is a privacy intent, never a runtime or permission record.
use super::*;
use guard_context_assistance::{ContextDocument, EvidenceCache, RuntimeError, SavedNotes};
fn legacy(f: &Fixture) -> String {
    let cache = EvidenceCache::open(&f.home).unwrap();
    let key = "a".repeat(64);
    let mut slot = cache.open_slot(&key, 1, 100).unwrap();
    let docs = vec![ContextDocument {
        id: "note:erase-this".into(),
        text: "Native retained erasure fixture".into(),
        start_line: 1,
    }];
    slot.stage_notes("0", &docs, 101).unwrap();
    slot.commit_notes(
        "1",
        Some(SavedNotes {
            documents: docs,
            basis: std::collections::BTreeSet::from(["file:one".into()]),
            version: "1".into(),
            valid_until_ms: 10000,
        }),
        102,
    )
    .unwrap();
    drop(slot);
    drop(cache);
    key
}
fn private(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}
fn corrupt_generation(f: &Fixture, key: &str) -> PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let root = f.home.join("context-assistance/evidence-generations");
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    private(&root.join("store.lock"), b"");
    let generation = root.join("d".repeat(64));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&generation)
        .unwrap();
    private(&generation.join("state.json"), b"{damaged metadata}");
    let cache = generation.join("cache");
    fs::DirBuilder::new().mode(0o700).create(&cache).unwrap();
    private(&cache.join("cache.lock"), b"");
    let slot = cache.join(key);
    fs::DirBuilder::new().mode(0o700).create(&slot).unwrap();
    fs::copy(
        f.home
            .join("context-assistance/saved-evidence")
            .join(key)
            .join("state.json"),
        slot.join("state.json"),
    )
    .unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(slot.join("sdk"))
        .unwrap();
    generation
}
#[test]
fn full_erasure_resumes_after_legacy_deletion_and_clears_corrupt_generations_and_selection() {
    let f = Fixture::new(true);
    let key = legacy(&f);
    let gen = corrupt_generation(&f, &key);
    let (owner, _) = f.begin();
    drop(owner);
    let prefs = fs::read(f.home.join("config.toml")).unwrap();
    DataRemoval::fail_next_after_legacy();
    assert!(matches!(
        crate::context_assistance_data::remove(&f.home),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert_eq!(
        EvidenceCache::existing(&f.home)
            .unwrap()
            .unwrap()
            .summary()
            .unwrap()
            .slots,
        0
    );
    assert!(gen.exists());
    assert!(f.home.join("cigar-erasure.json").exists());
    assert!(DataRemoval::check_clear(&f.home).is_err());
    let owner = Owner::acquire(&f.home).unwrap();
    assert!(owner
        .prepare_for(&jobs::SwitchRequest {
            job_id: "must-not-prepare".into(),
            target_runtime_id: "new".into(),
            expected_generation: 4,
            rollback: false
        })
        .is_err());
    drop(owner);
    assert_eq!(
        crate::context_assistance_data::inspect(&f.home)["status"],
        "repair_required"
    );
    crate::context_assistance_data::remove(&f.home).unwrap();
    assert!(!gen.exists());
    assert!(!f.home.join("cigar-erasure.json").exists());
    assert!(!f.home.join("cigar-lifecycle.json").exists());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), prefs);
    assert_eq!(
        crate::context_assistance_data::inspect(&f.home)["status"],
        "empty"
    );
}
#[test]
fn an_unacknowledged_intent_is_observed_without_republication_before_any_data_removal() {
    let f = Fixture::new(false);
    let key = legacy(&f);
    crate::guard_config_update::io::fail_next_erasure_intent_after_rename();
    assert!(matches!(
        crate::context_assistance_data::remove(&f.home),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert!(f
        .home
        .join("context-assistance/saved-evidence")
        .join(&key)
        .exists());
    let intent = fs::read(f.home.join("cigar-erasure.json")).unwrap();
    let removal = DataRemoval::acquire(&f.home).unwrap();
    assert_eq!(fs::read(f.home.join("cigar-erasure.json")).unwrap(), intent);
    removal.remove().unwrap();
    assert!(DataRemoval::check_clear(&f.home).is_ok());
}
#[test]
fn readonly_or_linked_erasure_marker_never_removes_data_or_unrelated_targets() {
    for linked in [false, true] {
        let f = Fixture::new(false);
        let key = legacy(&f);
        let marker = f.home.join("cigar-erasure.json");
        if linked {
            let target = f.home.join("operator-text");
            private(&target, b"preserve unrelated bytes");
            std::os::unix::fs::symlink(&target, &marker).unwrap();
        } else {
            private(&marker, b"pending");
            fs::set_permissions(&marker, fs::Permissions::from_mode(0o400)).unwrap();
        }
        assert!(DataRemoval::check_clear(&f.home).is_err());
        assert!(crate::context_assistance_data::remove(&f.home).is_err());
        assert!(f
            .home
            .join("context-assistance/saved-evidence")
            .join(key)
            .exists());
        if linked {
            assert_eq!(
                fs::read(f.home.join("operator-text")).unwrap(),
                b"preserve unrelated bytes"
            );
        }
    }
}
#[test]
fn busy_cache_keeps_durable_intent_until_its_real_owner_releases() {
    let f = Fixture::new(false);
    let _key = legacy(&f);
    let cache = EvidenceCache::existing(&f.home).unwrap().unwrap();
    assert!(matches!(
        crate::context_assistance_data::remove(&f.home),
        Err(RuntimeError::Busy)
    ));
    assert!(f.home.join("cigar-erasure.json").exists());
    assert_eq!(cache.summary().unwrap().slots, 1);
    drop(cache);
    crate::context_assistance_data::remove(&f.home).unwrap();
    assert!(!f.home.join("cigar-erasure.json").exists());
}
