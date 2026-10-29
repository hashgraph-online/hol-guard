use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "evidence_generation_tests.rs"]
mod generation_tests;
#[path = "evidence_upgrade_tests.rs"]
mod upgrade_tests;

const NOW: u64 = 1_700_000_000_000;
static FIXTURE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "guard-cache-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            FIXTURE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn root(&self) -> PathBuf {
        self.0.join("context-assistance/saved-evidence")
    }
    fn key(&self, app: &str) -> String {
        EvidenceCache::key(app, &self.0, &"a".repeat(64)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn doc() -> Vec<ContextDocument> {
    vec![ContextDocument {
        id: "note:reviewed".into(),
        text: "Only human-admitted evidence belongs here.".into(),
        start_line: 1,
    }]
}
fn saved(version: &str) -> SavedNotes {
    SavedNotes {
        documents: doc(),
        basis: BTreeSet::from(["file:example".into()]),
        version: version.into(),
        valid_until_ms: NOW + 1_800_000,
    }
}
fn empty_hash() -> String {
    records::documents_hash(&[]).unwrap()
}

#[test]
fn absent_cache_inspection_is_inactive_and_namespaces_are_opaque() {
    let fixture = Fixture::new();
    assert!(EvidenceCache::existing(&fixture.0.join("not-created"))
        .unwrap()
        .is_none());
    assert!(!fixture.0.join("not-created").exists());
    assert!(EvidenceCache::existing(&fixture.0).unwrap().is_none());
    assert!(!fixture.0.join("context-assistance").exists());
    let key = fixture.key("dashboard");
    assert!(valid_key(&key));
    assert_eq!(key, fixture.key("dashboard"));
    assert_ne!(key, fixture.key("codex"));
    assert!(EvidenceCache::key("../outside", &fixture.0, &"a".repeat(64)).is_err());
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let slot = cache.open_slot(&key, 24, NOW).unwrap();
    assert_eq!(slot.domain_name(), format!("cache:{key}"));
    let raw = std::fs::read_to_string(fixture.root().join(&key).join("state.json")).unwrap();
    assert!(!raw.contains(fixture.0.to_str().unwrap()));
    assert!(!raw.contains("dashboard"));
    assert_eq!(cache.summary().unwrap().active_slots, 1);
}

#[test]
fn health_reports_pending_corrupt_and_expired_metadata_without_source_or_sdk_access() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 1, NOW).unwrap();
    slot.stage_notes("0", &[], NOW).unwrap();
    let health = cache.health(NOW).unwrap();
    assert_eq!(health.unresolved_writes, 1);
    assert_eq!(health.invalid_records, 0);
    assert_eq!(cache.health(NOW + 3_600_000).unwrap().expired_slots, 1);
    drop(slot);
    std::fs::write(fixture.root().join(&key).join("state.json"), b"{invalid").unwrap();
    assert_eq!(cache.health(NOW).unwrap().invalid_records, 1);
    cache.forget(&key).unwrap();
    assert_eq!(cache.health(NOW).unwrap().summary.slots, 0);
}

#[test]
fn slot_and_database_leases_retain_exclusive_ownership_until_domain_close() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let slot = cache.open_slot(&key, 24, NOW).unwrap();
    assert!(matches!(
        cache.open_slot(&key, 24, NOW),
        Err(RuntimeError::Busy)
    ));
    assert!(matches!(
        EvidenceCache::open(&fixture.0),
        Err(RuntimeError::Busy)
    ));
    let storage = slot.broker_storage().unwrap();
    assert!(matches!(slot.broker_storage(), Err(RuntimeError::Busy)));
    assert!(matches!(slot.remove(), Err(RuntimeError::Busy)));
    assert!(matches!(cache.forget(&key), Err(RuntimeError::Busy)));
    drop(cache);
    assert!(matches!(
        EvidenceCache::open(&fixture.0),
        Err(RuntimeError::Busy)
    ));
    drop(storage);
    let cache = EvidenceCache::existing(&fixture.0).unwrap().unwrap();
    assert_eq!(cache.summary().unwrap().active_slots, 0);
    assert_eq!(cache.forget_all().unwrap(), 1);
    assert_eq!(cache.summary().unwrap().slots, 0);
}

#[test]
fn quota_and_retention_cover_inactive_stores_without_opening_sdk() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    for n in 0..MAX_SLOTS {
        drop(
            cache
                .open_slot(&fixture.key(&format!("app{n}")), 24, NOW)
                .unwrap(),
        );
    }
    assert_eq!(cache.summary().unwrap().slots, MAX_SLOTS);
    assert!(matches!(
        cache.open_slot(&fixture.key("ninth"), 24, NOW),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(cache.sweep(1, NOW + 3_600_000).unwrap(), MAX_SLOTS);
    assert_eq!(cache.summary().unwrap().bytes, 0);
    let slot = cache.open_slot(&fixture.key("next"), 1, NOW).unwrap();
    assert_eq!(
        cache.sweep(1, NOW + 3_600_000).unwrap(),
        0,
        "active owner must close first"
    );
    drop(slot);
    assert_eq!(cache.sweep(1, NOW + 3_600_000).unwrap(), 1);
}

#[test]
fn clock_rollback_and_malformed_records_preserve_saved_data_for_repair() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    drop(cache.open_slot(&key, 24, NOW).unwrap());
    assert!(matches!(
        cache.open_slot(&key, 24, NOW - 1),
        Err(RuntimeError::StorageRepairRequired)
    ));
    let state = fixture.root().join(&key).join("state.json");
    std::fs::write(&state, b"{broken").unwrap();
    assert!(matches!(
        cache.sweep(24, NOW),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert!(state.exists());
    cache.forget(&key).unwrap();
    assert!(!state.exists());
}

#[test]
fn staged_admission_records_only_a_hash_and_reconciles_without_retry() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 24, NOW).unwrap();
    slot.stage_notes("0", &[], NOW).unwrap();
    slot.commit_notes("1", None, NOW).unwrap();
    slot.stage_notes("1", &doc(), NOW).unwrap();
    let state = fixture.root().join(&key).join("state.json");
    assert!(!std::fs::read_to_string(&state)
        .unwrap()
        .contains(&doc()[0].text));
    drop(slot);
    let mut slot = cache.open_slot(&key, 24, NOW + 1).unwrap();
    assert!(slot.has_pending_write());
    slot.reconcile_notes("1", Some(&empty_hash()), NOW + 1)
        .unwrap();
    assert!(
        !slot.has_pending_write(),
        "confirmed uncommitted intent needs no SDK mutation"
    );
    slot.stage_notes("1", &doc(), NOW + 1).unwrap();
    let hash = records::documents_hash(&doc()).unwrap();
    assert!(matches!(
        slot.reconcile_notes("2", Some(&hash), NOW + 1),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert!(
        state.exists(),
        "SDK-committed text lost before metadata commit must not be invented"
    );
    slot.commit_notes("2", Some(saved("2")), NOW + 1).unwrap();
    drop(slot);
    let mut slot = cache.open_slot(&key, 24, NOW + 2).unwrap();
    slot.reconcile_notes("2", Some(&hash), NOW + 2).unwrap();
    assert_eq!(slot.notes().unwrap().documents[0].text, doc()[0].text);
    slot.stage_notes("2", &[], NOW + 2).unwrap();
    drop(slot);
    let mut slot = cache.open_slot(&key, 24, NOW + 3).unwrap();
    slot.reconcile_notes("3", Some(&empty_hash()), NOW + 3)
        .unwrap();
    assert!(slot.notes().is_none());
    assert_eq!(slot.notes_version(), "3");
}

#[test]
fn interrupted_metadata_writes_poison_only_the_open_handle_and_recover_actual_commit() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 24, NOW).unwrap();
    fs::WRITE_FAULT.with(|fault| fault.set(1));
    assert!(matches!(
        slot.stage_notes("0", &[], NOW),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert!(matches!(
        slot.revalidate(NOW),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    drop(slot);
    let mut slot = cache.open_slot(&key, 24, NOW).unwrap();
    slot.reconcile_notes("0", None, NOW).unwrap();
    slot.stage_notes("0", &[], NOW).unwrap();
    fs::WRITE_FAULT.with(|fault| fault.set(2));
    assert!(matches!(
        slot.commit_notes("1", None, NOW),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    drop(slot);
    let mut slot = cache.open_slot(&key, 24, NOW).unwrap();
    slot.reconcile_notes("1", Some(&empty_hash()), NOW).unwrap();
    assert!(!slot.has_pending_write());
}

#[test]
fn unexpected_files_links_and_permissions_refuse_removal_without_touching_other_data() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    drop(cache.open_slot(&key, 24, NOW).unwrap());
    let path = fixture.root().join(&key);
    let foreign = path.join("outside.txt");
    std::fs::write(&foreign, b"unrelated").unwrap();
    assert!(cache.forget(&key).is_err());
    assert_eq!(std::fs::read(&foreign).unwrap(), b"unrelated");
    std::fs::remove_file(foreign).unwrap();
    let state = path.join("state.json");
    let target = fixture.0.join("outside");
    std::fs::rename(&state, &target).unwrap();
    std::os::unix::fs::symlink(&target, &state).unwrap();
    assert!(cache.forget(&key).is_err());
    assert!(target.exists());
    std::fs::remove_file(&state).unwrap();
    std::fs::hard_link(&target, &state).unwrap();
    assert!(cache.forget(&key).is_err());
    std::fs::remove_file(&state).unwrap();
    std::fs::rename(&target, &state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(cache.forget(&key).is_err());
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    cache.forget(&key).unwrap();
}

#[test]
fn saved_note_limits_and_private_directory_identity_are_enforced() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 24, NOW).unwrap();
    let mut large = doc();
    large[0].text = "a".repeat(16 * 1024 + 1);
    assert!(slot.stage_notes("0", &large, NOW).is_err());
    assert!(!slot.has_pending_write());
    let before = fixture.root().join(&key);
    std::fs::rename(&before, fixture.root().join("displaced")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&before)
        .unwrap();
    assert!(matches!(
        slot.revalidate(NOW),
        Err(RuntimeError::ContextStale)
    ));
}
