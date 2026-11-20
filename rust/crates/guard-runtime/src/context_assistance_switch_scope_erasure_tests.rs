//! Private native intent tests. Fixtures grant no SDK/release qualification.
use super::*;
use guard_context_assistance::{EvidenceCache, EvidenceScope, RuntimeError};
use std::collections::BTreeSet;

fn seed(f: &Fixture) -> (String, String) {
    let cache = EvidenceCache::open(&f.home).unwrap();
    let key = EvidenceCache::key("codex", &f.home, &"a".repeat(64)).unwrap();
    let other = EvidenceCache::key("dashboard", &f.home, &"a".repeat(64)).unwrap();
    drop(
        cache
            .open_slot(&key, 1, crate::context_assistance_data::now_ms())
            .unwrap(),
    );
    drop(
        cache
            .open_slot(&other, 1, crate::context_assistance_data::now_ms())
            .unwrap(),
    );
    scope_index::remember(
        &f.home,
        &cache,
        &EvidenceScope::new("codex", &f.home).unwrap(),
        &key,
    )
    .unwrap();
    scope_index::remember(
        &f.home,
        &cache,
        &EvidenceScope::new("dashboard", &f.home).unwrap(),
        &other,
    )
    .unwrap();
    (key, other)
}
fn acquire(f: &Fixture) -> Result<ScopeRemoval, RuntimeError> {
    ScopeRemoval::acquire(
        &f.home,
        &EvidenceScope::new("codex", &f.home).unwrap(),
        &BTreeSet::from(["a".repeat(64)]),
        None,
    )
}
fn selected(f: &Fixture) -> (Vec<u8>, Vec<u8>) {
    let mut owner = Owner::acquire(&f.home).unwrap();
    owner.initialize(pointer("old")).unwrap();
    (
        fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        fs::read(f.home.join("cigar-lifecycle.key")).unwrap(),
    )
}
fn remaining(f: &Fixture) -> usize {
    EvidenceCache::existing(&f.home)
        .unwrap()
        .unwrap()
        .summary()
        .unwrap()
        .slots
}
#[test]
fn dropped_scoped_intent_resumes_without_sdk_or_grants_and_preserves_selection_and_other_data() {
    let f = Fixture::new(false);
    let (key, other) = seed(&f);
    let (record, key_bytes) = selected(&f);
    let prefs = fs::read(f.home.join("config.toml")).unwrap();
    let removal = acquire(&f).unwrap();
    assert!(Owner::acquire(&f.home).is_err());
    assert!(DataRemoval::check_clear(&f.home).is_err());
    let marker = fs::read(f.home.join("cigar-erasure.json")).unwrap();
    assert!(!String::from_utf8(marker.clone())
        .unwrap()
        .contains(f.home.to_str().unwrap()));
    drop(removal); // process-loss boundary before any data mutation
    assert_eq!(remaining(&f), 2);
    let resumed = ScopeRemoval::resume(&f.home).unwrap();
    assert_eq!(fs::read(f.home.join("cigar-erasure.json")).unwrap(), marker);
    assert_eq!(resumed.remove(None).unwrap().removed_slots, 1);
    assert!(!f
        .home
        .join("context-assistance/saved-evidence")
        .join(key)
        .exists());
    assert!(f
        .home
        .join("context-assistance/saved-evidence")
        .join(other)
        .exists());
    assert_eq!(remaining(&f), 1);
    assert!(DataRemoval::check_clear(&f.home).is_ok());
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        record
    );
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.key")).unwrap(),
        key_bytes
    );
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), prefs);
    assert!(!f.home.join("context-assistance/installations").exists());
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
}
#[test]
fn lost_scope_intent_publication_acknowledgment_retains_data_and_resumes_exact_private_intent() {
    let f = Fixture::new(false);
    seed(&f);
    crate::guard_config_update::io::fail_next_erasure_intent_after_rename();
    assert!(matches!(
        acquire(&f),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert_eq!(remaining(&f), 2);
    let marker = fs::read(f.home.join("cigar-erasure.json")).unwrap();
    let resumed = ScopeRemoval::resume(&f.home).unwrap();
    assert_eq!(fs::read(f.home.join("cigar-erasure.json")).unwrap(), marker);
    resumed.remove(None).unwrap();
    assert_eq!(remaining(&f), 1);
}
#[test]
fn interrupted_scope_completion_keeps_marker_after_data_removal_and_explicit_resume_is_idempotent()
{
    let f = Fixture::new(false);
    seed(&f);
    let removal = acquire(&f).unwrap();
    ScopeRemoval::fail_next_after_purge();
    assert!(matches!(
        removal.remove(None),
        Err(RuntimeError::StorageOutcomeUnknown)
    ));
    assert_eq!(remaining(&f), 1);
    assert!(DataRemoval::check_clear(&f.home).is_err());
    assert_eq!(
        crate::context_assistance_data::inspect(&f.home)["status"],
        "repair_required"
    );
    let marker = fs::read(f.home.join("cigar-erasure.json")).unwrap();
    let resumed = ScopeRemoval::resume(&f.home).unwrap();
    assert_eq!(fs::read(f.home.join("cigar-erasure.json")).unwrap(), marker);
    assert_eq!(resumed.remove(None).unwrap().removed_slots, 0);
    assert_eq!(remaining(&f), 1);
    assert!(DataRemoval::check_clear(&f.home).is_ok());
}
#[test]
fn an_active_scope_owner_keeps_data_and_intent_until_real_lease_release() {
    let f = Fixture::new(false);
    let (key, _) = seed(&f);
    let cache = EvidenceCache::existing(&f.home).unwrap().unwrap();
    let slot = cache
        .open_slot(&key, 1, crate::context_assistance_data::now_ms())
        .unwrap();
    assert!(matches!(
        ScopeRemoval::acquire(
            &f.home,
            &EvidenceScope::new("codex", &f.home).unwrap(),
            &BTreeSet::from(["a".repeat(64)]),
            Some(&cache),
        )
        .unwrap()
        .remove(Some(&cache)),
        Err(RuntimeError::Busy)
    ));
    assert_eq!(cache.summary().unwrap().slots, 2);
    assert!(DataRemoval::check_clear(&f.home).is_err());
    drop(slot);
    drop(cache);
    ScopeRemoval::resume(&f.home).unwrap().remove(None).unwrap();
    assert_eq!(remaining(&f), 1);
}
#[test]
fn tampered_or_wrong_role_markers_refuse_scoped_resume_and_need_explicit_full_erasure() {
    for mode in ["scope", "selection", "full"] {
        let f = Fixture::new(false);
        seed(&f);
        let _selected = selected(&f);
        drop(acquire(&f).unwrap());
        let path = f.home.join("cigar-erasure.json");
        let raw = match mode {
            "scope" => {
                let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                let mut payload: Value = serde_json::from_str(envelope["payload"].as_str().unwrap()).unwrap();
                payload["scope_sha256"] = json!("f".repeat(64));
                envelope["payload"] = json!(serde_json::to_string(&payload).unwrap());
                serde_json::to_vec(&envelope).unwrap()
            }
            "selection" => fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
            _ => br#"{"schema":"guard-cigar-full-erasure.v1","scope":"all_saved","request_id":"untrusted"}"#.to_vec(),
        };
        fs::write(&path, &raw).unwrap();
        assert!(matches!(
            ScopeRemoval::resume(&f.home),
            Err(RuntimeError::StorageRepairRequired)
        ));
        assert_eq!(remaining(&f), 2);
        assert_eq!(fs::read(&path).unwrap(), raw);
        DataRemoval::acquire(&f.home).unwrap().remove().unwrap();
        assert_eq!(remaining(&f), 0);
        assert!(DataRemoval::check_clear(&f.home).is_ok());
    }
}

#[test]
fn even_a_copied_key_and_valid_intent_cannot_replay_scope_deletion_in_another_profile() {
    let source = Fixture::new(false);
    seed(&source);
    drop(acquire(&source).unwrap());
    let other = Fixture::new(false);
    seed(&other);
    for name in ["cigar-lifecycle.key", "cigar-erasure.json"] {
        if name == "cigar-lifecycle.key" {
            fs::write(
                other.home.join(name),
                fs::read(source.home.join(name)).unwrap(),
            )
            .unwrap();
            continue;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(other.home.join(name))
            .unwrap()
            .write_all(&fs::read(source.home.join(name)).unwrap())
            .unwrap();
    }
    assert!(matches!(
        ScopeRemoval::resume(&other.home),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert_eq!(remaining(&source), 2);
    assert_eq!(remaining(&other), 2);
    ScopeRemoval::resume(&source.home)
        .unwrap()
        .remove(None)
        .unwrap();
    assert_eq!(remaining(&source), 1);
    assert_eq!(remaining(&other), 2);
}

#[test]
fn scoped_erasure_after_completed_switch_preserves_the_entire_selection_and_last_good() {
    let f = Fixture::new(false);
    seed(&f);
    let (mut owner, settings) = f.begin();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.advance(SelectionPhase::Healthy).unwrap();
    owner.advance(SelectionPhase::Completed).unwrap();
    assert!(owner.record().unwrap().last_good.is_some());
    let selection = fs::read(f.home.join("cigar-lifecycle.json")).unwrap();
    let key = fs::read(f.home.join("cigar-lifecycle.key")).unwrap();
    let prefs = fs::read(f.home.join("config.toml")).unwrap();
    drop(owner);
    acquire(&f).unwrap().remove(None).unwrap();
    assert_eq!(remaining(&f), 1);
    assert_eq!(
        fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        selection
    );
    assert_eq!(fs::read(f.home.join("cigar-lifecycle.key")).unwrap(), key);
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), prefs);
    assert!(Owner::acquire(&f.home)
        .unwrap()
        .record()
        .unwrap()
        .last_good
        .is_some());
}
