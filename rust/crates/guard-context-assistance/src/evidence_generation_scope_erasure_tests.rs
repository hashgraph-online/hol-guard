//! Serializer/filesystem scope-copy tests, not SDK release qualification.
use super::*;
use std::io::Write;

fn copy_slot(cache: &EvidenceCache, key: &str) -> EvidenceSlot {
    let mut slot = cache.open_slot(key, 1, NOW).unwrap();
    slot.stage_notes("0", &doc(), NOW).unwrap();
    slot.commit_notes("1", Some(saved("1")), NOW).unwrap();
    slot
}
#[test]
fn scope_erase_removes_prepared_text_and_legacy_copy_but_preserves_other_apps() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let key = slot.lease.key.clone();
    let other_key = f.key("otherapp");
    drop(copy_slot(&source, &other_key));
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let generation = prepare(&store, &source, &from, &to, &note, "erase-one-scope");
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    drop(slot);
    let erased = EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &BTreeSet::new(),
        Some(&source),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(erased.changed_records, 1);
    assert_eq!(erased.removed_slots, 1);
    assert_eq!(source.keys().unwrap(), vec![other_key]);
    assert!(!source.root.directory.path.join(key).exists());
    assert!(generation.transfer(&scope, &to, NOW + 1).is_err());
    let sealed = std::fs::read(generation_path(&f, generation.id()).join("state.json")).unwrap();
    assert!(!String::from_utf8(sealed)
        .unwrap()
        .contains("human-admitted"));
    let retry = EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &BTreeSet::new(),
        Some(&source),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(retry.changed_records, 0);
    assert_eq!(retry.removed_slots, 0);
}
#[test]
fn scope_erase_borrows_current_generation_without_disrupting_other_live_slots() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let generation = prepare(&store, &source, &from, &to, &note, "erase-current");
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let target = generation.open_cache().unwrap();
    let target_key = scope.key(&to).unwrap();
    drop(copy_slot(&target, &target_key));
    let other = EvidenceScope::new("otherapp", &f.0)
        .unwrap()
        .key(&to)
        .unwrap();
    let live_other = copy_slot(&target, &other);
    drop(slot);
    drop(source);
    let erased = EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &BTreeSet::new(),
        Some(&target),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(erased.removed_slots, 2);
    assert_eq!(target.keys().unwrap(), vec![other]);
    assert!(live_other.notes().unwrap().documents == doc());
    assert_eq!(target.summary().unwrap().active_slots, 1);
}
#[test]
fn scope_erase_refuses_busy_scope_before_any_prepared_text_changes() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (_held, note) = notes(&f, &source, &from);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = prepare(&store, &source, &from, &to, &note, "busy-scope");
    let before = std::fs::read(generation_path(&f, g.id()).join("state.json")).unwrap();
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    assert!(matches!(
        EvidenceGenerationStore::forget_scope_existing(
            &f.0,
            &scope,
            &BTreeSet::new(),
            Some(&source),
            NOW + 1,
        ),
        Err(RuntimeError::Busy)
    ));
    assert_eq!(
        std::fs::read(generation_path(&f, g.id()).join("state.json")).unwrap(),
        before
    );
    assert!(g.transfer(&scope, &to, NOW + 1).is_ok());
}
#[test]
fn absent_scope_erase_stays_absent_and_a_foreign_current_cache_cannot_be_used() {
    let f = Fixture::new();
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    assert_eq!(
        EvidenceGenerationStore::forget_scope_existing(&f.0, &scope, &BTreeSet::new(), None, NOW,)
            .unwrap()
            .removed_slots,
        0
    );
    assert!(!f.0.join("context-assistance").exists());
    let other = Fixture::new();
    let cache = EvidenceCache::open(&other.0).unwrap();
    let key = other.key("dashboard");
    drop(copy_slot(&cache, &key));
    assert!(matches!(
        EvidenceGenerationStore::forget_scope_existing(
            &f.0,
            &scope,
            &BTreeSet::new(),
            Some(&cache),
            NOW,
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    assert_eq!(cache.summary().unwrap().slots, 1);
}
#[test]
fn measured_legacy_keys_can_be_erased_without_a_generation_and_do_not_guess_other_keys() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let key = f.key("dashboard");
    drop(copy_slot(&source, &key));
    let unrelated = f.key("otherapp");
    drop(copy_slot(&source, &unrelated));
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let workers = BTreeSet::from(["a".repeat(64)]);
    let result = EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &workers,
        Some(&source),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(result.removed_slots, 1);
    assert_eq!(source.keys().unwrap(), vec![unrelated]);
    assert!(EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &BTreeSet::from(["invalid".into()]),
        Some(&source),
        NOW,
    )
    .is_err());
}

#[test]
fn interrupted_scope_record_writes_resume_without_losing_the_original_source_mapping() {
    for phase in [1, 2] {
        let f = Fixture::new();
        let source = EvidenceCache::open(&f.0).unwrap();
        let from = super::super::upgrade_tests::producer(false);
        let to = super::super::upgrade_tests::producer(true);
        let (slot, note) = notes(&f, &source, &from);
        let store = EvidenceGenerationStore::open(&f.0).unwrap();
        let g = prepare(&store, &source, &from, &to, &note, "interrupt-scope-record");
        let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
        let intent = crate::EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::new()).unwrap();
        drop(slot);
        fs::WRITE_FAULT.with(|fault| fault.set(phase));
        assert!(matches!(
            EvidenceGenerationStore::forget_scope_copies(&f.0, &intent, Some(&source), NOW + 1),
            Err(RuntimeError::StorageOutcomeUnknown)
        ));
        assert_eq!(source.summary().unwrap().slots, 1);
        let erased =
            EvidenceGenerationStore::forget_scope_copies(&f.0, &intent, Some(&source), NOW + 2)
                .unwrap();
        assert_eq!(erased.removed_slots, 1);
        assert_eq!(source.summary().unwrap().slots, 0);
        assert!(g.transfer(&scope, &to, NOW + 2).is_err());
        let dir = generation_path(&f, g.id());
        assert!(!std::fs::read_to_string(dir.join("state.json"))
            .unwrap()
            .contains("human-admitted"));
        assert!(!dir.join("state.next").exists());
    }
}
#[test]
fn damaged_authenticated_lineage_refuses_before_erasing_any_current_or_legacy_slot() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = prepare(&store, &source, &from, &to, &note, "damaged-scope-record");
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    drop(slot);
    std::fs::write(
        generation_path(&f, g.id()).join("state.json"),
        b"{damaged-lineage",
    )
    .unwrap();
    assert!(EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &BTreeSet::new(),
        Some(&source),
        NOW + 1,
    )
    .is_err());
    assert_eq!(source.summary().unwrap().slots, 1);
}
#[test]
fn another_workspace_scope_does_not_erase_a_matching_app_in_this_profile() {
    let f = Fixture::new();
    let other_workspace = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = prepare(
        &store,
        &source,
        &from,
        &to,
        &note,
        "workspace-bound-erasure",
    );
    drop(slot);
    let scope = EvidenceScope::new("dashboard", &other_workspace.0).unwrap();
    let erased = EvidenceGenerationStore::forget_scope_existing(
        &f.0,
        &scope,
        &BTreeSet::from(["a".repeat(64)]),
        Some(&source),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(erased.removed_slots, 0);
    assert_eq!(erased.changed_records, 0);
    assert_eq!(source.summary().unwrap().slots, 1);
    let original = EvidenceScope::new("dashboard", &f.0).unwrap();
    assert!(g.transfer(&original, &to, NOW + 1).is_ok());
}

#[test]
fn scope_erase_removes_abandoned_staging_even_when_the_committed_scope_is_already_erased() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let other = f.key("otherapp");
    drop(copy_slot(&source, &other));
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = prepare(
        &store,
        &source,
        &from,
        &to,
        &note,
        "abandoned-scope-staging",
    );
    let path = generation_path(&f, g.id());
    let abandoned = std::fs::read(path.join("state.json")).unwrap();
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let intent = crate::EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::new()).unwrap();
    drop(slot);
    EvidenceGenerationStore::forget_scope_copies(&f.0, &intent, Some(&source), NOW + 1).unwrap();
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path.join("state.next"))
        .unwrap()
        .write_all(&abandoned)
        .unwrap();
    let committed = std::fs::read(path.join("state.json")).unwrap();
    let result =
        EvidenceGenerationStore::forget_scope_copies(&f.0, &intent, Some(&source), NOW + 2)
            .unwrap();
    assert_eq!(result.changed_records, 0);
    assert_eq!(result.removed_staging_records, 1);
    assert!(!path.join("state.next").exists());
    assert_eq!(std::fs::read(path.join("state.json")).unwrap(), committed);
    assert_eq!(source.keys().unwrap(), vec![other]);
}
