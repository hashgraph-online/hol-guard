//! Synthetic MAC/serializer/retention tests; real SDK proof is separate.
use super::*;
use crate::{EvidenceCacheLocation, EvidenceErasureScope, EvidenceScopeOwner};
fn cold(
    store: &EvidenceGenerationStore,
    cache: &EvidenceCache,
    from: &EvidenceUpgradeProducer,
    to: &EvidenceUpgradeProducer,
    notes: &[VerifiedNoteTransfer],
    id: &str,
    time: u64,
) -> crate::PreparedEvidenceGeneration {
    store
        .prepare_cold(
            EvidencePreparation {
                request_id: id,
                source: cache,
                snapshot: &cache.upgrade_inventory(time).unwrap(),
                from,
                to,
                notes,
            },
            time,
        )
        .unwrap()
}
#[test]
fn cold_data_is_ready_but_unadmitted_and_summary_omits_text_and_paths() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &cache, &from);
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let expires = slot.expires_at_ms();
    drop(slot);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let gen = cold(
        &store,
        &cache,
        &from,
        &to,
        std::slice::from_ref(&note),
        "cold-ready",
        NOW,
    );
    let value = gen.describe().unwrap();
    assert_eq!(value["phase"], "ready");
    assert_eq!(value["deferred_scopes"], 1);
    assert_eq!(value["pending_scopes"], 0);
    assert_eq!(value["authority_restored"], false);
    assert!(gen.has_deferred_scope(&scope, &to).unwrap());
    assert_eq!(
        gen.transfer(&scope, &to, NOW).unwrap().data.expires_at_ms,
        expires
    );
    assert!(!value.to_string().contains("human-admitted"));
    assert!(!value.to_string().contains(f.0.to_str().unwrap()));
    assert!(!generation_path(&f, gen.id()).join("cache").exists());
}
#[test]
fn cold_preparation_requires_all_unexpired_cache_slots_without_sweeping_originals() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &cache, &from);
    drop(slot);
    let other = f.key("otherapp");
    let mut extra = cache.open_slot(&other, 1, NOW).unwrap();
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    assert!(matches!(
        store.prepare_cold(
            EvidencePreparation {
                request_id: "incomplete",
                source: &cache,
                snapshot: &cache.upgrade_inventory(NOW).unwrap(),
                from: &from,
                to: &to,
                notes: std::slice::from_ref(&note)
            },
            NOW
        ),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert!(store.list().unwrap().is_empty());
    let mut state = extra.state.clone();
    state.expires_at_ms = NOW + 1;
    extra.save(state).unwrap();
    drop(extra);
    let gen = cold(
        &store,
        &cache,
        &from,
        &to,
        std::slice::from_ref(&note),
        "expired-only-unmapped",
        NOW + 2,
    );
    assert_eq!(gen.describe().unwrap()["deferred_scopes"], 1);
    assert!(cache.root.directory.path.join(other).exists());
}
#[test]
fn reselection_and_live_preparation_keep_original_deferred_provenance_without_cache_copies() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &cache, &from);
    drop(slot);
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let digest = note.documents_sha256().unwrap();
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let a = cold(
        &store,
        &cache,
        &from,
        &to,
        std::slice::from_ref(&note),
        "cold-first",
        NOW,
    );
    let ac = a.open_cache().unwrap();
    let b = cold(&store, &ac, &to, &from, &[], "cold-second", NOW + 1);
    let copy = b.transfer(&scope, &from, NOW + 1).unwrap();
    assert_eq!(copy.data.source_producer_sha256, from.identity_sha256());
    assert_eq!(copy.documents_sha256().unwrap(), digest);
    assert_eq!(copy.data.expires_at_ms, note.data.expires_at_ms);
    assert_eq!(
        b.describe().unwrap()["source_producer_sha256"],
        to.identity_sha256()
    );
    drop(ac);
    let bc = b.open_cache().unwrap();
    let c = store
        .prepare(
            EvidencePreparation {
                request_id: "live-inherits-deferred",
                source: &bc,
                snapshot: &bc.upgrade_inventory(NOW + 2).unwrap(),
                from: &from,
                to: &to,
                notes: &[],
            },
            NOW + 2,
        )
        .unwrap();
    assert_eq!(c.describe().unwrap()["phase"], "ready");
    assert_eq!(c.describe().unwrap()["deferred_scopes"], 1);
    assert_eq!(
        c.transfer(&scope, &to, NOW + 2)
            .unwrap()
            .documents_sha256()
            .unwrap(),
        digest
    );
}
#[test]
fn expiry_removes_deferred_text_and_reselection_does_not_resurrect_it() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &cache, &from);
    drop(slot);
    let expires = note.data.expires_at_ms;
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let a = cold(
        &store,
        &cache,
        &from,
        &to,
        std::slice::from_ref(&note),
        "cold-expiry",
        NOW,
    );
    let ac = a.open_cache().unwrap();
    store.sweep(1, expires).unwrap();
    assert_eq!(a.describe().unwrap()["deferred_scopes"], 0);
    let b = cold(&store, &ac, &to, &from, &[], "expired-no-carry", expires);
    assert_eq!(b.describe().unwrap()["scopes"], 0);
    let raw = std::fs::read_to_string(generation_path(&f, a.id()).join("state.json")).unwrap();
    assert!(!raw.contains("human-admitted"));
}
#[test]
fn authenticated_scoped_erasure_removes_ancestral_deferred_copies_and_keeps_other_apps() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let legacy = slot.lease.key.clone();
    drop(slot);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let a = cold(
        &store,
        &source,
        &from,
        &to,
        std::slice::from_ref(&note),
        "cold-erase-a",
        NOW,
    );
    let ac = a.open_cache().unwrap();
    let b = cold(&store, &ac, &to, &from, &[], "cold-erase-b", NOW);
    drop(ac);
    let other_key = f.key("otherapp");
    let other = source.open_slot(&other_key, 1, NOW).unwrap();
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let other_scope = EvidenceScope::new("otherapp", &f.0).unwrap();
    let owners = vec![
        EvidenceScopeOwner {
            location: EvidenceCacheLocation::Legacy,
            slot_key: legacy.clone(),
            scope_sha256: scope.namespace_sha256().into(),
        },
        EvidenceScopeOwner {
            location: EvidenceCacheLocation::Legacy,
            slot_key: other_key.clone(),
            scope_sha256: other_scope.namespace_sha256().into(),
        },
    ];
    let removal = EvidenceErasureScope::from_authenticated_intent(
        scope.namespace_sha256(),
        BTreeSet::from([legacy]),
    )
    .unwrap()
    .ensure_attributed(&f.0, Some(&source), &owners)
    .unwrap();
    let result =
        EvidenceGenerationStore::forget_scope_copies(&f.0, &removal, Some(&source), NOW + 1)
            .unwrap();
    assert_eq!(result.changed_records, 2);
    assert_eq!(result.removed_slots, 1);
    assert_eq!(source.keys().unwrap(), vec![other_key]);
    assert_eq!(other.notes_version(), "0");
    for gen in [&a, &b] {
        assert_eq!(gen.describe().unwrap()["deferred_scopes"], 0);
        let raw =
            std::fs::read_to_string(generation_path(&f, gen.id()).join("state.json")).unwrap();
        assert!(!raw.contains("human-admitted"));
    }
}

#[test]
fn reduced_retention_is_durable_and_stales_a_previous_deferred_preparation_identity() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (mut slot, mut note) = notes(&f, &cache, &from);
    let long = NOW + 2 * 3_600_000;
    let mut state = slot.state.clone();
    state.expires_at_ms = long;
    state.notes.as_mut().unwrap().valid_until_ms = long;
    slot.save(state).unwrap();
    note.data.expires_at_ms = long;
    note.data.notes.as_mut().unwrap().valid_until_ms = long;
    note.data.source_manifest_sha256 = format!(
        "{:x}",
        Sha256::digest(slot.directory.read("state.json").unwrap())
    );
    drop(slot);
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let a = cold(
        &store,
        &cache,
        &from,
        &to,
        std::slice::from_ref(&note),
        "retention-source",
        NOW,
    );
    let ac = a.open_cache().unwrap();
    let b = cold(&store, &ac, &to, &from, &[], "retention-retry", NOW + 1);
    assert_eq!(
        b.transfer(&scope, &from, NOW + 1)
            .unwrap()
            .data
            .expires_at_ms,
        long
    );
    let before_semantic = a.semantic_sha256().unwrap();
    assert_eq!(
        before_semantic,
        store.load(a.id()).unwrap().semantic_sha256().unwrap()
    );
    store.sweep(1, NOW + 2).unwrap();
    assert_ne!(before_semantic, a.semantic_sha256().unwrap());
    let short = NOW + 3_600_000;
    for (g, p) in [(&a, &to), (&b, &from)] {
        let data = g.transfer(&scope, p, NOW + 2).unwrap();
        assert_eq!(data.data.expires_at_ms, short);
        assert_eq!(data.data.notes.unwrap().valid_until_ms, short);
    }
    store.sweep(2, NOW + 3).unwrap();
    assert_eq!(
        a.transfer(&scope, &to, NOW + 3).unwrap().data.expires_at_ms,
        short
    );
    assert!(matches!(
        store.prepare_cold(
            EvidencePreparation {
                request_id: "retention-retry",
                source: &ac,
                snapshot: &ac.upgrade_inventory(NOW + 3).unwrap(),
                from: &to,
                to: &from,
                notes: &[]
            },
            NOW + 3
        ),
        Err(RuntimeError::ContextConflict)
    ));
}
