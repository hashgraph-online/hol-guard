use super::*;
use guard_cigar_release::{
    SelectionData, SelectionInstallation, SelectionOrigin, SelectionPointer, SelectionRecord,
};

fn selected(data: SelectionData) -> SelectionRecord {
    SelectionRecord {
        schema: "guard-cigar-selection.v2".into(),
        revision: 1,
        current: SelectionPointer {
            runtime: SelectionInstallation {
                installation_id: "current".into(),
                installation_sha256: "1".repeat(64),
                approval_sha256: "2".repeat(64),
                producer_sha256: "3".repeat(64),
                origin: SelectionOrigin::Enrolled {
                    sdk_version: "0.14.1".into(),
                    core_version: "0.14.0".into(),
                    profile_id: "fixture".into(),
                    adapter_id: "guard-cigar-python-sdk-v1".into(),
                    adapter_revision: 1,
                },
            },
            data,
        },
        last_good: None,
        transaction: None,
    }
}
fn empty(
    store: &EvidenceGenerationStore,
    source: &EvidenceCache,
    from: &EvidenceUpgradeProducer,
    to: &EvidenceUpgradeProducer,
    id: &str,
) -> crate::PreparedEvidenceGeneration {
    store
        .prepare(
            EvidencePreparation {
                request_id: id,
                source,
                snapshot: &source.upgrade_inventory(NOW).unwrap(),
                from,
                to,
                notes: &[],
            },
            NOW,
        )
        .unwrap()
}
#[test]
fn ready_cleanup_requires_the_owning_request_and_preserves_current_and_last_good() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = empty(&store, &source, &from, &to, "owned");
    assert_eq!(g.describe().unwrap()["phase"], "ready");
    let selection = selected(SelectionData::Generation {
        generation_id: g.id().into(),
    });
    assert!(matches!(
        store.discard_unselected(g.id(), "owned", &selection),
        Err(RuntimeError::ScopeDenied)
    ));
    let mut retained = selected(SelectionData::Memory);
    retained.last_good = Some(selection.current);
    assert!(matches!(
        store.discard_unselected(g.id(), "owned", &retained),
        Err(RuntimeError::ScopeDenied)
    ));
    let clear = selected(SelectionData::Memory);
    assert!(matches!(
        store.discard_unselected(g.id(), "another-request", &clear),
        Err(RuntimeError::ScopeDenied)
    ));
    store.discard_unselected(g.id(), "owned", &clear).unwrap();
    assert!(store.list().unwrap().is_empty());
}
#[test]
fn ready_cleanup_waits_for_the_actual_native_cache_owner_to_release() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = empty(&store, &source, &from, &to, "busy-target");
    let cache = g.open_cache().unwrap();
    assert!(matches!(
        store.discard_unselected(g.id(), "busy-target", &selected(SelectionData::Memory)),
        Err(RuntimeError::Busy)
    ));
    assert!(generation_path(&f, g.id()).exists());
    drop(cache);
    store
        .discard_unselected(g.id(), "busy-target", &selected(SelectionData::Memory))
        .unwrap();
}
#[test]
fn an_unmapped_parent_is_retained_transitively_even_when_it_is_not_last_good() {
    let f = Fixture::new();
    let original = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let parent = empty(&store, &original, &from, &to, "parent");
    let cache = parent.open_cache().unwrap();
    let slot = cache.open_slot(&"a".repeat(64), 1, NOW).unwrap();
    drop(slot);
    let child = empty(&store, &cache, &to, &from, "child");
    drop(cache);
    assert_eq!(child.describe().unwrap()["preserved_unmapped_scopes"], 1);
    let selection = selected(SelectionData::Generation {
        generation_id: child.id().into(),
    });
    assert!(matches!(
        store.discard_unselected(parent.id(), "parent", &selection),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(generation_path(&f, parent.id()).exists());
}
#[test]
fn invalid_or_missing_retention_references_refuse_before_any_deletion() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = empty(&store, &source, &from, &to, "keep-on-error");
    let missing = selected(SelectionData::Generation {
        generation_id: "e".repeat(64),
    });
    assert!(store
        .discard_unselected(g.id(), "keep-on-error", &missing)
        .is_err());
    let mut invalid = selected(SelectionData::Memory);
    invalid.schema = "unknown".into();
    assert!(store
        .discard_unselected(g.id(), "keep-on-error", &invalid)
        .is_err());
    assert!(generation_path(&f, g.id()).exists());
}
