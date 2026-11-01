//! Native-data attribution cases; no SDK or release qualification is forged.
use super::*;
use crate::{EvidenceCacheLocation, EvidenceErasureScope, EvidenceScopeOwner};
fn row(location: EvidenceCacheLocation, key: &str, scope: &EvidenceScope) -> EvidenceScopeOwner {
    EvidenceScopeOwner {
        location,
        slot_key: key.into(),
        scope_sha256: scope.namespace_sha256().into(),
    }
}
#[test]
fn unknown_legacy_slots_refuse_before_mutation_and_authenticated_other_scopes_are_preserved() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let key = f.key("dashboard");
    let other = f.key("otherapp");
    drop(cache.open_slot(&key, 1, NOW).unwrap());
    drop(cache.open_slot(&other, 1, NOW).unwrap());
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let spec =
        EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::from(["a".repeat(64)])).unwrap();
    assert!(matches!(
        spec.ensure_attributed(&f.0, Some(&cache), &[]),
        Err(RuntimeError::StorageRepairRequired)
    ));
    assert_eq!(cache.summary().unwrap().slots, 2);
    let other_scope = EvidenceScope::new("otherapp", &f.0).unwrap();
    let full = spec
        .ensure_attributed(
            &f.0,
            Some(&cache),
            &[row(EvidenceCacheLocation::Legacy, &other, &other_scope)],
        )
        .unwrap();
    assert_eq!(full.legacy_keys(), &BTreeSet::from([key]));
    EvidenceGenerationStore::forget_scope_copies(&f.0, &full, Some(&cache), NOW + 1).unwrap();
    assert_eq!(cache.slot_keys().unwrap(), vec![other]);
}
#[test]
fn recorded_old_worker_namespaces_are_erased_without_the_old_installation() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let key = EvidenceCache::key("dashboard", &f.0, &"b".repeat(64)).unwrap();
    drop(cache.open_slot(&key, 1, NOW).unwrap());
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let spec =
        EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::from(["a".repeat(64)])).unwrap();
    assert!(spec.ensure_attributed(&f.0, Some(&cache), &[]).is_err());
    let full = spec
        .ensure_attributed(
            &f.0,
            Some(&cache),
            &[row(EvidenceCacheLocation::Legacy, &key, &scope)],
        )
        .unwrap();
    assert_eq!(full.legacy_keys(), &BTreeSet::from([key]));
    assert_eq!(
        EvidenceGenerationStore::forget_scope_copies(&f.0, &full, Some(&cache), NOW + 1)
            .unwrap()
            .removed_slots,
        1
    );
}
#[test]
fn generation_lineage_attributes_its_snapshot_and_native_rows_cover_later_apps() {
    let f = Fixture::new();
    let source = EvidenceCache::open(&f.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, note) = notes(&f, &source, &from);
    let store = EvidenceGenerationStore::open(&f.0).unwrap();
    let g = prepare(&store, &source, &from, &to, &note, "ownership-later-app");
    let cache = g.open_cache().unwrap();
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let own = scope.key(&to).unwrap();
    drop(cache.open_slot(&own, 1, NOW).unwrap());
    let other_scope = EvidenceScope::new("otherapp", &f.0).unwrap();
    let other_key = other_scope.key(&to).unwrap();
    let other = cache.open_slot(&other_key, 1, NOW).unwrap();
    drop(slot);
    drop(source);
    let spec = EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::new()).unwrap();
    assert!(spec.ensure_attributed(&f.0, Some(&cache), &[]).is_err());
    let location = EvidenceCacheLocation::Generation {
        generation_id: g.id().into(),
    };
    let full = spec
        .ensure_attributed(
            &f.0,
            Some(&cache),
            &[row(location, &other_key, &other_scope)],
        )
        .unwrap();
    assert_eq!(
        EvidenceGenerationStore::forget_scope_copies(&f.0, &full, Some(&cache), NOW + 1)
            .unwrap()
            .removed_slots,
        2
    );
    assert_eq!(cache.summary().unwrap().active_slots, 1);
    assert_eq!(other.notes_version(), "0");
}
#[test]
fn conflicting_attribution_invalid_locations_and_oversized_rows_refuse() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let key = f.key("dashboard");
    drop(cache.open_slot(&key, 1, NOW).unwrap());
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let spec =
        EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::from(["a".repeat(64)])).unwrap();
    let wrong = EvidenceScope::new("otherapp", &f.0).unwrap();
    let conflict = row(EvidenceCacheLocation::Legacy, &key, &wrong);
    assert!(spec
        .ensure_attributed(&f.0, Some(&cache), &[conflict])
        .is_err());
    let invalid = row(
        EvidenceCacheLocation::Generation {
            generation_id: "../outside".into(),
        },
        &key,
        &scope,
    );
    assert!(spec
        .ensure_attributed(&f.0, Some(&cache), &[invalid])
        .is_err());
    let rows = vec![row(EvidenceCacheLocation::Legacy, &key, &scope); 65];
    assert!(spec.ensure_attributed(&f.0, Some(&cache), &rows).is_err());
    assert_eq!(cache.summary().unwrap().slots, 1);
}
#[test]
fn attribution_preflight_can_borrow_live_scopes_but_never_a_foreign_profile_cache() {
    let f = Fixture::new();
    let cache = EvidenceCache::open(&f.0).unwrap();
    let key = f.key("dashboard");
    let held = cache.open_slot(&key, 1, NOW).unwrap();
    let scope = EvidenceScope::new("dashboard", &f.0).unwrap();
    let spec =
        EvidenceErasureScope::capture(&f.0, &scope, &BTreeSet::from(["a".repeat(64)])).unwrap();
    assert!(spec.ensure_attributed(&f.0, Some(&cache), &[]).is_ok());
    assert_eq!(cache.summary().unwrap().active_slots, 1);
    let other = Fixture::new();
    let foreign = EvidenceCache::open(&other.0).unwrap();
    assert!(matches!(
        spec.ensure_attributed(&f.0, Some(&foreign), &[]),
        Err(RuntimeError::ScopeDenied)
    ));
    assert_eq!(held.notes_version(), "0");
}
