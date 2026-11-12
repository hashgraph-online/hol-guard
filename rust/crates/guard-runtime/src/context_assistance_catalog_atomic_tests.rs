//! The ordinary signed provider uses the atomic pair without relaxing trust,
//! ledger continuity, preferences or exact installed-receipt checks.
use super::*;
use crate::guard_config_update::io::{catalog_fault_next, CatalogFault, LifecycleFile, WriteLock};
#[test]
fn unknown_first_publication_is_authenticated_and_explicit_retry_keeps_the_key() {
    let f = Fixture::new();
    f.configure();
    let d = f.doc();
    let raw = f.sign(&d);
    let before = b"mode='enforce'\n[context_assistance]\nenabled=false\nruntime_id='kept'\n";
    fs::write(f.home.join("config.toml"), before).unwrap();
    catalog_fault_next(CatalogFault::Error("init_renamed"));
    assert!(import(&f.home, &raw)
        .unwrap_err()
        .ends_with("cigar_catalog_commit_outcome_unknown"));
    let s = installed(&f.home).unwrap();
    assert_eq!(s.source, "cached");
    let verified = receipt(&d, s.catalog.checkpoint());
    assert!(verified.resolve(&s.catalog, &[Feature::Graph]).is_ok());
    let key = fs::read(f.home.join("cigar-catalog-state/key")).unwrap();
    native::import_at(&f.home, &raw, f.time + 1).unwrap();
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/key")).unwrap(),
        key
    );
    assert_eq!(fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(!f.home.join("context-assistance/installations").exists());
}
#[test]
fn unknown_refresh_cannot_lose_withdrawals_and_completion_uses_the_identical_verified_pair() {
    let f = Fixture::new();
    f.configure();
    let first = f.doc();
    f.import(&first);
    let key = fs::read(f.home.join("cigar-catalog-state/key")).unwrap();
    let mut next = first.clone();
    next.revision += 1;
    next.builds[0].withdrawn = true;
    catalog_fault_next(CatalogFault::Error("update_renamed"));
    assert!(import(&f.home, &f.sign(&next))
        .unwrap_err()
        .ends_with("cigar_catalog_commit_outcome_unknown"));
    let state = installed(&f.home).unwrap();
    assert!(state.check_sdk(&next.builds[0].identity.build_id).is_err());
    let checkpoint = state.catalog.checkpoint().clone();
    let bytes = fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap();
    assert!(import(&f.home, &f.sign(&first))
        .unwrap_err()
        .ends_with("cigar_catalog_replayed"));
    super::super::feed::reconcile(&f.home, Some(&checkpoint), |published| {
        assert!(published);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/key")).unwrap(),
        key
    );
    assert_eq!(
        fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
        bytes
    );
    assert!(installed(&f.home)
        .unwrap()
        .check_sdk(&next.builds[0].identity.build_id)
        .is_err());
}
#[test]
fn existing_signed_flat_layout_remains_usable_without_migration_or_key_regeneration() {
    let f = Fixture::new();
    f.configure();
    let d = f.doc();
    f.import(&d);
    let state = installed(&f.home).unwrap();
    let verified = receipt(&d, state.catalog.checkpoint());
    let dir = f.home.join("cigar-catalog-state");
    let cache = fs::read(dir.join("catalog.json")).unwrap();
    let key = fs::read(dir.join("key")).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    {
        let lock = WriteLock::acquire(&f.home).unwrap();
        lock.publish_lifecycle(LifecycleFile::CatalogKey, None, &key)
            .unwrap();
        lock.publish_lifecycle(LifecycleFile::CatalogCache, None, &cache)
            .unwrap();
    }
    let state = installed(&f.home).unwrap();
    assert!(verified.resolve(&state.catalog, &[Feature::Graph]).is_ok());
    let mut next = d.clone();
    next.revision += 1;
    f.import(&next);
    assert!(!dir.exists());
    assert_eq!(fs::read(f.home.join("cigar-catalog.key")).unwrap(), key);
    fs::remove_file(f.home.join("cigar-catalog.json")).unwrap();
    assert!(installed(&f.home)
        .err()
        .unwrap()
        .ends_with("cigar_catalog_state_incomplete"));
    assert!(import(&f.home, &f.sign(&next))
        .unwrap_err()
        .ends_with("cigar_catalog_state_incomplete"));
    assert_eq!(fs::read(f.home.join("cigar-catalog.key")).unwrap(), key);
    assert!(!dir.exists());
}
