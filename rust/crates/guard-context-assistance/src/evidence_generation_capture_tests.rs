//! Semantic cutover checks keep real edits distinct from ordinary read stamps.
use super::*;

#[test]
fn semantic_note_stamp_ignores_capture_bookkeeping_but_binds_reviewed_data_and_expiry() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let (_slot, mut transfer) = notes(&fixture, &cache, &from);
    let initial = transfer.semantic_sha256().unwrap();
    transfer.data.captured_at_ms += 1;
    transfer.data.source_manifest_sha256 = "b".repeat(64);
    assert_eq!(initial, transfer.semantic_sha256().unwrap());
    let baseline = transfer.data.clone();
    transfer.data.source_notes_version = "2".into();
    assert_ne!(initial, transfer.semantic_sha256().unwrap());
    transfer.data = baseline.clone();
    transfer
        .data
        .basis_sha256
        .insert("file:example".into(), "c".repeat(64));
    assert_ne!(initial, transfer.semantic_sha256().unwrap());
    transfer.data = baseline.clone();
    transfer.data.expires_at_ms -= 1;
    assert_ne!(initial, transfer.semantic_sha256().unwrap());
    transfer.data = baseline.clone();
    transfer.data.notes.as_mut().unwrap().documents[0].text = "A newly reviewed edit".into();
    assert_ne!(initial, transfer.semantic_sha256().unwrap());
    transfer.data = baseline;
    transfer.data.notes = None;
    transfer.data.basis_sha256.clear();
    assert_ne!(initial, transfer.semantic_sha256().unwrap());
}
#[test]
fn cache_clones_retain_one_exclusive_owner_and_the_same_active_slot_registry() {
    let fixture = Fixture::new();
    let first = EvidenceCache::open(&fixture.0).unwrap();
    let second = first.clone();
    let slot = first.open_slot(&fixture.key("dashboard"), 1, NOW).unwrap();
    drop(first);
    assert!(matches!(second.forget_all(), Err(RuntimeError::Busy)));
    assert!(matches!(
        EvidenceCache::open(&fixture.0),
        Err(RuntimeError::Busy)
    ));
    drop(second);
    assert!(matches!(
        EvidenceCache::open(&fixture.0),
        Err(RuntimeError::Busy)
    ));
    drop(slot);
    let reopened = EvidenceCache::open(&fixture.0).unwrap();
    assert_eq!(reopened.summary().unwrap().slots, 1);
}
#[test]
fn zero_scope_preparation_keeps_unmapped_evidence_and_has_no_transfer_authority() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let from = super::super::upgrade_tests::producer(false);
    let to = super::super::upgrade_tests::producer(true);
    let (slot, _) = notes(&fixture, &cache, &from);
    let before = std::fs::read(slot.directory.path.join("state.json")).unwrap();
    let store = EvidenceGenerationStore::open(&fixture.0).unwrap();
    let prepared = store
        .prepare(
            EvidencePreparation {
                request_id: "empty-but-preserving-unmapped",
                source: &cache,
                snapshot: &cache.upgrade_inventory(NOW).unwrap(),
                from: &from,
                to: &to,
                notes: &[],
            },
            NOW,
        )
        .unwrap();
    let summary = prepared.describe().unwrap();
    assert_eq!(summary["phase"], "ready");
    assert_eq!(summary["scopes"], 0);
    assert_eq!(summary["preserved_unmapped_scopes"], 1);
    assert_eq!(summary["authority_restored"], false);
    assert!(matches!(
        prepared.transfer(
            &EvidenceScope::new("dashboard", &fixture.0).unwrap(),
            &to,
            NOW
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    assert_eq!(prepared.open_cache().unwrap().summary().unwrap().slots, 0);
    assert_eq!(
        before,
        std::fs::read(slot.directory.path.join("state.json")).unwrap()
    );
}
