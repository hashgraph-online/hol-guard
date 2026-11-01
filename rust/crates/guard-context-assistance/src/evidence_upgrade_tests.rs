//! Native inventory/preflight fixtures use no SDK or project read authority.
use super::*;
use crate::{DataCompatibility, EvidenceUpgradeStrategy, StorageMode};
use guard_cigar_release::{
    CatalogDocument, CatalogTrust, Feature, Qualification, ResolvedRelease, TrustedCatalog,
    TrustedKey,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn release(changed: bool) -> ResolvedRelease {
    let mut doc: CatalogDocument = TrustedCatalog::bundled().unwrap().document().clone();
    doc.builds[0].identity.build_id = if changed {
        "synthetic-storage-b"
    } else {
        "synthetic-storage-a"
    }
    .into();
    doc.builds[0].identity.source_revision = if changed { "b" } else { "a" }.repeat(40);
    doc.builds[0].platforms[0].qualification = Qualification::GuardQualified;
    doc.builds[0].platforms[0].qualification_receipt_sha256 = Some("d".repeat(64));
    doc.builds[0].platforms[0].features = vec![Feature::Graph, Feature::Persistence];
    let pair = Ed25519KeyPair::from_seed_unchecked(&[111; 32]).unwrap();
    let key = TrustedKey {
        key_id: "evidence-plan-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 1,
        not_after: u64::MAX,
        revoked: false,
    };
    let payload = serde_json::to_string(&doc).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let signature: String = pair
        .sign(&message)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let envelope = serde_json::to_vec(
        &serde_json::json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,
        "payload":payload,"signature_hex":signature}),
    )
    .unwrap();
    TrustedCatalog::verify(
        &envelope,
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: doc.issued_at,
        },
    )
    .unwrap()
    .for_activation(
        &doc.builds[0].identity.build_id,
        "darwin-arm64",
        false,
        &[Feature::Graph, Feature::Persistence],
    )
    .unwrap()
}
fn plan(cache: &EvidenceCache, changed: bool) -> crate::EvidenceUpgradePlan {
    cache
        .upgrade_inventory(NOW)
        .unwrap()
        .preflight(
            &producer(false),
            &producer(changed),
            StorageMode::Sqlite,
            &[Feature::Graph, Feature::Persistence],
        )
        .unwrap()
}
#[test]
fn inventory_preserves_reviewed_notes_without_rendering_content_or_restoring_authority() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 1, NOW).unwrap();
    slot.stage_notes("0", &doc(), NOW).unwrap();
    slot.commit_notes("1", Some(saved("1")), NOW).unwrap();
    let before = std::fs::read(fixture.root().join(&key).join("state.json")).unwrap();
    let inventory = cache.upgrade_inventory(NOW).unwrap();
    let value = serde_json::to_value(&inventory).unwrap();
    assert_eq!(value["slots"][0]["state"], "readable");
    assert_eq!(value["slots"][0]["notes"], 1);
    assert_eq!(value["slots"][0]["active"], true);
    assert_eq!(value["authority_restored"], false);
    let serialized = value.to_string();
    for private in [
        "human-admitted",
        "file:example",
        "note:reviewed",
        fixture.0.to_str().unwrap(),
        "dashboard",
    ] {
        assert!(!serialized.contains(private));
    }
    assert_eq!(
        before,
        std::fs::read(fixture.root().join(&key).join("state.json")).unwrap()
    );
    let same = plan(&cache, false);
    assert_eq!(same.strategy, EvidenceUpgradeStrategy::ReuseCompatible);
    assert_eq!(same.required_extra_bytes, 0);
    assert!(same.requires_quiescent_recheck);
    drop(slot);
    let next = plan(&cache, true);
    assert_eq!(next.compatibility, DataCompatibility::Migratable);
    assert_eq!(
        next.strategy,
        EvidenceUpgradeStrategy::FreshBrokerReadmission
    );
    assert!(next.requires_prepared_copy);
    assert!(next.requires_fresh_authority);
    assert!(!next.raw_sdk_checkpoint_copied);
    assert!(next.previous_checkpoint_preserved);
    assert!(!next.requires_quiescent_recheck);
    assert_eq!(
        before,
        std::fs::read(fixture.root().join(&key).join("state.json")).unwrap()
    );
}
#[test]
fn snapshot_changes_for_checkpoint_writes_and_for_manifest_commit() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    let mut slot = cache.open_slot(&key, 1, NOW).unwrap();
    let first = cache
        .upgrade_inventory(NOW)
        .unwrap()
        .snapshot_sha256()
        .to_owned();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.root().join(&key).join("sdk/broker.sqlite3"))
        .unwrap();
    file.write_all(b"synthetic opaque SDK bytes").unwrap();
    file.sync_all().unwrap();
    let second = cache
        .upgrade_inventory(NOW)
        .unwrap()
        .snapshot_sha256()
        .to_owned();
    assert_ne!(first, second);
    slot.stage_notes("0", &doc(), NOW).unwrap();
    assert_ne!(
        second,
        cache.upgrade_inventory(NOW).unwrap().snapshot_sha256()
    );
    assert_eq!(plan(&cache, true).code, "context_storage_outcome_unknown");
}
#[test]
fn corrupt_newer_and_interrupted_metadata_refuse_without_mutation_or_text_disclosure() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    let key = fixture.key("dashboard");
    drop(cache.open_slot(&key, 1, NOW).unwrap());
    let path = fixture.root().join(&key).join("state.json");
    let original = std::fs::read(&path).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(fixture.root().join(&key).join("state.next"))
        .unwrap();
    file.write_all(b"incomplete-private-note-body").unwrap();
    drop(file);
    assert_eq!(plan(&cache, true).code, "context_storage_outcome_unknown");
    std::fs::remove_file(fixture.root().join(&key).join("state.next")).unwrap();
    std::fs::write(&path, b"{corrupt-private-note").unwrap();
    assert_eq!(
        plan(&cache, true).compatibility,
        DataCompatibility::Incompatible
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"{corrupt-private-note");
    let mut newer: serde_json::Value = serde_json::from_slice(&original).unwrap();
    newer["schema"] = 2.into();
    let newer = serde_json::to_vec(&newer).unwrap();
    std::fs::write(&path, &newer).unwrap();
    assert_eq!(plan(&cache, true).compatibility, DataCompatibility::Unknown);
    assert_eq!(std::fs::read(&path).unwrap(), newer);
    let inventory = cache.upgrade_inventory(NOW).unwrap();
    let memory = inventory
        .preflight(
            &producer(false),
            &producer(true),
            StorageMode::Memory,
            &[Feature::Graph],
        )
        .unwrap();
    assert_eq!(memory.strategy, EvidenceUpgradeStrategy::MemoryRebuild);
    assert!(memory.previous_checkpoint_preserved);
    assert!(!memory.authority_restored);
}
#[test]
fn expiry_and_capacity_are_reported_without_sweeping_or_deleting_previous_data() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    for n in 0..MAX_SLOTS {
        drop(
            cache
                .open_slot(&fixture.key(&format!("app{n}")), 1, NOW)
                .unwrap(),
        );
    }
    let next = plan(&cache, true);
    assert_eq!(next.compatibility, DataCompatibility::Migratable);
    assert_eq!(next.code, "fresh_broker_preparation_required");
    assert_eq!(next.required_extra_slots, MAX_SLOTS);
    assert_eq!(cache.summary().unwrap().slots, MAX_SLOTS);
    let inventory = cache.upgrade_inventory(NOW + 3_600_000).unwrap();
    let value = serde_json::to_value(&inventory).unwrap();
    assert!(value["slots"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["state"] == "expired"));
    assert_eq!(cache.summary().unwrap().slots, MAX_SLOTS);
}
#[test]
fn empty_cache_has_no_copy_or_authority_and_future_feature_reduction_is_explicit() {
    let inventory = crate::EvidenceUpgradeInventory::empty(NOW).unwrap();
    let plan = inventory
        .preflight(
            &producer(false),
            &producer(true),
            StorageMode::Sqlite,
            &[Feature::Graph, Feature::Persistence],
        )
        .unwrap();
    assert_eq!(plan.code, "empty_saved_evidence");
    assert_eq!(plan.required_extra_bytes, 0);
    assert!(!plan.requires_prepared_copy);
    assert!(!plan.authority_restored);
    let denied = inventory
        .preflight(
            &producer(false),
            &producer(true),
            StorageMode::Memory,
            &[Feature::Graph, Feature::Sharing],
        )
        .unwrap();
    assert_eq!(denied.code, "cigar_feature_unqualified");
    assert_eq!(denied.strategy, EvidenceUpgradeStrategy::Blocked);
    assert!(denied.transition_after_preparation.is_none());
}

fn approval(release: &ResolvedRelease) -> crate::BundleApproval {
    crate::BundleApproval {
        schema: "guard-cigar-bundle-approval.v2".into(),
        platform: "darwin-arm64".into(),
        python_sha256: "a".repeat(64),
        package_tree_sha256: release.platform().package_tree_sha256.clone().unwrap(),
        worker_sha256: release.platform().worker_sha256.clone(),
        files: 124,
        bytes: 11454530,
        release: Some(release.binding().unwrap()),
        python_bundle: None,
    }
}
pub(super) fn producer(changed: bool) -> crate::EvidenceUpgradeProducer {
    let release = release(changed);
    crate::EvidenceUpgradeProducer::new(&release, &approval(&release)).unwrap()
}
#[test]
fn same_sdk_with_changed_python_or_private_standard_library_requires_fresh_data() {
    let fixture = Fixture::new();
    let cache = EvidenceCache::open(&fixture.0).unwrap();
    drop(cache.open_slot(&fixture.key("dashboard"), 1, NOW).unwrap());
    let inventory = cache.upgrade_inventory(NOW).unwrap();
    let release = release(false);
    let mut approval = approval(&release);
    let from = crate::EvidenceUpgradeProducer::new(&release, &approval).unwrap();
    approval.python_sha256 = "b".repeat(64);
    let changed = crate::EvidenceUpgradeProducer::new(&release, &approval).unwrap();
    let plan = inventory
        .preflight(
            &from,
            &changed,
            StorageMode::Sqlite,
            &[Feature::Graph, Feature::Persistence],
        )
        .unwrap();
    assert_eq!(
        plan.strategy,
        EvidenceUpgradeStrategy::FreshBrokerReadmission
    );
    let mut python = TrustedCatalog::bundled().unwrap().document().interpreters[0]
        .binding()
        .unwrap();
    approval.schema = "guard-cigar-bundle-approval.v3".into();
    approval.python_sha256 = python.executable_sha256.clone();
    approval.python_bundle = Some(python.clone());
    let from = crate::EvidenceUpgradeProducer::new(&release, &approval).unwrap();
    python.tree_sha256 = "e".repeat(64);
    approval.python_bundle = Some(python);
    let changed = crate::EvidenceUpgradeProducer::new(&release, &approval).unwrap();
    let plan = inventory
        .preflight(
            &from,
            &changed,
            StorageMode::Sqlite,
            &[Feature::Graph, Feature::Persistence],
        )
        .unwrap();
    assert_eq!(
        plan.strategy,
        EvidenceUpgradeStrategy::FreshBrokerReadmission
    );
    assert!(plan.requires_prepared_copy);
    assert!(!plan.raw_sdk_checkpoint_copied);
}
#[test]
fn catalog_producer_binding_keeps_the_existing_durable_wire_shape() {
    let producer = producer(false);
    assert_eq!(
        serde_json::to_value(producer.release_binding().unwrap()).unwrap(),
        serde_json::to_value(release(false).binding().unwrap()).unwrap()
    );
}
#[test]
fn a_mismatched_approval_cannot_describe_a_compatible_data_producer() {
    let release = release(false);
    let mut approval = approval(&release);
    approval.package_tree_sha256 = "e".repeat(64);
    assert!(matches!(
        crate::EvidenceUpgradeProducer::new(&release, &approval),
        Err(RuntimeError::PackageMismatch)
    ));
    approval = self::approval(&release);
    approval.python_sha256 = "path-to-unverified-python".into();
    assert!(matches!(
        crate::EvidenceUpgradeProducer::new(&release, &approval),
        Err(RuntimeError::PackageMismatch)
    ));
}
