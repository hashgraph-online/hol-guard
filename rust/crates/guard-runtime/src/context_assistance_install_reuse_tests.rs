//! Synthetic receipt/registry cases; no SDK or interpreter process is started.
use super::*;
use guard_cigar_release::{InstalledReleaseReceipt, Qualification, ResolvedRelease};

fn installed(
    fixture: &Fixture,
    features: Vec<Feature>,
) -> (Installation, interpreters::Interpreter) {
    let interpreter = metadata_interpreter(fixture);
    let catalog = TrustedCatalog::bundled().unwrap();
    let mut build = catalog.document().builds[0].clone();
    build.identity.build_id = "synthetic-reuse-record".into();
    build.platforms.truncate(1);
    build.platforms[0].qualification = Qualification::GuardQualified;
    build.platforms[0].qualification_receipt_sha256 = Some("8".repeat(64));
    build.platforms[0].features = features.clone();
    let key = owner_key::provision_locked(&fixture.home).unwrap();
    let mut metadata = InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: build,
        profile: catalog.document().profiles[0].clone(),
        platform: "darwin-arm64".into(),
        catalog_checkpoint: catalog.checkpoint().clone(),
        guard_binary_sha256: "7".repeat(64),
        context_sha256: "0".repeat(64),
        verified_features: features,
    };
    let temporary = guard_cigar_release::seal_installation_receipt(&metadata, &key).unwrap();
    let verified = guard_cigar_release::verify_installation_receipt(
        &temporary,
        &key,
        &metadata.context_sha256,
    )
    .unwrap();
    let release = verified.resolve(&catalog, &[Feature::Graph]).unwrap();
    let slot = "a".repeat(64);
    let mut record = Installation {
        schema: versioned::SCHEMA_V2.into(),
        runtime_id: "historical-opaque-runtime".into(),
        qualification: "guard_qualified".into(),
        source_revision: release.build().identity.source_revision.clone(),
        selection: RuntimeSelection {
            python: interpreter.python.clone(),
            site_packages: fixture
                .home
                .join("context-assistance/bundles")
                .join(&slot)
                .join("site-packages"),
            work_dir: fixture.home.join("context-assistance/work").join(&slot),
            python_bundle: None,
            verified_python: None,
        },
        approval: BundleApproval {
            schema: "guard-cigar-bundle-approval.v2".into(),
            platform: "darwin-arm64".into(),
            python_sha256: interpreter.python_sha256.clone(),
            package_tree_sha256: release.platform().package_tree_sha256.clone().unwrap(),
            worker_sha256: release.platform().worker_sha256.clone(),
            files: 124,
            bytes: 11454530,
            release: Some(release.binding().unwrap()),
            python_bundle: None,
        },
        interpreter: interpreter.facts.clone(),
        receipt: None,
        managed_slot: Some(slot),
        verification_job_id: None,
    };
    metadata.context_sha256 = versioned::context(&record, &fixture.home).unwrap();
    record.receipt = Some(guard_cigar_release::seal_installation_receipt(&metadata, &key).unwrap());
    write_record(fixture, &record);
    (record, interpreter)
}
fn write_record(fixture: &Fixture, record: &Installation) {
    let path = root(&fixture.home, true)
        .unwrap()
        .join(record_name(&record.runtime_id));
    persist_private_bytes(
        &path,
        &serde_json::to_vec(record).unwrap(),
        MAX_RECORD,
        "cigar_installation",
        &fixture.home,
    )
    .unwrap();
}
fn release(fixture: &Fixture, record: &Installation, features: Vec<Feature>) -> ResolvedRelease {
    let key = owner_key::read(&fixture.home).unwrap();
    let verified = guard_cigar_release::verify_installation_receipt(
        record.receipt.as_ref().unwrap(),
        &key,
        &versioned::context(record, &fixture.home).unwrap(),
    )
    .unwrap();
    let mut metadata = verified.metadata().clone();
    metadata.release.platforms[0].features = features.clone();
    metadata.verified_features = features;
    metadata.release.platforms[0].qualification_receipt_sha256 = Some("9".repeat(64));
    metadata.context_sha256 = "0".repeat(64);
    let sealed = guard_cigar_release::seal_installation_receipt(&metadata, &key).unwrap();
    guard_cigar_release::verify_installation_receipt(&sealed, &key, &metadata.context_sha256)
        .unwrap()
        .resolve(&TrustedCatalog::bundled().unwrap(), &[Feature::Graph])
        .unwrap()
}
fn refresh_job(
    fixture: &Fixture,
    record: &Installation,
    release: &ResolvedRelease,
    id: &str,
) -> store::Job {
    let mut job = fixture.job(id);
    job.request.build_id = release.build().identity.build_id.clone();
    job.request_sha256 = store::request_sha(&job.request).unwrap();
    job.release = release.binding().unwrap();
    job.runtime_id = record.runtime_id.clone();
    job.slot = record.managed_slot.clone().unwrap();
    job.package_tree_sha256 = record.approval.package_tree_sha256.clone();
    job.worker_sha256 = record.approval.worker_sha256.clone();
    job.refresh = Some(reuse::target(record, release).unwrap());
    store::save(&fixture.home, &mut job, Phase::Queued, "queued").unwrap();
    job
}
#[test]
fn exact_metadata_reuses_historical_slots_and_opaque_ids_without_sdk_file_reads() {
    let fixture = Fixture::new();
    let (record, interpreter) = installed(&fixture, vec![Feature::Graph]);
    let target = release(&fixture, &record, vec![Feature::Graph, Feature::Sharing]);
    let canonical = reuse::physical_slot(&target, &record.approval).unwrap();
    assert_ne!(record.managed_slot.as_deref(), Some(canonical.as_str()));
    let found = reuse::find(&fixture.home, &target, &interpreter, &canonical)
        .unwrap()
        .unwrap();
    assert_eq!(found.runtime_id, record.runtime_id);
    assert_eq!(found.managed_slot, record.managed_slot);
    assert!(!record.selection.site_packages.exists());
    assert!(!record.selection.work_dir.exists());
    let job = refresh_job(&fixture, &record, &target, "verify-history");
    assert!(job.validate().is_ok());
    assert_eq!(
        Jobs::default()
            .get(&fixture.home, &job.request.job_id)
            .unwrap()["operation"],
        "verify"
    );
}
#[test]
fn qualification_reduction_requires_a_separate_explicit_transition() {
    let fixture = Fixture::new();
    let (record, interpreter) = installed(&fixture, vec![Feature::Graph, Feature::Sharing]);
    let target = release(&fixture, &record, vec![Feature::Graph]);
    let canonical = reuse::physical_slot(&target, &record.approval).unwrap();
    assert!(
        matches!(reuse::find(&fixture.home, &target, &interpreter, &canonical),
        Err(code) if code == error("qualification_reduction_requires_switch"))
    );
    assert!(!record.selection.work_dir.exists());
}
#[test]
fn interrupted_reverification_does_not_claim_the_preexisting_record_is_its_commit() {
    let fixture = Fixture::new();
    let (record, _) = installed(&fixture, vec![Feature::Graph]);
    let target = release(&fixture, &record, vec![Feature::Graph, Feature::Sharing]);
    let mut job = refresh_job(&fixture, &record, &target, "lost-uncommitted-check");
    let before = reuse::record_sha(&record).unwrap();
    store::save(&fixture.home, &mut job, Phase::Publishing, "publishing").unwrap();
    assert!(!reuse::committed(&fixture.home, &job, &record).unwrap());
    let recovered = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(recovered["phase"], "failed");
    assert_eq!(recovered["code"], "verification_interrupted");
    assert_eq!(
        reuse::record_sha(&load(&fixture.home, &record.runtime_id).unwrap()).unwrap(),
        before
    );
}
#[test]
fn a_verification_commit_marker_is_authenticated_and_cannot_be_added_to_an_old_receipt() {
    let fixture = Fixture::new();
    let (mut record, _) = installed(&fixture, vec![Feature::Graph]);
    record.verification_job_id = Some("forged-completion".into());
    write_record(&fixture, &record);
    assert!(matches!(load(&fixture.home, &record.runtime_id),
        Err(code) if code == error("cigar_installation_context_mismatch")));
}
#[test]
fn malformed_refresh_targets_do_not_turn_historical_job_metadata_into_authority() {
    let fixture = Fixture::new();
    let (record, _) = installed(&fixture, vec![Feature::Graph]);
    let target = release(&fixture, &record, vec![Feature::Graph]);
    let mut job = refresh_job(&fixture, &record, &target, "invalid-reverify-target");
    job.refresh.as_mut().unwrap().features.clear();
    assert_eq!(job.validate(), Err(error("install_job_invalid")));
}

#[cfg(unix)]
#[path = "context_assistance_install_reuse_actual_tests.rs"]
mod actual;

#[test]
fn an_unselected_stronger_receipt_does_not_block_the_compatible_canonical_record() {
    let fixture = Fixture::new();
    let (record, interpreter) = installed(&fixture, vec![Feature::Graph, Feature::Sharing]);
    let target = release(&fixture, &record, vec![Feature::Graph]);
    let canonical = reuse::physical_slot(&target, &record.approval).unwrap();
    let mut preferred = record.clone();
    preferred.runtime_id = "canonical-graph".into();
    preferred.managed_slot = Some(canonical.clone());
    preferred.selection.site_packages = fixture
        .home
        .join("context-assistance/bundles")
        .join(&canonical)
        .join("site-packages");
    preferred.selection.work_dir = fixture
        .home
        .join("context-assistance/work")
        .join(&canonical);
    let key = owner_key::read(&fixture.home).unwrap();
    let verified = guard_cigar_release::verify_installation_receipt(
        record.receipt.as_ref().unwrap(),
        &key,
        &versioned::context(&record, &fixture.home).unwrap(),
    )
    .unwrap();
    let mut metadata = verified.metadata().clone();
    metadata.release.platforms[0].features = vec![Feature::Graph];
    metadata.verified_features = vec![Feature::Graph];
    metadata.context_sha256 = versioned::context(&preferred, &fixture.home).unwrap();
    preferred.receipt =
        Some(guard_cigar_release::seal_installation_receipt(&metadata, &key).unwrap());
    write_record(&fixture, &preferred);
    let chosen = reuse::find(&fixture.home, &target, &interpreter, &canonical)
        .unwrap()
        .unwrap();
    assert_eq!(chosen.runtime_id, preferred.runtime_id);
}
#[test]
fn recovery_preserves_a_different_explicit_receipt_commit_as_a_conflict() {
    let fixture = Fixture::new();
    let (mut record, _) = installed(&fixture, vec![Feature::Graph]);
    let target = release(&fixture, &record, vec![Feature::Graph, Feature::Sharing]);
    let mut job = refresh_job(&fixture, &record, &target, "competing-reverification");
    store::save(&fixture.home, &mut job, Phase::Publishing, "publishing").unwrap();
    let key = owner_key::read(&fixture.home).unwrap();
    let receipt = guard_cigar_release::verify_installation_receipt(
        record.receipt.as_ref().unwrap(),
        &key,
        &versioned::context(&record, &fixture.home).unwrap(),
    )
    .unwrap();
    let mut metadata = receipt.metadata().clone();
    record.verification_job_id = Some("a-different-explicit-refresh".into());
    metadata.context_sha256 = versioned::context(&record, &fixture.home).unwrap();
    record.receipt = Some(guard_cigar_release::seal_installation_receipt(&metadata, &key).unwrap());
    write_record(&fixture, &record);
    let before = reuse::record_sha(&record).unwrap();
    let recovered = Jobs::default()
        .recover(&fixture.home, &job.request.job_id)
        .unwrap();
    assert_eq!(recovered["phase"], "recovery_required");
    assert_eq!(recovered["code"], "verification_conflict");
    assert_eq!(
        reuse::record_sha(&load(&fixture.home, &record.runtime_id).unwrap()).unwrap(),
        before
    );
}
