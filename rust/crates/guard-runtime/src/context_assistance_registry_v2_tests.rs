//! Synthetic metadata only: no SDK/interpreter is launched by these tests.
use super::*;
use guard_cigar_release::{
    seal_installation_receipt, verify_installation_receipt, InstalledReleaseReceipt, Qualification,
    TrustedCatalog,
};

fn modern(fixture: &Fixture) -> Installation {
    let mut record = fixture.record();
    let home = fs::canonicalize(&fixture.0).unwrap();
    let slot = "1".repeat(64);
    record.schema = versioned::SCHEMA_V2.into();
    record.runtime_id = "managed-314".into();
    record.qualification = "guard_qualified".into();
    record.managed_slot = Some(slot.clone());
    record.selection.site_packages = home
        .join("context-assistance/bundles")
        .join(&slot)
        .join("site-packages");
    record.selection.work_dir = home.join("context-assistance/work").join(&slot);
    let catalog = TrustedCatalog::bundled().unwrap();
    let mut build = catalog.document().builds[0].clone();
    build.platforms.truncate(1);
    build.identity.build_id = "synthetic-metadata-only".into();
    let platform = &mut build.platforms[0];
    platform.package_tree_sha256 = Some("6".repeat(64));
    platform.qualification = Qualification::GuardQualified;
    platform.qualification_receipt_sha256 = Some("5".repeat(64));
    platform.features = vec![Feature::Graph];
    platform.dependencies = vec![guard_cigar_release::WheelLock {
        distribution: "protobuf".into(),
        version: "7.36.2".into(),
        filename: "protobuf-7.36.2-py3-none-any.whl".into(),
        sha256: "2".repeat(64),
        bytes: 4096,
        requires_python: None,
        source: guard_cigar_release::WheelSource::OfflineBundle,
    }];
    record.source_revision = build.identity.source_revision.clone();
    record.approval.schema = "guard-cigar-bundle-approval.v2".into();
    record.approval.worker_sha256 = platform.worker_sha256.clone();
    record.approval.package_tree_sha256 = "6".repeat(64);
    let key = owner_key::provision_locked(&fixture.0).unwrap();
    let mut metadata = InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: build,
        profile: catalog.document().profiles[0].clone(),
        platform: "darwin-arm64".into(),
        catalog_checkpoint: catalog.checkpoint().clone(),
        guard_binary_sha256: "7".repeat(64),
        context_sha256: "0".repeat(64),
        verified_features: vec![Feature::Graph],
    };
    // The temporary synthetic receipt obtains only the stable binding. The
    // persisted receipt below binds the complete final installation context.
    let sealed = seal_installation_receipt(&metadata, &key).unwrap();
    let verified = verify_installation_receipt(&sealed, &key, &metadata.context_sha256).unwrap();
    let release = verified.resolve(&catalog, &[Feature::Graph]).unwrap();
    record.approval.release = Some(release.binding().unwrap());
    metadata.context_sha256 = versioned::context(&record, &fixture.0).unwrap();
    record.receipt = Some(seal_installation_receipt(&metadata, &key).unwrap());
    record
}
fn key_path(fixture: &Fixture) -> PathBuf {
    fs::canonicalize(&fixture.0)
        .unwrap()
        .join("context-assistance/installation-authority.json")
}
#[test]
fn legacy_reads_preserve_record_bytes_and_do_not_provision_a_key() {
    let fixture = Fixture::new();
    let path = fixture.write(&fixture.record());
    let before = fs::read(&path).unwrap();
    assert!(load(&fixture.0, "local-314").is_ok());
    let choices = list(&fixture.0).unwrap();
    assert_eq!(choices[0]["sdk_version"], "0.14.1");
    assert_eq!(choices[0]["core_version"], "0.14.1");
    assert_eq!(choices[0]["managed"], false);
    assert_eq!(choices[0]["build_id"], Value::Null);
    assert_eq!(fs::read(path).unwrap(), before);
    assert!(!key_path(&fixture).exists());
}
#[test]
fn authenticated_modern_metadata_is_read_without_sdk_paths_or_processes() {
    let fixture = Fixture::new();
    let record = modern(&fixture);
    assert!(!record.selection.site_packages.exists());
    assert!(!record.selection.work_dir.exists());
    let path = fixture.write(&record);
    let before = fs::read(&path).unwrap();
    let loaded = load(&fixture.0, &record.runtime_id).unwrap();
    assert_eq!(loaded.qualification, "guard_qualified");
    let choices = list(&fixture.0).unwrap();
    assert_eq!(
        choices[0]["build_id"],
        record.approval.release.as_ref().unwrap().identity.build_id
    );
    assert_eq!(choices[0]["sdk_version"], "0.14.1");
    assert_eq!(choices[0]["managed"], true);
    assert_eq!(fs::read(path).unwrap(), before);
}
#[test]
fn modified_installation_context_cannot_reuse_an_authenticated_receipt() {
    let fixture = Fixture::new();
    let mut record = modern(&fixture);
    record.selection.python = "/never-executed/changed-python".into();
    fixture.write(&record);
    assert_eq!(
        load(&fixture.0, &record.runtime_id).err().unwrap(),
        "native_context_assistance_cigar_installation_context_mismatch"
    );
}
#[test]
fn a_mixed_legacy_schema_cannot_claim_published_qualification() {
    let fixture = Fixture::new();
    let mut record = modern(&fixture);
    record.schema = SCHEMA.into();
    fixture.write(&record);
    assert_eq!(
        load(&fixture.0, &record.runtime_id).err().unwrap(),
        "native_context_assistance_installation_invalid"
    );
}
#[test]
fn missing_key_is_unavailable_without_recreating_or_reapproving_anything() {
    let fixture = Fixture::new();
    let record = modern(&fixture);
    let path = fixture.write(&record);
    let before = fs::read(&path).unwrap();
    fs::remove_file(key_path(&fixture)).unwrap();
    assert!(load(&fixture.0, &record.runtime_id).is_err());
    assert!(!key_path(&fixture).exists());
    assert_eq!(fs::read(path).unwrap(), before);
}
#[test]
fn requested_feature_qualification_is_checked_before_any_sdk_artifact_access() {
    let fixture = Fixture::new();
    let record = modern(&fixture);
    fixture.write(&record);
    let loaded = load(&fixture.0, &record.runtime_id).unwrap();
    let mut config = guard_context_assistance::ContextAssistanceConfig {
        enabled: true,
        ..Default::default()
    };
    config.features.agent_context = true;
    config.features.shared_agents = true;
    let result = loaded.start_cancellable(
        &fixture.0,
        &config,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    assert_eq!(
        result.err().unwrap(),
        "native_context_assistance_cigar_feature_unqualified"
    );
}
#[test]
fn managed_scope_cannot_point_at_an_operator_owned_environment() {
    let fixture = Fixture::new();
    let mut record = modern(&fixture);
    record.selection.site_packages = "/never-touch/operator-environment".into();
    fixture.write(&record);
    assert_eq!(
        load(&fixture.0, &record.runtime_id).err().unwrap(),
        "native_context_assistance_installation_invalid"
    );
}
#[cfg(unix)]
#[test]
fn installation_keys_refuse_shared_permissions_hardlinks_and_other_home_binding() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let record = modern(&fixture);
    fixture.write(&record);
    let path = key_path(&fixture);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load(&fixture.0, &record.runtime_id).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = fixture.0.join("key-alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(load(&fixture.0, &record.runtime_id).is_err());
    fs::remove_file(alias).unwrap();
    let other = Fixture::new();
    let copied = key_path(&other);
    let bytes = fs::read(&path).unwrap();
    persist_private_bytes(&copied, &bytes, 4096, "cigar_installation_key", &other.0).unwrap();
    assert!(owner_key::read(&other.0).is_err());
}
