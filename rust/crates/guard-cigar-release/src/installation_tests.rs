use super::*;
use crate::tests::{document, verify};

fn metadata() -> InstalledReleaseReceipt {
    let doc = document();
    let catalog = verify(&doc).unwrap();
    InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: doc.builds[0].clone(),
        profile: doc.profiles[0].clone(),
        platform: "darwin-arm64".into(),
        catalog_checkpoint: catalog.checkpoint().clone(),
        guard_binary_sha256: "7".repeat(64),
        context_sha256: "6".repeat(64),
        verified_features: vec![Feature::Graph],
    }
}
#[test]
fn owner_verified_installed_build_survives_new_guard_catalog_omission() {
    let metadata = metadata();
    let key = [19u8; 32];
    let sealed = seal_installation_receipt(&metadata, &key).unwrap();
    let verified = verify_installation_receipt(&sealed, &key, &metadata.context_sha256).unwrap();
    let mut newer = document();
    newer.revision += 1;
    newer.builds.clear();
    let current = verify(&newer).unwrap();
    let resolved = verified.resolve(&current, &[Feature::Graph]).unwrap();
    assert!(resolved.activation_qualified());
    assert_eq!(resolved.build().identity, metadata.release.identity);
    assert_eq!(resolved.checkpoint(), &metadata.catalog_checkpoint);
}
#[test]
fn changed_installation_scope_or_another_guard_home_key_cannot_reuse_a_receipt() {
    let metadata = metadata();
    let key = [19u8; 32];
    let sealed = seal_installation_receipt(&metadata, &key).unwrap();
    assert_eq!(
        verify_installation_receipt(&sealed, &[20u8; 32], &metadata.context_sha256).unwrap_err(),
        ReleaseError::InstallationReceiptUnauthenticated
    );
    assert_eq!(
        verify_installation_receipt(&sealed, &key, &"8".repeat(64)).unwrap_err(),
        ReleaseError::InstallationContextMismatch
    );
}
#[test]
fn receipt_tampering_and_unknown_fields_are_not_local_approval() {
    let metadata = metadata();
    let key = [19u8; 32];
    let mut sealed = seal_installation_receipt(&metadata, &key).unwrap();
    sealed.payload = sealed.payload.replace("0.14.1", "0.15.2");
    assert_eq!(
        verify_installation_receipt(&sealed, &key, &metadata.context_sha256).unwrap_err(),
        ReleaseError::InstallationReceiptUnauthenticated
    );
    assert!(serde_json::from_value::<SealedInstallationReceipt>(serde_json::json!({
        "schema":"guard-cigar-sealed-installation.v1","payload":"","mac_hex":"0".repeat(64),"trust_me":true
    })).is_err());
}
#[test]
fn explicit_current_withdrawal_and_identity_reuse_override_the_archived_receipt() {
    let metadata = metadata();
    let key = [19u8; 32];
    let sealed = seal_installation_receipt(&metadata, &key).unwrap();
    let verified = verify_installation_receipt(&sealed, &key, &metadata.context_sha256).unwrap();
    let mut doc = document();
    doc.builds[0].withdrawn = true;
    assert_eq!(
        verified
            .resolve(&verify(&doc).unwrap(), &[Feature::Graph])
            .unwrap_err(),
        ReleaseError::BuildWithdrawn
    );
    doc.builds[0].withdrawn = false;
    doc.builds[0].identity.source_revision = "a".repeat(40);
    assert_eq!(
        verified
            .resolve(&verify(&doc).unwrap(), &[Feature::Graph])
            .unwrap_err(),
        ReleaseError::IdentityConflict
    );
}
#[test]
fn receipt_seals_an_upstream_build_but_not_a_local_candidate() {
    let mut metadata = metadata();
    metadata.release.platforms[0].qualification = Qualification::UpstreamOnly;
    metadata.release.platforms[0].qualification_receipt_sha256 = None;
    assert!(seal_installation_receipt(&metadata, &[19u8; 32]).is_ok());
    metadata.release.platforms[0].qualification = Qualification::LocalCandidate;
    metadata.release.channel = Channel::LocalCandidate;
    assert!(seal_installation_receipt(&metadata, &[19u8; 32]).is_err());
}
#[test]
fn feature_qualification_still_applies_after_offline_recovery() {
    let mut metadata = metadata();
    metadata.release.platforms[0].features = vec![Feature::Graph];
    let sealed = seal_installation_receipt(&metadata, &[19u8; 32]).unwrap();
    let verified =
        verify_installation_receipt(&sealed, &[19u8; 32], &metadata.context_sha256).unwrap();
    assert_eq!(
        verified
            .resolve(&TrustedCatalog::bundled().unwrap(), &[Feature::Sharing])
            .unwrap_err(),
        ReleaseError::FeatureUnqualified
    );
    // The catalog listing a feature is not enough: the receipt must record it.
    let metadata = self::metadata();
    assert!(metadata.release.platforms[0]
        .features
        .contains(&Feature::Sharing));
    let sealed = seal_installation_receipt(&metadata, &[19u8; 32]).unwrap();
    let verified =
        verify_installation_receipt(&sealed, &[19u8; 32], &metadata.context_sha256).unwrap();
    let catalog = TrustedCatalog::bundled().unwrap();
    assert_eq!(
        verified
            .resolve(&catalog, &[Feature::Graph, Feature::Sharing])
            .unwrap_err(),
        ReleaseError::FeatureUnqualified
    );
    assert!(verified.resolve(&catalog, &[Feature::Graph]).is_ok());
}

#[test]
fn old_receipt_payload_without_python_requirements_still_authenticates_and_resolves() {
    let mut metadata = metadata();
    for platform in &mut metadata.release.platforms {
        if let Some(wheel) = &mut platform.wheel {
            wheel.requires_python = None;
        }
        for wheel in &mut platform.dependencies {
            wheel.requires_python = None;
        }
    }
    let key = [29; 32];
    let sealed = seal_installation_receipt(&metadata, &key).unwrap();
    assert!(!sealed.payload.contains("requires_python"));
    let verified = verify_installation_receipt(&sealed, &key, &metadata.context_sha256).unwrap();
    let release = verified
        .resolve(&TrustedCatalog::bundled().unwrap(), &[Feature::Graph])
        .unwrap();
    release.check_python_version([3, 14, 7]).unwrap();
    assert_eq!(
        release.check_python_version([3, 15, 0]),
        Err(ReleaseError::PythonVersionRequired)
    );
    assert!(release.activation_qualified());
}
