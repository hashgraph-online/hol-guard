use super::*;
use crate::tests::{document, verify};

fn metadata() -> InstalledReleaseReceipt {
    let doc = document();
    InstalledReleaseReceipt {
        schema: "guard-cigar-installed-release.v1".into(),
        release: doc.builds[0].clone(),
        profile: doc.profiles[0].clone(),
        platform: "darwin-arm64".into(),
        catalog_checkpoint: verify(&doc).unwrap().checkpoint().clone(),
        guard_binary_sha256: "7".repeat(64),
        context_sha256: "6".repeat(64),
        verified_features: vec![Feature::Graph],
    }
}
#[test]
fn installed_build_ids_cannot_be_reused_for_changed_artifact_or_dependency_bytes() {
    let metadata = metadata();
    let sealed = seal_installation_receipt(&metadata, &[47; 32]).unwrap();
    let installed =
        verify_installation_receipt(&sealed, &[47; 32], &metadata.context_sha256).unwrap();
    for field in [
        "worker",
        "tree",
        "sdk",
        "dependency",
        "length",
        "missing_dependency",
    ] {
        let mut doc = document();
        let platform = &mut doc.builds[0].platforms[0];
        match field {
            "worker" => platform.worker_sha256 = "a".repeat(64),
            "tree" => platform.package_tree_sha256 = Some("b".repeat(64)),
            "sdk" => platform.wheel.as_mut().unwrap().sha256 = "c".repeat(64),
            "dependency" => platform.dependencies[0].sha256 = "d".repeat(64),
            "length" => platform.dependencies[0].bytes += 1,
            _ => platform.dependencies.clear(),
        }
        assert_eq!(
            installed
                .resolve(&verify(&doc).unwrap(), &[Feature::Graph])
                .unwrap_err(),
            ReleaseError::IdentityConflict,
            "{field}"
        );
    }
}
#[test]
fn catalog_origin_qualification_refresh_and_partial_omission_do_not_replace_installed_bytes() {
    let metadata = metadata();
    let sealed = seal_installation_receipt(&metadata, &[47; 32]).unwrap();
    let installed =
        verify_installation_receipt(&sealed, &[47; 32], &metadata.context_sha256).unwrap();
    let mut doc = document();
    doc.revision += 1;
    let platform = &mut doc.builds[0].platforms[0];
    platform.wheel.as_mut().unwrap().source = WheelSource::OfflineBundle;
    platform.qualification_receipt_sha256 = Some("e".repeat(64));
    platform.dependencies[0].requires_python = Some(">=3.14,<3.15".into());
    assert!(installed
        .resolve(&verify(&doc).unwrap(), &[Feature::Graph])
        .is_ok());
    let platform = &mut doc.builds[0].platforms[0];
    platform.qualification = Qualification::UpstreamOnly;
    platform.qualification_receipt_sha256 = None;
    platform.features.clear();
    platform.dependencies.clear();
    platform.wheel = None;
    platform.package_tree_sha256 = None;
    assert!(installed
        .resolve(&verify(&doc).unwrap(), &[Feature::Graph])
        .is_ok());
}
