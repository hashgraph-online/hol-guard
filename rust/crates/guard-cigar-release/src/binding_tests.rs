use super::*;
use crate::tests::{document, verify};

#[test]
fn catalog_refresh_preserves_exact_installed_identity_without_forcing_a_restart() {
    let mut doc = document();
    let first = verify(&doc).unwrap();
    let id = doc.builds[0].identity.build_id.clone();
    let installed = first
        .for_activation(&id, "darwin-arm64", false, &[Feature::Graph])
        .unwrap();
    doc.revision += 1;
    doc.expires_at += 60;
    let next = verify(&doc).unwrap();
    let refreshed = next
        .for_activation(&id, "darwin-arm64", false, &[Feature::Graph])
        .unwrap();
    assert_ne!(installed.checkpoint(), refreshed.checkpoint());
    assert_eq!(installed.binding().unwrap(), refreshed.binding().unwrap());
}
#[test]
fn preparation_never_mints_activation_and_profile_changes_change_installation_binding() {
    let mut doc = document();
    let first = verify(&doc).unwrap();
    let id = doc.builds[0].identity.build_id.clone();
    let prepared = first.prepare(&id, "darwin-arm64", false).unwrap();
    assert!(!prepared.activation_qualified());
    assert!(first
        .for_activation(&id, "darwin-arm64", false, &[Feature::Graph])
        .unwrap()
        .activation_qualified());
    let original = prepared.binding().unwrap();
    let mut separate = doc.profiles[0].clone();
    separate.profile_id = "separate-profile".into();
    doc.profiles.push(separate);
    doc.builds[0].profile_id = "separate-profile".into();
    let next = verify(&doc).unwrap();
    let changed = next.prepare(&id, "darwin-arm64", false).unwrap();
    assert_ne!(original, changed.binding().unwrap());
}
#[test]
fn legacy_profile_remains_historical_and_separate_from_published_qualification() {
    let (legacy, profile) = legacy_candidate_profile().unwrap();
    assert_eq!(legacy.sdk_version, "0.14.1");
    assert_eq!(
        legacy.source_revision,
        "b47380e5a5cbeaaad5a61cab3372e9e67368732f"
    );
    assert_eq!(profile.python_minor, 14);
}
