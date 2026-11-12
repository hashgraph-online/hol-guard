use super::*;
use crate::tests::{document, verify};

#[test]
fn preview_sdk_core_and_release_tag_are_independent_exact_catalog_data() {
    let mut doc = document();
    let build = &mut doc.builds[0];
    build.identity.sdk_version = "0.15.0rc1+candidate.7".into();
    build.identity.core_version = "native-0.14.9-rc.3+arm64.7".into();
    build.channel = Channel::Preview;
    let wheel = build.platforms[0].wheel.as_mut().unwrap();
    wheel.version = build.identity.sdk_version.clone();
    wheel.filename = "hol_cigar-0.15.0rc1+candidate.7-py3-none-any.whl".into();
    wheel.source = WheelSource::GithubCigarRelease {
        tag: "v0.15.0-rc.1-candidate.7".into(),
    };
    let id = build.identity.build_id.clone();
    let catalog = verify(&doc).unwrap();
    assert_eq!(
        catalog.prepare(&id, "darwin-arm64", false).unwrap_err(),
        ReleaseError::PreviewDisabled
    );
    let resolved = catalog
        .for_activation(&id, "darwin-arm64", true, &[Feature::Graph])
        .unwrap();
    assert_eq!(
        resolved.build().identity.core_version,
        "native-0.14.9-rc.3+arm64.7"
    );
    assert!(resolved
        .platform()
        .wheel
        .as_ref()
        .unwrap()
        .download_url()
        .unwrap()
        .unwrap()
        .contains("/v0.15.0-rc.1-candidate.7/hol_cigar-0.15.0rc1+candidate.7-"));
}
#[test]
fn a_mislabeled_stable_prerelease_still_requires_preview_consent() {
    for sdk in ["0.15.0rc1", "0.15.0.dev2"] {
        let mut doc = document();
        let build = &mut doc.builds[0];
        build.identity.sdk_version = sdk.into();
        let wheel = build.platforms[0].wheel.as_mut().unwrap();
        wheel.version = sdk.into();
        wheel.filename = format!("hol_cigar-{sdk}-py3-none-any.whl");
        let id = build.identity.build_id.clone();
        let catalog = verify(&doc).unwrap();
        assert_eq!(
            catalog.prepare(&id, "darwin-arm64", false).unwrap_err(),
            ReleaseError::PreviewDisabled
        );
        assert!(catalog.prepare(&id, "darwin-arm64", true).is_ok());
    }
}
#[test]
fn malformed_producer_labels_and_release_url_segments_are_rejected() {
    for label in [
        "",
        "../core",
        "core/0.15",
        "0.15?x=1",
        "0.15#x",
        "0.15%2fnext",
        "0.15\n",
        "0.15 λ",
        "0.15:next",
    ] {
        let mut doc = document();
        doc.builds[0].identity.core_version = label.into();
        assert!(verify(&doc).is_err(), "{label:?}");
        let mut doc = document();
        doc.builds[0].platforms[0].wheel.as_mut().unwrap().source =
            WheelSource::GithubCigarRelease { tag: label.into() };
        assert!(verify(&doc).is_err(), "{label:?}");
    }
    let mut doc = document();
    doc.builds[0].identity.core_version = "a".repeat(129);
    assert!(verify(&doc).is_err());
}
#[test]
fn exact_core_label_changes_are_same_version_replacements_not_python_version_ordering() {
    let first = document().builds[0].identity.clone();
    let mut next = first.clone();
    next.build_id = "same-sdk-native-rebuild".into();
    next.core_version = "native-next+build.2".into();
    next.manifest_sha256 = "b".repeat(64);
    assert_eq!(
        compare_builds(&first, &next).unwrap(),
        BuildChange::SameVersionReplacement
    );
    next.build_id = first.build_id.clone();
    assert_eq!(
        compare_builds(&first, &next),
        Err(ReleaseError::IdentityConflict)
    );
}
