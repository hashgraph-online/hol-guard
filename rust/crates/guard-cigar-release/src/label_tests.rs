use super::*;

#[test]
fn malformed_producer_labels_are_rejected() {
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
        assert!(!labels::producer_label(label), "{label:?}");
    }
    assert!(!labels::producer_label(&"a".repeat(129)));
    assert!(labels::producer_label("native-0.14.9-rc.3+arm64.7"));
}
#[test]
fn exact_core_label_changes_are_same_version_replacements_not_python_version_ordering() {
    let first = BuildIdentity {
        build_id: "fixture-build".into(),
        sdk_version: "0.14.2".into(),
        core_version: "native-0.14.2".into(),
        source_revision: "a".repeat(40),
        manifest_sha256: "a".repeat(64),
    };
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
