//! Synthetic package files prove native boundary checks, never an SDK release.
use super::*;
use guard_cigar_release::{
    CatalogTrust, Feature, Qualification, ResolvedRelease, TrustedCatalog, TrustedKey, WheelLock,
    WheelSource,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn catalog(fixture: &Fixture, sdk: &str, core: &str, qualified: bool) -> TrustedCatalog {
    let package = fixture.selection.site_packages.join("cigar_sdk");
    let mut release: serde_json::Value =
        serde_json::from_slice(&fs::read(package.join("release.json")).unwrap()).unwrap();
    release["version"] = json!(sdk);
    release["local_context_core_version"] = json!(core);
    fs::write(
        package.join("release.json"),
        serde_json::to_vec(&release).unwrap(),
    )
    .unwrap();
    let manifest = package.join("_native/darwin-arm64/manifest.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["sdk_release"] = json!(sdk);
    value["core_version"] = json!(core);
    fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut expected = RuntimeRelease::legacy().unwrap();
    expected.sdk_version = sdk.into();
    expected.core_version = core.into();
    let observed = inspect(&fixture.selection, "darwin-arm64", &expected, None).unwrap();
    let mut doc = TrustedCatalog::bundled().unwrap().document().clone();
    doc.issued_at = 900;
    doc.expires_at = 2000;
    let build = &mut doc.builds[0];
    build.identity.build_id = "synthetic-catalog-build".into();
    build.identity.sdk_version = sdk.into();
    build.identity.core_version = core.into();
    let platform = &mut build.platforms[0];
    platform.package_tree_sha256 = Some(observed.package_tree_sha256);
    platform.worker_sha256 = observed.worker_sha256;
    platform.qualification = if qualified {
        Qualification::GuardQualified
    } else {
        Qualification::UpstreamOnly
    };
    platform.qualification_receipt_sha256 = qualified.then(|| "5".repeat(64));
    platform.features = vec![Feature::Graph];
    let wheel = platform.wheel.as_mut().unwrap();
    wheel.version = sdk.into();
    wheel.filename = format!("hol_cigar-{sdk}-py3-none-macosx_11_0_arm64.whl");
    wheel.source = WheelSource::OfflineBundle;
    platform.dependencies = vec![WheelLock {
        distribution: "protobuf".into(),
        version: "7.35.0".into(),
        filename: "protobuf-7.35.0-py3-none-any.whl".into(),
        sha256: "2".repeat(64),
        bytes: 4096,
        requires_python: None,
        source: WheelSource::OfflineBundle,
    }];
    let pair = Ed25519KeyPair::from_seed_unchecked(&[83; 32]).unwrap();
    let key = TrustedKey {
        key_id: "native-test-only".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 500,
        not_after: 3000,
        revoked: false,
    };
    let payload = serde_json::to_string(&doc).unwrap();
    let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
    message.extend_from_slice(payload.as_bytes());
    let signature: String = pair
        .sign(&message)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let envelope = serde_json::to_vec(
        &json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,
        "payload":payload,"signature_hex":signature}),
    )
    .unwrap();
    TrustedCatalog::verify(
        &envelope,
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: 1000,
        },
    )
    .unwrap()
}
fn selected(catalog: &TrustedCatalog) -> ResolvedRelease {
    catalog
        .for_activation(
            "synthetic-catalog-build",
            "darwin-arm64",
            false,
            &[Feature::Graph],
        )
        .unwrap()
}
#[test]
fn future_sdk_and_independent_core_are_inspected_through_catalog_data() {
    let fixture = Fixture::new();
    let cat = catalog(&fixture, "0.15.2", "0.15.1", true);
    let release = selected(&cat);
    assert_eq!(
        fixture.inspect(),
        Err(RuntimeError::PackageMismatch),
        "legacy approval cannot widen"
    );
    let approval = inspect_release_bundle(&fixture.selection, &release).unwrap();
    assert_eq!(approval.schema, "guard-cigar-bundle-approval.v2");
    assert_eq!(
        approval.release.as_ref().unwrap().identity.sdk_version,
        "0.15.2"
    );
    assert_eq!(
        approval.release.as_ref().unwrap().identity.core_version,
        "0.15.1"
    );
    assert!(matches!(
        crate::VerifiedRuntime::start(fixture.selection.clone(), &approval),
        Err(RuntimeError::ApprovalMismatch)
    ));
}
#[test]
fn independent_native_core_preview_labels_are_bound_exactly_without_normalization() {
    let fixture = Fixture::new();
    let cat = catalog(&fixture, "0.15.2", "native-0.14.9-rc.3+arm64.7", true);
    let release = selected(&cat);
    let approval = inspect_release_bundle(&fixture.selection, &release).unwrap();
    assert_eq!(
        approval.release.as_ref().unwrap().identity.core_version,
        "native-0.14.9-rc.3+arm64.7"
    );
    let path = fixture
        .selection
        .site_packages
        .join("cigar_sdk/_native/darwin-arm64/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["core_version"] = json!("native-0.14.9rc3+arm64.7");
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(
        inspect_release_bundle(&fixture.selection, &release),
        Err(RuntimeError::PackageMismatch)
    );
}
#[test]
fn official_worker_beside_changed_sdk_code_does_not_match_the_approved_release() {
    let fixture = Fixture::new();
    let cat = catalog(&fixture, "0.15.2", "0.15.1", true);
    let release = selected(&cat);
    assert!(inspect_release_bundle(&fixture.selection, &release).is_ok());
    fs::write(
        fixture
            .selection
            .site_packages
            .join("cigar_sdk/modified_sdk.py"),
        b"changed importable code",
    )
    .unwrap();
    assert_eq!(
        inspect_release_bundle(&fixture.selection, &release),
        Err(RuntimeError::ApprovalMismatch)
    );
}
#[test]
fn core_metadata_is_bound_independently_of_the_sdk_label() {
    let fixture = Fixture::new();
    let cat = catalog(&fixture, "0.15.2", "0.15.1", true);
    let release = selected(&cat);
    let manifest = fixture
        .selection
        .site_packages
        .join("cigar_sdk/_native/darwin-arm64/manifest.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["core_version"] = json!("0.15.2");
    fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        inspect_release_bundle(&fixture.selection, &release),
        Err(RuntimeError::PackageMismatch)
    );
}
#[test]
fn preparation_only_release_is_refused_before_any_runtime_artifact_is_read() {
    let fixture = Fixture::new();
    let cat = catalog(&fixture, "0.15.2", "0.15.1", false);
    let release = cat
        .prepare("synthetic-catalog-build", "darwin-arm64", false)
        .unwrap();
    let approval = inspect_release_bundle(&fixture.selection, &release).unwrap();
    let missing = RuntimeSelection {
        verified_python: None,
        python_bundle: None,
        python: "/never-read/python".into(),
        site_packages: "/never-read/site".into(),
        work_dir: "/never-read/work".into(),
    };
    assert!(matches!(
        crate::VerifiedRuntime::start_release_cancellable(
            missing,
            &approval,
            &release,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
        ),
        Err(RuntimeError::ReleaseUnqualified)
    ));
}
