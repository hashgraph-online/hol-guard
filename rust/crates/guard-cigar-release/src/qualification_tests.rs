//! The bundled darwin-arm64 qualification must match the committed receipts byte for byte.
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SDK_RECEIPT: &[u8] = include_bytes!(
    "../../../../docs/guard/cigar-integration/evidence/qualification/cigar-0.14.1-darwin-arm64-prepared-qualification.json"
);
const PYTHON_RECEIPT: &[u8] = include_bytes!(
    "../../../../docs/guard/cigar-integration/evidence/qualification/cpython-3.14.10-darwin-arm64-private-python-qualification.json"
);

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
const ALL_FEATURES: [Feature; 4] = [
    Feature::Graph,
    Feature::Sharing,
    Feature::Persistence,
    Feature::ExecutionContext,
];

#[test]
fn bundled_sdk_qualification_digest_binds_the_committed_receipt_and_its_proven_features() {
    let catalog = TrustedCatalog::bundled().unwrap();
    let build = &catalog.document().builds[0];
    let platform = &build.platforms[0];
    assert_eq!(build.identity.sdk_version, "0.14.1");
    assert_eq!(platform.platform, "darwin-arm64");
    assert_eq!(platform.qualification, Qualification::GuardQualified);
    assert_eq!(
        platform.qualification_receipt_sha256.as_deref(),
        Some(digest(SDK_RECEIPT).as_str())
    );
    assert_eq!(platform.features, ALL_FEATURES);

    let receipt = json(SDK_RECEIPT);
    let status = &receipt["status"];
    assert_eq!(receipt["schema"], "guard-cigar-prepared-qualification.v1");
    assert_eq!(receipt["build"]["build_id"], build.identity.build_id);
    assert_eq!(
        receipt["build"]["manifest_sha256"],
        build.identity.manifest_sha256
    );
    assert_eq!(
        receipt["build"]["source_revision"],
        build.identity.source_revision
    );
    assert_eq!(
        status["package_fingerprint"].as_str(),
        platform.package_tree_sha256.as_deref()
    );
    assert_eq!(status["worker_fingerprint"], platform.worker_sha256);
    for proven in [
        "compile_verified",
        "shared_compile_verified",
        "persistence_compile_verified",
        "execution_handoff_verified",
    ] {
        assert_eq!(status[proven], true, "{proven}");
    }
    assert_eq!(status["active"], false);
    for flag in ["installed", "selected", "enabled", "qualification_promoted"] {
        assert_eq!(receipt[flag], false, "{flag}");
    }
}

#[test]
fn bundled_interpreter_qualification_digest_binds_the_committed_receipt() {
    let catalog = TrustedCatalog::bundled().unwrap();
    let build = &catalog.document().interpreters[0];
    assert_eq!(build.platform, "darwin-arm64");
    assert_eq!(build.qualification, Qualification::GuardQualified);
    assert_eq!(
        build.qualification_receipt_sha256.as_deref(),
        Some(digest(PYTHON_RECEIPT).as_str())
    );

    let receipt = json(PYTHON_RECEIPT);
    assert_eq!(
        receipt["schema"],
        "guard-cigar-private-python-qualification.v1"
    );
    assert_eq!(receipt["interpreter_build"]["build_id"], build.build_id);
    assert_eq!(
        receipt["interpreter_build"]["archive_sha256"],
        build.archive_sha256
    );
    assert_eq!(receipt["python_tree"], build.tree_sha256);
    assert_eq!(receipt["python_sha256"], build.executable_sha256);
    assert_eq!(receipt["python_files"], build.files);
    assert_eq!(receipt["python_bytes"], build.expanded_bytes);
    assert_eq!(
        receipt["interpreter"]["version"],
        serde_json::json!(build.python_version)
    );
    assert_eq!(receipt["relocated_before_probe"], true);
    assert_eq!(receipt["tree_unchanged_after_sdk"], true);
    for flag in [
        "registered",
        "selected",
        "enabled",
        "qualification_promoted",
    ] {
        assert_eq!(receipt[flag], false, "{flag}");
    }
    // The same run verified the locked SDK on this interpreter with every feature.
    let sdk = &catalog.document().builds[0];
    assert_eq!(receipt["sdk_build"]["build_id"], sdk.identity.build_id);
    assert_eq!(
        receipt["sdk_tree"].as_str(),
        sdk.platforms[0].package_tree_sha256.as_deref()
    );
    for proven in [
        "compile_verified",
        "shared_compile_verified",
        "persistence_compile_verified",
        "execution_handoff_verified",
    ] {
        assert_eq!(receipt["status"][proven], true, "{proven}");
    }
}

#[test]
fn bundled_qualification_is_scoped_to_darwin_arm64_and_resolves_for_activation_and_setup() {
    let catalog = TrustedCatalog::bundled().unwrap();
    let build_id = catalog.document().builds[0].identity.build_id.clone();
    let release = catalog
        .for_activation(&build_id, "darwin-arm64", false, &ALL_FEATURES)
        .unwrap();
    assert!(release.activation_qualified());
    assert!(catalog.signer().is_none());
    let python_id = catalog.document().interpreters[0].build_id.clone();
    assert!(catalog
        .interpreter_for_setup(&python_id, "darwin-arm64")
        .unwrap()
        .setup_qualified());
    // No other platform has a bundled entry, so none can be activated or set up.
    for other in [
        "darwin-x64",
        "linux-x64-gnu",
        "linux-arm64-gnu",
        "win32-x64",
    ] {
        assert_eq!(
            catalog
                .for_activation(&build_id, other, false, &[Feature::Graph])
                .unwrap_err(),
            ReleaseError::PlatformUnavailable,
            "{other}"
        );
        assert_eq!(
            catalog
                .interpreter_for_setup(&python_id, other)
                .unwrap_err(),
            ReleaseError::PlatformUnavailable,
            "{other}"
        );
    }
}

#[test]
fn committed_receipts_embed_no_user_home_directory() {
    for (name, bytes) in [("sdk", SDK_RECEIPT), ("python", PYTHON_RECEIPT)] {
        let text = std::str::from_utf8(bytes).unwrap();
        for private in [concat!("/Us", "ers/"), "/home/", "C:\\Us\u{65}rs"] {
            assert!(!text.contains(private), "{name} receipt embeds {private}");
        }
        assert!(
            !bytes.ends_with(b"\n"),
            "{name} receipt bytes must stay exact"
        );
    }
}
