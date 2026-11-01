//! Description tests do not manufacture a VerifiedRuntime or startup authority.
use super::*;
use crate::InterpreterFacts;

fn fixture() -> (BundleApproval, RuntimeStatus) {
    let (legacy, profile) = legacy_candidate_profile().unwrap();
    let approval = BundleApproval {
        schema: "guard-cigar-bundle-approval.v1".into(),
        platform: "darwin-arm64".into(),
        python_sha256: "a".repeat(64),
        package_tree_sha256: "b".repeat(64),
        worker_sha256: "c".repeat(64),
        files: 124,
        bytes: 11454530,
        release: None,
        python_bundle: None,
    };
    let status = RuntimeStatus {
        schema: "guard-cigar-runtime-status.v1",
        interpreter: InterpreterFacts {
            schema: "guard-cigar-interpreter.v1".into(),
            implementation: "cpython".into(),
            version: [3, 14, 7],
            release_level: "final".into(),
            free_threaded: false,
            debug_build: false,
            abi: "cpython-314-darwin".into(),
            platform: "darwin-arm64".into(),
        },
        package_version: legacy.sdk_version,
        core_version: legacy.core_version,
        protocol: profile.worker_protocol,
        adapter_id: profile.adapter_id,
        adapter_revision: profile.adapter_revision,
        release: None,
        package_fingerprint: approval.package_tree_sha256.clone(),
        worker_fingerprint: approval.worker_sha256.clone(),
        features: vec![],
        compile_verified: true,
        shared_compile_verified: false,
        persistence_compile_verified: true,
        execution_handoff_verified: false,
        active: true,
    };
    (approval, status)
}
#[test]
fn enrollment_identity_has_no_inferred_public_build_or_source_revision() {
    let (approval, status) = fixture();
    let producer = EvidenceUpgradeProducer::enrolled_description(&approval, &status).unwrap();
    assert!(producer.data_preparation_qualified());
    let binding = producer.release_binding().unwrap();
    let value = serde_json::to_value(&binding).unwrap();
    assert_eq!(value["qualification"], "verified_enrolled_candidate");
    for field in ["source_revision", "identity", "manifest_sha256", "build_id"] {
        assert!(value.get(field).is_none());
    }
    assert!(value["approval"].get("release").is_none());
    let reloaded: EvidenceProducerBinding = serde_json::from_value(value).unwrap();
    reloaded.validate().unwrap();
    assert_eq!(reloaded, binding);
}
#[test]
fn exact_legacy_sdk_dependencies_and_external_python_distinguish_producers() {
    let (mut approval, mut status) = fixture();
    let original = EvidenceUpgradeProducer::enrolled_description(&approval, &status).unwrap();
    approval.package_tree_sha256 = "d".repeat(64);
    // A runtime with a different measured tree cannot describe this approval.
    assert!(EvidenceUpgradeProducer::enrolled_description(&approval, &status).is_err());
    status.package_fingerprint = approval.package_tree_sha256.clone();
    let changed = EvidenceUpgradeProducer::enrolled_description(&approval, &status).unwrap();
    assert_ne!(original.identity_sha256(), changed.identity_sha256());
    approval.python_sha256 = "e".repeat(64);
    let python = EvidenceUpgradeProducer::enrolled_description(&approval, &status).unwrap();
    assert_ne!(python.identity_sha256(), changed.identity_sha256());
    status.interpreter.version[2] += 1;
    let patch = EvidenceUpgradeProducer::enrolled_description(&approval, &status).unwrap();
    assert_ne!(patch.identity_sha256(), python.identity_sha256());
}
#[test]
fn legacy_profile_and_measured_capability_remain_required() {
    let (mut approval, mut status) = fixture();
    status.persistence_compile_verified = false;
    let producer = EvidenceUpgradeProducer::enrolled_description(&approval, &status).unwrap();
    assert!(!producer.data_preparation_qualified());
    status.persistence_compile_verified = true;
    approval.schema = "guard-cigar-bundle-approval.v2".into();
    assert!(EvidenceUpgradeProducer::enrolled_description(&approval, &status).is_err());
    approval.schema = "guard-cigar-bundle-approval.v1".into();
    approval.python_sha256 = "unverified-path".into();
    assert!(EvidenceUpgradeProducer::enrolled_description(&approval, &status).is_err());
    approval.python_sha256 = "a".repeat(64);
    status.protocol = "unknown-protocol".into();
    assert!(EvidenceUpgradeProducer::enrolled_description(&approval, &status).is_err());
}
#[test]
fn sealed_enrollment_descriptions_reject_public_relabeling_and_unknown_fields() {
    let (approval, status) = fixture();
    let binding = EvidenceUpgradeProducer::enrolled_description(&approval, &status)
        .unwrap()
        .release_binding()
        .unwrap();
    let value = serde_json::to_value(binding).unwrap();
    let mut relabeled = value.clone();
    relabeled["qualification"] = "guard_qualified".into();
    let binding: EvidenceProducerBinding = serde_json::from_value(relabeled).unwrap();
    assert!(binding.validate().is_err());
    let mut invented = value;
    invented["source_revision"] = "b47380e5a5cbeaaad5a61cab3372e9e67368732f".into();
    assert!(serde_json::from_value::<EvidenceProducerBinding>(invented).is_err());
}
