//! Synthetic contracts do not qualify real SDK releases or platform artifacts.
use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

const NOW: u64 = 1000;
const DOMAIN: &[u8] = b"hol-guard-cigar-release-catalog.v1\0";

pub(super) fn document() -> CatalogDocument {
    let mut document = TrustedCatalog::bundled().unwrap().document().clone();
    document.revision = 10;
    document.builds[0].identity.build_id = "synthetic-qualified-0_14_1".into();
    document.issued_at = 900;
    document.expires_at = 2000;
    // Synthetic fixtures describe one platform; bundled coverage is separate.
    document.builds[0].platforms.truncate(1);
    let platform = &mut document.builds[0].platforms[0];
    platform.qualification = Qualification::GuardQualified;
    platform.package_tree_sha256 = Some("5".repeat(64));
    platform.qualification_receipt_sha256 = Some("1".repeat(64));
    platform.features = vec![
        Feature::Graph,
        Feature::Sharing,
        Feature::Persistence,
        Feature::ExecutionContext,
    ];
    platform.dependencies = vec![WheelLock {
        distribution: "protobuf".into(),
        version: "7.35.0".into(),
        filename: "protobuf-7.35.0-py3-none-any.whl".into(),
        sha256: "2".repeat(64),
        bytes: 4096,
        requires_python: None,
        source: WheelSource::OfflineBundle,
    }];
    document
}
fn signer() -> (Ed25519KeyPair, TrustedKey) {
    // Test-only deterministic key. No production catalog keys are bundled.
    let pair = Ed25519KeyPair::from_seed_unchecked(&[39; 32]).unwrap();
    let key = TrustedKey {
        key_id: "fixture-key".into(),
        public_key: pair.public_key().as_ref().try_into().unwrap(),
        not_before: 500,
        not_after: 3000,
        revoked: false,
    };
    (pair, key)
}
fn envelope_bytes(payload: &str, pair: &Ed25519KeyPair) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(payload.as_bytes());
    let signature = pair.sign(&message);
    let text: String = signature
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    serde_json::to_vec(&json!({
        "schema":ENVELOPE_SCHEMA, "key_id":"fixture-key", "payload":payload, "signature_hex":text,
    }))
    .unwrap()
}
pub(super) fn verify(document: &CatalogDocument) -> Result<TrustedCatalog, ReleaseError> {
    let (pair, key) = signer();
    TrustedCatalog::verify(
        &envelope_bytes(&serde_json::to_string(document).unwrap(), &pair),
        &CatalogTrust {
            keys: &[key],
            checkpoint: None,
            now: NOW,
        },
    )
}
fn build_id(catalog: &TrustedCatalog) -> &str {
    &catalog.document().builds[0].identity.build_id
}

#[test]
fn bundled_public_build_activates_with_every_feature_listed() {
    let catalog = TrustedCatalog::bundled().unwrap();
    assert_eq!(catalog.document().builds[0].identity.sdk_version, "0.14.1");
    assert!(catalog.signer().is_none());
    let all = [
        Feature::Graph,
        Feature::Sharing,
        Feature::ExecutionContext,
        Feature::Persistence,
    ];
    let platforms: Vec<_> = catalog.document().builds[0]
        .platforms
        .iter()
        .map(|platform| platform.platform.as_str())
        .collect();
    assert_eq!(
        platforms,
        [
            "darwin-arm64",
            "darwin-x64",
            "linux-x64-gnu",
            "linux-arm64-gnu",
            "linux-x64-musl",
            "linux-arm64-musl",
            "win32-x64"
        ]
    );
    for platform in platforms {
        let features = &all[..if platform == "win32-x64" { 2 } else { 4 }];
        assert!(catalog
            .for_activation(build_id(&catalog), platform, false, features)
            .unwrap()
            .activation_qualified());
        let python = catalog
            .document()
            .interpreters
            .iter()
            .find(|build| build.platform == platform)
            .unwrap();
        assert!(catalog
            .interpreter_for_setup(&python.build_id, platform)
            .unwrap()
            .setup_qualified());
    }
}

#[test]
fn exact_signed_build_resolves_the_shipped_adapter_and_required_feature_receipts() {
    let catalog = verify(&document()).unwrap();
    let release = catalog
        .for_activation(
            build_id(&catalog),
            "darwin-arm64",
            false,
            &[Feature::Graph, Feature::Sharing],
        )
        .unwrap();
    assert_eq!(release.build().identity.sdk_version, "0.14.1");
    assert_eq!(release.profile().adapter_id, "guard-cigar-python-sdk-v1");
    assert_eq!(release.platform().dependencies[0].distribution, "protobuf");
    assert_eq!(release.checkpoint(), catalog.checkpoint());
    assert_eq!(catalog.signer(), Some("fixture-key"));
}

#[test]
fn a_future_compatible_release_is_catalog_data_with_independent_core_identity() {
    let mut doc = document();
    let mut future = doc.builds[0].clone();
    future.identity.build_id = "synthetic-future-0_15_2".into();
    future.identity.sdk_version = "0.15.2".into();
    future.identity.core_version = "0.15.1".into();
    future.identity.source_revision = "3".repeat(40);
    future.identity.manifest_sha256 = "4".repeat(64);
    let wheel = future.platforms[0].wheel.as_mut().unwrap();
    wheel.version = "0.15.2".into();
    wheel.filename = "hol_cigar-0.15.2-py3-none-macosx_11_0_arm64.whl".into();
    wheel.source = WheelSource::GithubCigarRelease {
        tag: "v0.15.2".into(),
    };
    doc.builds.push(future);
    let catalog = verify(&doc).unwrap();
    let release = catalog
        .for_activation(
            "synthetic-future-0_15_2",
            "darwin-arm64",
            false,
            &[Feature::Graph],
        )
        .unwrap();
    assert_eq!(release.build().identity.core_version, "0.15.1");
    assert_eq!(
        release.profile().adapter_id,
        catalog.document().profiles[0].adapter_id
    );
    // This proves routing/schema extensibility, never installed SDK behavior.
}

#[test]
fn same_version_build_replacements_are_distinct_and_identity_reuse_is_refused() {
    let first = document().builds[0].identity.clone();
    let mut next = first.clone();
    next.build_id = "same-version-final-build".into();
    next.manifest_sha256 = "8".repeat(64);
    assert_eq!(
        compare_builds(&first, &next).unwrap(),
        BuildChange::SameVersionReplacement
    );
    next.build_id = first.build_id.clone();
    assert_eq!(
        compare_builds(&first, &next),
        Err(ReleaseError::IdentityConflict)
    );
    assert_eq!(
        compare_builds(&first, &first).unwrap(),
        BuildChange::SameBuild
    );
}

#[test]
fn release_ordering_is_pep440_not_lexical() {
    let mut first = document().builds[0].identity.clone();
    first.sdk_version = "0.9.9".into();
    let mut next = first.clone();
    next.build_id = "synthetic-next".into();
    next.sdk_version = "0.9.10".into();
    assert_eq!(compare_builds(&first, &next).unwrap(), BuildChange::Upgrade);
    assert_eq!(
        compare_builds(&next, &first).unwrap(),
        BuildChange::Downgrade
    );
    next.sdk_version = "0.9.9rc1".into();
    assert_eq!(
        compare_builds(&first, &next).unwrap(),
        BuildChange::Downgrade
    );
    next.sdk_version = "not-a-version".into();
    assert_eq!(
        compare_builds(&first, &next),
        Err(ReleaseError::InvalidVersion)
    );
}

#[test]
fn unknown_keys_bad_signatures_and_payload_edits_cannot_supply_trust() {
    let (pair, key) = signer();
    let bytes = envelope_bytes(&serde_json::to_string(&document()).unwrap(), &pair);
    assert_eq!(
        TrustedCatalog::verify(
            &bytes,
            &CatalogTrust {
                keys: &[],
                checkpoint: None,
                now: NOW
            }
        )
        .unwrap_err(),
        ReleaseError::UnknownKey
    );
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["payload"] = json!(value["payload"]
        .as_str()
        .unwrap()
        .replace("0.14.1", "0.14.2"));
    assert_eq!(
        TrustedCatalog::verify(
            &serde_json::to_vec(&value).unwrap(),
            &CatalogTrust {
                keys: &[key],
                checkpoint: None,
                now: NOW
            }
        )
        .unwrap_err(),
        ReleaseError::InvalidSignature
    );
}

#[test]
fn revoked_not_yet_valid_expired_and_ambiguous_keys_are_refused() {
    for change in ["revoked", "future", "expired", "duplicate"] {
        let (pair, mut key) = signer();
        let bytes = envelope_bytes(&serde_json::to_string(&document()).unwrap(), &pair);
        match change {
            "revoked" => key.revoked = true,
            "future" => key.not_before = NOW + 1,
            "expired" => key.not_after = NOW,
            _ => {}
        }
        let mut keys = vec![key];
        if change == "duplicate" {
            keys.push(signer().1);
        }
        assert_eq!(
            TrustedCatalog::verify(
                &bytes,
                &CatalogTrust {
                    keys: &keys,
                    checkpoint: None,
                    now: NOW
                }
            )
            .unwrap_err(),
            ReleaseError::KeyUnavailable
        );
    }
}

#[test]
fn monotonic_revision_prevents_replay_and_same_revision_equivocation() {
    let first = verify(&document()).unwrap();
    let checkpoint = first.checkpoint().clone();
    let (pair, key) = signer();
    let keys = [key];
    let trust = CatalogTrust {
        keys: &keys,
        checkpoint: Some(&checkpoint),
        now: NOW,
    };
    let payload = serde_json::to_string(&document()).unwrap();
    assert!(TrustedCatalog::verify(&envelope_bytes(&payload, &pair), &trust).is_ok());
    let mut doc = document();
    doc.revision -= 1;
    assert_eq!(
        TrustedCatalog::verify(
            &envelope_bytes(&serde_json::to_string(&doc).unwrap(), &pair),
            &trust
        )
        .unwrap_err(),
        ReleaseError::Replay
    );
    doc.revision = checkpoint.revision;
    doc.builds[0].withdrawn = true;
    assert_eq!(
        TrustedCatalog::verify(
            &envelope_bytes(&serde_json::to_string(&doc).unwrap(), &pair),
            &trust
        )
        .unwrap_err(),
        ReleaseError::Equivocation
    );
    doc.revision += 1;
    assert!(TrustedCatalog::verify(
        &envelope_bytes(&serde_json::to_string(&doc).unwrap(), &pair),
        &trust
    )
    .is_ok());
}

#[test]
fn catalog_expiry_and_future_issue_dates_are_enforced_for_imports() {
    for (issued, expires) in [(500, NOW), (NOW + 1, NOW + 200)] {
        let mut doc = document();
        doc.issued_at = issued;
        doc.expires_at = expires;
        assert_eq!(verify(&doc).unwrap_err(), ReleaseError::Expired);
    }
}

#[test]
fn duplicate_nested_json_fields_are_refused_even_with_a_valid_signature() {
    let (pair, key) = signer();
    let payload = serde_json::to_string(&document()).unwrap().replace(
        "\"sdk_version\":\"0.14.1\"",
        "\"sdk_version\":\"0.14.1\",\"sdk_version\":\"0.15.0\"",
    );
    let bytes = envelope_bytes(&payload, &pair);
    assert_eq!(
        TrustedCatalog::verify(
            &bytes,
            &CatalogTrust {
                keys: &[key],
                checkpoint: None,
                now: NOW
            }
        )
        .unwrap_err(),
        ReleaseError::InvalidCatalog
    );
}

#[test]
fn withdrawn_unqualified_preview_unknown_and_missing_features_cannot_activate() {
    let mut doc = document();
    let id = doc.builds[0].identity.build_id.clone();
    doc.builds[0].withdrawn = true;
    assert_eq!(
        verify(&doc)
            .unwrap()
            .prepare(&id, "darwin-arm64", false)
            .unwrap_err(),
        ReleaseError::BuildWithdrawn
    );
    doc.builds[0].withdrawn = false;
    doc.builds[0].platforms[0].qualification = Qualification::UpstreamOnly;
    assert!(verify(&doc)
        .unwrap()
        .prepare(&id, "darwin-arm64", false)
        .is_ok());
    // Qualification state is informational; only the listed features gate.
    assert!(verify(&doc)
        .unwrap()
        .for_activation(&id, "darwin-arm64", false, &[])
        .is_ok());
    doc.builds[0].platforms[0].features = vec![Feature::Graph];
    assert_eq!(
        verify(&doc)
            .unwrap()
            .for_activation(&id, "darwin-arm64", false, &[Feature::Persistence])
            .unwrap_err(),
        ReleaseError::FeatureUnqualified
    );
    doc.builds[0].channel = Channel::Preview;
    assert_eq!(
        verify(&doc)
            .unwrap()
            .prepare(&id, "darwin-arm64", false)
            .unwrap_err(),
        ReleaseError::PreviewDisabled
    );
    assert!(verify(&doc)
        .unwrap()
        .prepare(&id, "darwin-arm64", true)
        .is_ok());
    assert_eq!(
        verify(&doc)
            .unwrap()
            .prepare("missing", "darwin-arm64", true)
            .unwrap_err(),
        ReleaseError::BuildUnknown
    );
    assert_eq!(
        verify(&doc)
            .unwrap()
            .prepare(&id, "win32-x64", true)
            .unwrap_err(),
        ReleaseError::PlatformUnavailable
    );
}

#[test]
fn catalog_cannot_download_an_adapter_or_widen_python_or_protocol_support() {
    for field in [
        "adapter_id",
        "worker_protocol",
        "python_minor",
        "sdk_api_revision",
        "guard_contract",
    ] {
        let mut doc = document();
        match field {
            "adapter_id" => doc.profiles[0].adapter_id = "downloaded-python-adapter".into(),
            "worker_protocol" => doc.profiles[0].worker_protocol = "cigar.context-worker.v2".into(),
            "python_minor" => doc.profiles[0].python_minor = 15,
            "sdk_api_revision" => doc.profiles[0].sdk_api_revision = 2,
            _ => doc.profiles[0].guard_contract = 2,
        }
        let catalog = verify(&doc).unwrap();
        assert_eq!(
            catalog
                .prepare(build_id(&catalog), "darwin-arm64", false)
                .unwrap_err(),
            if field == "guard_contract" {
                ReleaseError::GuardUpdateRequired
            } else {
                ReleaseError::AdapterUpdateRequired
            }
        );
    }
}

#[test]
fn candidate_enrollment_is_separate_from_catalog_qualification() {
    let mut doc = document();
    doc.builds[0].channel = Channel::LocalCandidate;
    doc.builds[0].platforms[0].qualification = Qualification::LocalCandidate;
    let catalog = verify(&doc).unwrap();
    assert_eq!(
        catalog
            .prepare(build_id(&catalog), "darwin-arm64", true)
            .unwrap_err(),
        ReleaseError::CandidateRequiresEnrollment
    );
}

#[test]
fn oversized_envelopes_unknown_fields_and_excess_builds_are_refused() {
    let bytes = vec![b' '; MAX_ENVELOPE_BYTES + 1];
    assert_eq!(
        TrustedCatalog::verify(
            &bytes,
            &CatalogTrust {
                keys: &[],
                checkpoint: None,
                now: NOW
            }
        )
        .unwrap_err(),
        ReleaseError::TooLarge
    );
    let (pair, key) = signer();
    let mut value = serde_json::to_value(document()).unwrap();
    value["trust_me"] = json!(true);
    assert_eq!(
        TrustedCatalog::verify(
            &envelope_bytes(&serde_json::to_string(&value).unwrap(), &pair),
            &CatalogTrust {
                keys: &[key],
                checkpoint: None,
                now: NOW
            }
        )
        .unwrap_err(),
        ReleaseError::InvalidCatalog
    );
    let mut doc = document();
    doc.builds = vec![doc.builds[0].clone(); MAX_BUILDS + 1];
    assert_eq!(verify(&doc).unwrap_err(), ReleaseError::InvalidCatalog);
}

#[path = "wheel_lock_tests.rs"]
mod wheel_lock_tests;
