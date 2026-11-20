use super::*;
use crate::tests::{document, verify};

fn metadata() -> InstalledInterpreterReceipt {
    let catalog = TrustedCatalog::bundled().unwrap();
    let mut build = catalog.document().interpreters[0].clone();
    build.qualification = Qualification::GuardQualified;
    build.qualification_receipt_sha256 = Some("9".repeat(64));
    InstalledInterpreterReceipt {
        schema: "guard-cigar-installed-python.v1".into(),
        build,
        catalog_checkpoint: catalog.checkpoint().clone(),
        guard_binary_sha256: "7".repeat(64),
        context_sha256: "6".repeat(64),
    }
}
fn current(build: InterpreterBuild) -> TrustedCatalog {
    let mut doc = document();
    doc.interpreters = vec![build];
    verify(&doc).unwrap()
}
#[test]
fn authenticated_private_python_survives_catalog_omission_without_new_setup_authority() {
    let metadata = metadata();
    let sealed = seal_interpreter_receipt(&metadata, &[41; 32]).unwrap();
    let verified =
        verify_interpreter_receipt(&sealed, &[41; 32], &metadata.context_sha256).unwrap();
    let mut doc = document();
    doc.interpreters.clear();
    let catalog = verify(&doc).unwrap();
    let resolved = verified.resolve(&catalog).unwrap();
    assert!(resolved.setup_qualified());
    assert_eq!(resolved.build(), &metadata.build);
    assert_eq!(resolved.checkpoint(), &metadata.catalog_checkpoint);
    assert_eq!(
        catalog
            .interpreter_for_setup(&metadata.build.build_id, "darwin-arm64")
            .unwrap_err(),
        ReleaseError::BuildUnknown
    );
}
#[test]
fn python_receipt_cannot_cross_guard_homes_or_installation_contexts() {
    let metadata = metadata();
    let sealed = seal_interpreter_receipt(&metadata, &[41; 32]).unwrap();
    assert_eq!(
        verify_interpreter_receipt(&sealed, &[42; 32], &metadata.context_sha256).unwrap_err(),
        ReleaseError::InstallationReceiptUnauthenticated
    );
    assert_eq!(
        verify_interpreter_receipt(&sealed, &[41; 32], &"8".repeat(64)).unwrap_err(),
        ReleaseError::InstallationContextMismatch
    );
    let sdk_envelope = SealedInstallationReceipt {
        schema: sealed.schema.clone(),
        payload: sealed.payload.clone(),
        mac_hex: sealed.mac_hex.clone(),
    };
    assert!(
        verify_installation_receipt(&sdk_envelope, &[41; 32], &metadata.context_sha256).is_err()
    );
}
#[test]
fn receipt_tampering_with_python_tree_and_explicit_withdrawal_are_refused() {
    let metadata = metadata();
    let sealed = seal_interpreter_receipt(&metadata, &[41; 32]).unwrap();
    let verified =
        verify_interpreter_receipt(&sealed, &[41; 32], &metadata.context_sha256).unwrap();
    let mut changed = metadata.build.clone();
    changed.withdrawn = true;
    assert_eq!(
        verified.resolve(&current(changed)).unwrap_err(),
        ReleaseError::BuildWithdrawn
    );
    for field in [
        "tree",
        "source",
        "archive",
        "bytes",
        "version",
        "executable",
    ] {
        let mut changed = metadata.build.clone();
        match field {
            "tree" => changed.tree_sha256 = "a".repeat(64),
            "source" => changed.source_revision = "a".repeat(40),
            "archive" => changed.archive_sha256 = "a".repeat(64),
            "bytes" => changed.expanded_bytes += 1,
            "version" => changed.python_version[2] += 1,
            _ => changed.executable_sha256 = "a".repeat(64),
        }
        assert_eq!(
            verified.resolve(&current(changed)).unwrap_err(),
            ReleaseError::IdentityConflict
        );
    }
    let mut tampered = sealed.clone();
    tampered.payload = tampered
        .payload
        .replace(&metadata.build.tree_sha256, &"b".repeat(64));
    assert_eq!(
        verify_interpreter_receipt(&tampered, &[41; 32], &metadata.context_sha256).unwrap_err(),
        ReleaseError::InstallationReceiptUnauthenticated
    );
}
#[test]
fn qualification_refresh_is_metadata_and_upstream_python_mints_receipts() {
    let metadata = metadata();
    let sealed = seal_interpreter_receipt(&metadata, &[41; 32]).unwrap();
    let verified =
        verify_interpreter_receipt(&sealed, &[41; 32], &metadata.context_sha256).unwrap();
    let mut changed = metadata.build.clone();
    changed.source_release = "20261027".into();
    changed.qualification = Qualification::UpstreamOnly;
    changed.qualification_receipt_sha256 = None;
    assert!(verified
        .resolve(&current(changed.clone()))
        .unwrap()
        .setup_qualified());
    assert_eq!(
        changed.binding().unwrap(),
        metadata.build.binding().unwrap()
    );
    assert!(seal_interpreter_receipt(
        &InstalledInterpreterReceipt {
            build: changed,
            ..metadata
        },
        &[41; 32]
    )
    .is_ok());
}
