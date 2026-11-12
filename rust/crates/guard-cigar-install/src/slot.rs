//! Immutable physical identity, independent of approval/source metadata.
use crate::*;

/// Approval receipts, qualified features, catalog revisions and download
/// origins may change without replacing the same verified bytes. The build,
/// shipped adapter, exact dependency set, worker, tree and interpreter may not.
pub fn slot_id(release: &ResolvedRelease, python_sha256: &str) -> Result<String, InstallError> {
    if python_sha256.len() != 64
        || !python_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(InstallError::InputsInvalid);
    }
    let platform = release.platform();
    let locks: BTreeMap<_, _> = platform
        .wheel
        .iter()
        .chain(&platform.dependencies)
        .map(|wheel| {
            (
                &wheel.distribution,
                (&wheel.version, &wheel.filename, &wheel.sha256, wheel.bytes),
            )
        })
        .collect();
    let bytes = serde_json::to_vec(&(
        "guard-cigar-managed-slot.v2",
        release.binding().map_err(|_| InstallError::InputsInvalid)?,
        locks,
        &platform.package_tree_sha256,
        &platform.worker_sha256,
        python_sha256,
    ))
    .map_err(|_| InstallError::InputsInvalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Managed SDK slots bind the complete interpreter distribution as well as
/// the existing exact SDK/dependency identity. External v2 slots are preserved.
pub fn slot_id_with_python(
    release: &ResolvedRelease,
    python: &guard_cigar_release::InterpreterBinding,
) -> Result<String, InstallError> {
    python.validate().map_err(|_| InstallError::InputsInvalid)?;
    if python.platform != release.platform().platform {
        return Err(InstallError::InputsInvalid);
    }
    let sdk = slot_id(release, &python.executable_sha256)?;
    let bytes = serde_json::to_vec(&("guard-cigar-managed-slot.v3", sdk, python))
        .map_err(|_| InstallError::InputsInvalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_cigar_release::{
        CatalogDocument, CatalogTrust, Feature, Qualification, TrustedCatalog, TrustedKey,
        WheelSource,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    fn release(doc: &CatalogDocument) -> ResolvedRelease {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[79; 32]).unwrap();
        let key = TrustedKey {
            key_id: "slot-tests-only".into(),
            public_key: pair.public_key().as_ref().try_into().unwrap(),
            not_before: 1,
            not_after: u64::MAX,
            revoked: false,
        };
        let payload = serde_json::to_string(doc).unwrap();
        let mut message = b"hol-guard-cigar-release-catalog.v1\0".to_vec();
        message.extend_from_slice(payload.as_bytes());
        let signature: String = pair
            .sign(&message)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let envelope = serde_json::to_vec(&serde_json::json!({"schema":"guard-cigar-signed-catalog.v1","key_id":key.key_id,"payload":payload,"signature_hex":signature})).unwrap();
        TrustedCatalog::verify(
            &envelope,
            &CatalogTrust {
                keys: &[key],
                checkpoint: None,
                now: doc.issued_at,
            },
        )
        .unwrap()
        .prepare(&doc.builds[0].identity.build_id, "darwin-arm64", false)
        .unwrap()
    }
    #[test]
    fn managed_sdk_slot_changes_when_only_private_standard_library_identity_changes() {
        let doc = TrustedCatalog::bundled().unwrap().document().clone();
        let sdk = release(&doc);
        let mut python = doc.interpreters[0].binding().unwrap();
        let original = slot_id_with_python(&sdk, &python).unwrap();
        assert_ne!(original, slot_id(&sdk, &python.executable_sha256).unwrap());
        let executable = python.executable_sha256.clone();
        python.tree_sha256 = "b".repeat(64);
        assert_eq!(python.executable_sha256, executable);
        assert_ne!(original, slot_id_with_python(&sdk, &python).unwrap());
        python.platform = "linux-x64-gnu".into();
        assert_eq!(
            slot_id_with_python(&sdk, &python),
            Err(InstallError::InputsInvalid)
        );
    }
    #[test]
    fn qualification_and_origin_refresh_reuse_exactly_the_same_slot() {
        let mut doc = TrustedCatalog::bundled().unwrap().document().clone();
        let original = slot_id(&release(&doc), &"a".repeat(64)).unwrap();
        doc.revision += 1;
        let platform = &mut doc.builds[0].platforms[0];
        platform.qualification = Qualification::GuardQualified;
        platform.qualification_receipt_sha256 = Some("f".repeat(64));
        platform.features = vec![Feature::Graph, Feature::Sharing];
        platform.wheel.as_mut().unwrap().source = WheelSource::OfflineBundle;
        assert_eq!(original, slot_id(&release(&doc), &"a".repeat(64)).unwrap());
        doc.builds[0].platforms[0].features.reverse();
        doc.builds[0].platforms[0].qualification_receipt_sha256 = Some("e".repeat(64));
        assert_eq!(original, slot_id(&release(&doc), &"a".repeat(64)).unwrap());
        for field in ["tree", "worker", "dependency", "manifest"] {
            let mut changed = doc.clone();
            match field {
                "tree" => changed.builds[0].platforms[0].package_tree_sha256 = Some("b".repeat(64)),
                "worker" => changed.builds[0].platforms[0].worker_sha256 = "b".repeat(64),
                "dependency" => {
                    changed.builds[0].platforms[0].dependencies[0].sha256 = "b".repeat(64)
                }
                _ => changed.builds[0].identity.manifest_sha256 = "b".repeat(64),
            }
            assert_ne!(
                original,
                slot_id(&release(&changed), &"a".repeat(64)).unwrap(),
                "{field}"
            );
        }
    }
}
