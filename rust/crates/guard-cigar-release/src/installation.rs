//! Locally sealed installation receipts keep already approved immutable builds
//! usable across Guard releases/catalog refreshes. The seal is local to one
//! Guard home and cannot authorize a remote catalog or a new installation.
use crate::types::{hex, identifier};
use crate::{
    AdapterProfile, CatalogCheckpoint, CatalogDocument, Feature, ReleaseBuild, ReleaseError,
    ResolvedRelease, TrustedCatalog,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"hol-guard-cigar-local-installation.v1\0";
const LIMIT: usize = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledReleaseReceipt {
    pub schema: String,
    pub release: ReleaseBuild,
    pub profile: AdapterProfile,
    pub platform: String,
    pub catalog_checkpoint: CatalogCheckpoint,
    pub guard_binary_sha256: String,
    /// Native hash of the full installation ID, selection, approval and facts.
    pub context_sha256: String,
    pub verified_features: Vec<Feature>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedInstallationReceipt {
    pub schema: String,
    pub payload: String,
    pub mac_hex: String,
}

/// Only verification against the owner's separately provisioned installation
/// key constructs this capability. Deserializing a record cannot construct it.
#[derive(Clone, Debug)]
pub struct VerifiedInstallationReceipt {
    metadata: InstalledReleaseReceipt,
}
impl VerifiedInstallationReceipt {
    pub fn metadata(&self) -> &InstalledReleaseReceipt {
        &self.metadata
    }
    pub fn resolve(
        &self,
        current: &TrustedCatalog,
        features: &[Feature],
    ) -> Result<ResolvedRelease, ReleaseError> {
        // Omission from a newer bundled catalog is not a withdrawal. Explicit
        // known withdrawal or reuse of an identity still refuses activation.
        if let Some(build) = current
            .document()
            .builds
            .iter()
            .find(|build| build.identity.build_id == self.metadata.release.identity.build_id)
        {
            if build.withdrawn {
                return Err(ReleaseError::BuildWithdrawn);
            }
            if build.identity != self.metadata.release.identity {
                return Err(ReleaseError::IdentityConflict);
            }
            if let Some(platform) = build
                .platforms
                .iter()
                .find(|item| item.platform == self.metadata.platform)
            {
                crate::artifact_identity::ensure(platform, &self.metadata.release.platforms[0])?;
            }
        }
        crate::catalog::resolve_installation_receipt(self, features)
    }
}
pub fn seal_installation_receipt(
    metadata: &InstalledReleaseReceipt,
    key: &[u8; 32],
) -> Result<SealedInstallationReceipt, ReleaseError> {
    validate(metadata)?;
    let payload =
        serde_json::to_string(metadata).map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    if payload.len() > LIMIT {
        return Err(ReleaseError::TooLarge);
    }
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(payload.as_bytes());
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), &message);
    Ok(SealedInstallationReceipt {
        schema: "guard-cigar-sealed-installation.v1".into(),
        payload,
        mac_hex: tag
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}
pub fn verify_installation_receipt(
    sealed: &SealedInstallationReceipt,
    key: &[u8; 32],
    expected_context_sha256: &str,
) -> Result<VerifiedInstallationReceipt, ReleaseError> {
    if sealed.schema != "guard-cigar-sealed-installation.v1"
        || sealed.payload.len() > LIMIT
        || !hex(&sealed.mac_hex, 64)
        || !hex(expected_context_sha256, 64)
    {
        return Err(ReleaseError::InstallationReceiptInvalid);
    }
    let mut tag = [0u8; 32];
    for (index, byte) in tag.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&sealed.mac_hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    }
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(sealed.payload.as_bytes());
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &message, &tag)
        .map_err(|_| ReleaseError::InstallationReceiptUnauthenticated)?;
    let metadata: InstalledReleaseReceipt = crate::strict_json::parse(sealed.payload.as_bytes())
        .map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    validate(&metadata)?;
    if metadata.context_sha256 != expected_context_sha256 {
        return Err(ReleaseError::InstallationContextMismatch);
    }
    Ok(VerifiedInstallationReceipt { metadata })
}
pub(crate) fn document(metadata: &InstalledReleaseReceipt) -> CatalogDocument {
    CatalogDocument {
        schema: crate::CATALOG_SCHEMA.into(),
        revision: metadata.catalog_checkpoint.revision,
        issued_at: 0,
        expires_at: 1,
        legacy_candidate: None,
        profiles: vec![metadata.profile.clone()],
        builds: vec![metadata.release.clone()],
        interpreters: Vec::new(),
    }
}
fn validate(metadata: &InstalledReleaseReceipt) -> Result<(), ReleaseError> {
    if metadata.schema != "guard-cigar-installed-release.v1"
        || !identifier(&metadata.profile.profile_id)
        || !hex(&metadata.guard_binary_sha256, 64)
        || !hex(&metadata.context_sha256, 64)
        || !hex(&metadata.catalog_checkpoint.payload_sha256, 64)
        || metadata.catalog_checkpoint.revision == 0
        || metadata.release.platforms.len() != 1
        || metadata.release.platforms[0].platform != metadata.platform
        || metadata.release.profile_id != metadata.profile.profile_id
        || metadata.verified_features.len() > 4
        || metadata
            .verified_features
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != metadata.verified_features.len()
        || !metadata.verified_features.contains(&Feature::Graph)
        || metadata
            .verified_features
            .iter()
            .any(|feature| !metadata.release.platforms[0].features.contains(feature))
    {
        return Err(ReleaseError::InstallationReceiptInvalid);
    }
    crate::check_shipped_adapter(&metadata.profile)?;
    crate::catalog::validate(&document(metadata))?;
    let platform = &metadata.release.platforms[0];
    if metadata.release.withdrawn
        || metadata.release.channel == crate::Channel::LocalCandidate
        || platform.qualification != crate::Qualification::GuardQualified
        || platform.package_tree_sha256.is_none()
        || platform.wheel.is_none()
        || !platform
            .dependencies
            .iter()
            .any(|wheel| wheel.distribution == "protobuf")
    {
        return Err(ReleaseError::QualificationRequired);
    }
    Ok(())
}
