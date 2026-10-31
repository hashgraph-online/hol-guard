use crate::{identity::version, strict_json, types::*, ReleaseError};
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"hol-guard-cigar-release-catalog.v1\0";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCheckpoint {
    pub revision: u64,
    pub payload_sha256: String,
}
/// Trust keys come from Guard's authorized configuration, never from a catalog,
/// archive, HTTP client or signed payload. No production key is generated here.
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}
pub struct CatalogTrust<'a> {
    pub keys: &'a [TrustedKey],
    pub checkpoint: Option<&'a CatalogCheckpoint>,
    pub now: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    key_id: String,
    payload: String,
    signature_hex: String,
}

/// Construction proves bundled origin or an authorized detached signature.
/// Catalog qualification remains separate from actual installation verification.
#[derive(Clone, Debug)]
pub struct TrustedCatalog {
    document: CatalogDocument,
    checkpoint: CatalogCheckpoint,
    signer: Option<String>,
}
#[derive(Clone, Debug)]
pub struct ResolvedRelease {
    build: ReleaseBuild,
    platform: PlatformBuild,
    profile: AdapterProfile,
    checkpoint: CatalogCheckpoint,
    activation_qualified: bool,
}
impl ResolvedRelease {
    pub fn activation_qualified(&self) -> bool {
        self.activation_qualified
    }
    pub fn build(&self) -> &ReleaseBuild {
        &self.build
    }
    pub fn platform(&self) -> &PlatformBuild {
        &self.platform
    }
    pub fn profile(&self) -> &AdapterProfile {
        &self.profile
    }
    pub fn checkpoint(&self) -> &CatalogCheckpoint {
        &self.checkpoint
    }
}
impl TrustedCatalog {
    /// Call only with the bytes embedded in the signed Guard distribution.
    /// This is deliberately not a file loader or network/import endpoint.
    pub fn bundled() -> Result<Self, ReleaseError> {
        let bytes = include_bytes!("../../../../integrations/cigar/release-catalog.v1.json");
        Self::parse(bytes, None)
    }
    pub fn verify(envelope: &[u8], trust: &CatalogTrust<'_>) -> Result<Self, ReleaseError> {
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(ReleaseError::TooLarge);
        }
        let envelope: Envelope =
            strict_json::parse(envelope).map_err(|_| ReleaseError::InvalidCatalog)?;
        if envelope.schema != ENVELOPE_SCHEMA {
            return Err(ReleaseError::UnsupportedSchema);
        }
        if !identifier(&envelope.key_id) {
            return Err(ReleaseError::InvalidCatalog);
        }
        if envelope.payload.len() > MAX_CATALOG_BYTES {
            return Err(ReleaseError::TooLarge);
        }
        let mut matching = trust
            .keys
            .iter()
            .filter(|key| key.key_id == envelope.key_id);
        let key = matching.next().ok_or(ReleaseError::UnknownKey)?;
        if matching.next().is_some()
            || key.revoked
            || trust.now < key.not_before
            || trust.now >= key.not_after
        {
            return Err(ReleaseError::KeyUnavailable);
        }
        let signature = decode_signature(&envelope.signature_hex)?;
        let mut message = DOMAIN.to_vec();
        message.extend_from_slice(envelope.payload.as_bytes());
        signature::UnparsedPublicKey::new(&signature::ED25519, key.public_key)
            .verify(&message, &signature)
            .map_err(|_| ReleaseError::InvalidSignature)?;
        let result = Self::parse(envelope.payload.as_bytes(), Some(envelope.key_id))?;
        if result.document.issued_at > trust.now || result.document.expires_at <= trust.now {
            return Err(ReleaseError::Expired);
        }
        if let Some(previous) = trust.checkpoint {
            if !hex(&previous.payload_sha256, 64) || previous.revision == 0 {
                return Err(ReleaseError::InvalidCatalog);
            }
            if result.checkpoint.revision < previous.revision {
                return Err(ReleaseError::Replay);
            }
            if result.checkpoint.revision == previous.revision
                && result.checkpoint.payload_sha256 != previous.payload_sha256
            {
                return Err(ReleaseError::Equivocation);
            }
        }
        Ok(result)
    }
    fn parse(payload: &[u8], signer: Option<String>) -> Result<Self, ReleaseError> {
        if payload.len() > MAX_CATALOG_BYTES {
            return Err(ReleaseError::TooLarge);
        }
        let document: CatalogDocument =
            strict_json::parse(payload).map_err(|_| ReleaseError::InvalidCatalog)?;
        validate(&document)?;
        let checkpoint = CatalogCheckpoint {
            revision: document.revision,
            payload_sha256: format!("{:x}", Sha256::digest(payload)),
        };
        Ok(Self {
            document,
            checkpoint,
            signer,
        })
    }
    pub fn document(&self) -> &CatalogDocument {
        &self.document
    }
    pub fn checkpoint(&self) -> &CatalogCheckpoint {
        &self.checkpoint
    }
    pub fn signer(&self) -> Option<&str> {
        self.signer.as_deref()
    }

    /// Resolves trusted metadata for preparation. It does not authorize runtime
    /// activation or replace protected artifact/interpreter/doctor checks.
    pub fn prepare(
        &self,
        build_id: &str,
        platform: &str,
        allow_preview: bool,
    ) -> Result<ResolvedRelease, ReleaseError> {
        let build = self
            .document
            .builds
            .iter()
            .find(|build| build.identity.build_id == build_id)
            .ok_or(ReleaseError::BuildUnknown)?;
        if build.withdrawn {
            return Err(ReleaseError::BuildWithdrawn);
        }
        if !allow_preview
            && (build.channel == Channel::Preview
                || version(&build.identity.sdk_version)?.any_prerelease())
        {
            return Err(ReleaseError::PreviewDisabled);
        }
        if build.channel == Channel::LocalCandidate {
            return Err(ReleaseError::CandidateRequiresEnrollment);
        }
        let profile = self
            .document
            .profiles
            .iter()
            .find(|profile| profile.profile_id == build.profile_id)
            .ok_or(ReleaseError::AdapterUpdateRequired)?;
        check_shipped_adapter(profile)?;
        let artifact = build
            .platforms
            .iter()
            .find(|value| value.platform == platform)
            .ok_or(ReleaseError::PlatformUnavailable)?;
        if artifact.wheel.is_none() || artifact.package_tree_sha256.is_none() {
            return Err(ReleaseError::DependencyLockMissing);
        }
        // This shipped adapter imports protobuf. A qualified installation must
        // lock it rather than resolving the SDK's broad dependency at install.
        if !artifact
            .dependencies
            .iter()
            .any(|wheel| wheel.distribution == "protobuf")
        {
            return Err(ReleaseError::DependencyLockMissing);
        }
        Ok(ResolvedRelease {
            build: build.clone(),
            platform: artifact.clone(),
            profile: profile.clone(),
            checkpoint: self.checkpoint.clone(),
            activation_qualified: false,
        })
    }
    pub fn for_activation(
        &self,
        build_id: &str,
        platform: &str,
        allow_preview: bool,
        features: &[Feature],
    ) -> Result<ResolvedRelease, ReleaseError> {
        let mut release = self.prepare(build_id, platform, allow_preview)?;
        if release.platform.qualification != Qualification::GuardQualified {
            return Err(ReleaseError::QualificationRequired);
        }
        if features
            .iter()
            .any(|feature| !release.platform.features.contains(feature))
        {
            return Err(ReleaseError::FeatureUnqualified);
        }
        release.activation_qualified = true;
        Ok(release)
    }
}
pub(crate) fn resolve_installation_receipt(
    receipt: &crate::VerifiedInstallationReceipt,
    features: &[Feature],
) -> Result<ResolvedRelease, ReleaseError> {
    let metadata = receipt.metadata();
    let document = crate::installation::document(metadata);
    let payload =
        serde_json::to_vec(&document).map_err(|_| ReleaseError::InstallationReceiptInvalid)?;
    // This path is reachable only after native-owner receipt authentication.
    // It does not import or trust an unsigned remote/offline catalog.
    let catalog = TrustedCatalog::parse(&payload, None)?;
    let mut release = catalog.for_activation(
        &metadata.release.identity.build_id,
        &metadata.platform,
        true,
        features,
    )?;
    release.checkpoint = metadata.catalog_checkpoint.clone();
    Ok(release)
}

fn decode_signature(text: &str) -> Result<[u8; 64], ReleaseError> {
    if !hex(text, 128) {
        return Err(ReleaseError::InvalidSignature);
    }
    let mut output = [0; 64];
    for (index, value) in output.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| ReleaseError::InvalidSignature)?;
    }
    Ok(output)
}

pub(crate) fn validate(document: &CatalogDocument) -> Result<(), ReleaseError> {
    if document.schema != CATALOG_SCHEMA {
        return Err(ReleaseError::UnsupportedSchema);
    }
    if document.revision == 0
        || document.expires_at <= document.issued_at
        || document.profiles.is_empty()
        || document.profiles.len() > 16
        || document.builds.len() > MAX_BUILDS
    {
        return Err(ReleaseError::InvalidCatalog);
    }
    crate::interpreter_build::validate(&document.interpreters)?;
    let mut profiles = BTreeSet::new();
    for profile in &document.profiles {
        if !identifier(&profile.profile_id)
            || !identifier(&profile.adapter_id)
            || profile.worker_protocol.len() > 128
            || profile.broker_protocol.len() > 128
            || profile.broker_storage.len() > 128
            || profile.python_implementation.len() > 32
            || !profiles.insert(&profile.profile_id)
        {
            return Err(ReleaseError::InvalidCatalog);
        }
    }
    if let Some(legacy) = &document.legacy_candidate {
        version(&legacy.sdk_version)?;
        if !crate::labels::producer_label(&legacy.core_version) {
            return Err(ReleaseError::InvalidVersion);
        }
        if !profiles.contains(&legacy.profile_id) || !hex(&legacy.source_revision, 40) {
            return Err(ReleaseError::InvalidCatalog);
        }
    }
    let mut builds = BTreeSet::new();
    for build in &document.builds {
        build.identity.validate()?;
        if !builds.insert(&build.identity.build_id) {
            return Err(ReleaseError::DuplicateIdentity);
        }
        if !profiles.contains(&build.profile_id)
            || build.platforms.is_empty()
            || build.platforms.len() > 7
        {
            return Err(ReleaseError::InvalidCatalog);
        }
        let mut platforms = BTreeSet::new();
        for artifact in &build.platforms {
            if !platform(&artifact.platform)
                || !platforms.insert(&artifact.platform)
                || !hex(&artifact.worker_sha256, 64)
                || artifact
                    .package_tree_sha256
                    .as_deref()
                    .is_some_and(|value| !hex(value, 64))
                || artifact.dependencies.len() > 64
                || artifact.features.len() > 4
                || artifact.features.iter().collect::<BTreeSet<_>>().len()
                    != artifact.features.len()
                || artifact
                    .qualification_receipt_sha256
                    .as_deref()
                    .is_some_and(|value| !hex(value, 64))
            {
                return Err(ReleaseError::InvalidCatalog);
            }
            if artifact.qualification == Qualification::GuardQualified
                && (artifact.qualification_receipt_sha256.is_none()
                    || artifact.wheel.is_none()
                    || !artifact.features.contains(&Feature::Graph))
            {
                return Err(ReleaseError::InvalidCatalog);
            }
            if artifact.qualification == Qualification::LocalCandidate
                && build.channel != Channel::LocalCandidate
                || build.channel == Channel::LocalCandidate
                    && artifact.qualification != Qualification::LocalCandidate
            {
                return Err(ReleaseError::InvalidCatalog);
            }
            let mut distributions = BTreeSet::new();
            let mut names = BTreeSet::new();
            for wheel in artifact.wheel.iter().chain(&artifact.dependencies) {
                validate_wheel(wheel)?;
                if !distributions.insert(&wheel.distribution) || !names.insert(&wheel.filename) {
                    return Err(ReleaseError::InvalidCatalog);
                }
            }
            if let Some(wheel) = &artifact.wheel {
                if wheel.distribution != "hol-cigar" || wheel.version != build.identity.sdk_version
                {
                    return Err(ReleaseError::InvalidCatalog);
                }
            }
        }
    }
    Ok(())
}
fn validate_wheel(wheel: &WheelLock) -> Result<(), ReleaseError> {
    version(&wheel.version)?;
    if wheel.distribution.is_empty()
        || wheel.distribution.len() > 128
        || !wheel
            .distribution
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !crate::labels::wheel_filename(&wheel.filename)
        || !hex(&wheel.sha256, 64)
        || wheel.bytes == 0
        || wheel.bytes > 128 * 1024 * 1024
    {
        return Err(ReleaseError::InvalidCatalog);
    }
    if let Some(requirement) = &wheel.requires_python {
        crate::python::validate_requirement(requirement)?;
    }
    let _ = wheel.download_url()?;
    Ok(())
}
