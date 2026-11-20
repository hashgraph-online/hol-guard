use crate::{AdapterProfile, BuildIdentity, ReleaseError, ResolvedRelease, TrustedCatalog};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Persisted identity is metadata, not an authority token. Runtime startup must
/// compare it with a freshly resolved trusted catalog before using versioned bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBinding {
    pub identity: BuildIdentity,
    pub profile_id: String,
    pub adapter_id: String,
    pub adapter_revision: u32,
    pub platform: String,
    pub profile_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyCandidate {
    pub sdk_version: String,
    pub core_version: String,
    pub profile_id: String,
    pub source_revision: String,
}
impl ResolvedRelease {
    pub fn binding(&self) -> Result<ReleaseBinding, ReleaseError> {
        Ok(ReleaseBinding {
            identity: self.build().identity.clone(),
            profile_id: self.profile().profile_id.clone(),
            adapter_id: self.profile().adapter_id.clone(),
            adapter_revision: self.profile().adapter_revision,
            platform: self.platform().platform.clone(),
            profile_sha256: format!(
                "{:x}",
                Sha256::digest(
                    serde_json::to_vec(self.profile()).map_err(|_| ReleaseError::InvalidCatalog)?
                )
            ),
        })
    }
}
pub fn legacy_candidate_profile() -> Result<(LegacyCandidate, AdapterProfile), ReleaseError> {
    let catalog = TrustedCatalog::bundled()?;
    let legacy = catalog
        .document()
        .legacy_candidate
        .clone()
        .ok_or(ReleaseError::UnsupportedSchema)?;
    let profile = catalog
        .document()
        .profiles
        .iter()
        .find(|profile| profile.profile_id == legacy.profile_id)
        .ok_or(ReleaseError::AdapterUpdateRequired)?
        .clone();
    crate::check_shipped_adapter(&profile)?;
    Ok((legacy, profile))
}
