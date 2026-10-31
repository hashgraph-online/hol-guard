//! Historical data provenance, not release qualification or startup authority.
use super::*;
use crate::{BundleApproval, InterpreterFacts};
use guard_cigar_release::{legacy_candidate_profile, AdapterProfile, ReleaseBinding};

/// Untagged keeps the existing catalog-bound record wire shape readable.
/// The other shape explicitly identifies enrollment, with no inferred upstream
/// source revision, release manifest or public build ID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub(crate) enum EvidenceProducerBinding {
    Catalog(Box<ReleaseBinding>),
    Enrolled(Box<EnrolledEvidenceBinding>),
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrolledEvidenceBinding {
    pub schema: String,
    pub qualification: String,
    pub sdk_version: String,
    pub core_version: String,
    pub profile: AdapterProfile,
    pub approval: BundleApproval,
    pub interpreter: InterpreterFacts,
}
impl EvidenceProducerBinding {
    pub(crate) fn validate(&self) -> Result<(), RuntimeError> {
        match self {
            Self::Catalog(binding) => binding
                .identity
                .validate()
                .map_err(|_| RuntimeError::StorageRepairRequired),
            Self::Enrolled(binding) => binding.validate(),
        }
    }
}
impl EnrolledEvidenceBinding {
    fn validate(&self) -> Result<(), RuntimeError> {
        let (legacy, profile) =
            legacy_candidate_profile().map_err(|_| RuntimeError::PackageMismatch)?;
        if self.schema != "guard-cigar-enrolled-evidence-producer.v1"
            || self.qualification != "verified_enrolled_candidate"
            || self.sdk_version != legacy.sdk_version
            || self.core_version != legacy.core_version
            || self.profile != profile
            || self.approval.schema != "guard-cigar-bundle-approval.v1"
            || self.approval.release.is_some()
            || self.approval.python_bundle.is_some()
            || self.approval.platform != self.interpreter.platform
            || crate::check_interpreter(&self.interpreter).is_err()
            || [
                &self.approval.python_sha256,
                &self.approval.package_tree_sha256,
                &self.approval.worker_sha256,
            ]
            .iter()
            .any(|s| !valid_key(s))
            || self.approval.files == 0
            || self.approval.files > 8192
            || self.approval.bytes == 0
            || self.approval.bytes > 256 * 1024 * 1024
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        Ok(())
    }
}
