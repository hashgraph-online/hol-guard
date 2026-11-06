//! An enrolled producer can only be described through a real verified runtime.
use super::*;
use crate::evidence_cache::upgrade::producer_binding::EnrolledEvidenceBinding;
use crate::{RuntimeStatus, VerifiedRuntime};
use guard_cigar_release::{legacy_candidate_profile, Feature};

impl EvidenceUpgradeProducer {
    /// Does not infer a public build or source revision from matching version
    /// strings. Native installation enrollment and byte checks remain required
    /// at startup; this object describes historical data, not execution consent.
    pub fn from_enrolled_runtime(runtime: &VerifiedRuntime) -> Result<Self, RuntimeError> {
        let status = runtime.status();
        if !status.active || !status.compile_verified || status.release.is_some() {
            return Err(RuntimeError::ApprovalMismatch);
        }
        Self::enrolled_description(runtime.bundle_approval(), status)
    }

    fn enrolled_description(
        approval: &BundleApproval,
        status: &RuntimeStatus,
    ) -> Result<Self, RuntimeError> {
        let (legacy, profile) =
            legacy_candidate_profile().map_err(|_| RuntimeError::PackageMismatch)?;
        if !RuntimeRelease::legacy()?.matches(approval)
            || status.package_version != legacy.sdk_version
            || status.core_version != legacy.core_version
            || status.package_fingerprint != approval.package_tree_sha256
            || status.worker_fingerprint != approval.worker_sha256
            || status.adapter_id != profile.adapter_id
            || status.adapter_revision != profile.adapter_revision
            || status.protocol != profile.worker_protocol
        {
            return Err(RuntimeError::ApprovalMismatch);
        }
        let binding = EvidenceProducerBinding::Enrolled(Box::new(EnrolledEvidenceBinding {
            schema: "guard-cigar-enrolled-evidence-producer.v1".into(),
            qualification: "verified_enrolled_candidate".into(),
            sdk_version: status.package_version.clone(),
            core_version: status.core_version.clone(),
            profile,
            approval: approval.clone(),
            interpreter: status.interpreter.clone(),
        }));
        binding.validate()?;
        let bytes = serde_json::to_vec(&("guard-cigar-enrolled-evidence-producer.v1", &binding))
            .map_err(|_| RuntimeError::RequestInvalid)?;
        let mut features = vec![Feature::Graph];
        for (verified, feature) in [
            (status.shared_compile_verified, Feature::Sharing),
            (status.persistence_compile_verified, Feature::Persistence),
            (status.execution_handoff_verified, Feature::ExecutionContext),
        ] {
            if verified {
                features.push(feature);
            }
        }
        Ok(Self {
            release: None,
            binding,
            features,
            fingerprint: format!("{:x}", Sha256::digest(bytes)),
        })
    }
}

#[cfg(test)]
#[path = "evidence_upgrade_producer_legacy_tests.rs"]
mod tests;
