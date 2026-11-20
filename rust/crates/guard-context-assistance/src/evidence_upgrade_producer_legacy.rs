//! An enrolled producer can only be described through a real verified runtime.
use super::*;
use crate::evidence_cache::upgrade::producer_binding::{
    BuiltinEvidenceBinding, EnrolledEvidenceBinding,
};
use crate::{BundleApproval, RuntimeStatus, VerifiedRuntime};
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
        if runtime.is_builtin() {
            return Self::builtin_description(runtime.bundle_approval(), status);
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
        Self::described("guard-cigar-enrolled-evidence-producer.v1", binding, status)
    }

    fn builtin_description(
        approval: &BundleApproval,
        status: &RuntimeStatus,
    ) -> Result<Self, RuntimeError> {
        if *approval != crate::builtin_approval()
            || status.core_version != guard_cigar_native::CORE_VERSION
            || status.protocol != guard_cigar_native::WORKER_PROTOCOL
            || status.worker_fingerprint != approval.worker_sha256
        {
            return Err(RuntimeError::ApprovalMismatch);
        }
        let binding = EvidenceProducerBinding::Builtin(Box::new(BuiltinEvidenceBinding {
            schema: BuiltinEvidenceBinding::SCHEMA.into(),
            core_version: status.core_version.clone(),
            worker_protocol: status.protocol.clone(),
            broker_protocol: guard_cigar_native::BROKER_PROTOCOL.into(),
            platform: approval.platform.clone(),
            worker_sha256: approval.worker_sha256.clone(),
        }));
        Self::described(BuiltinEvidenceBinding::SCHEMA, binding, status)
    }

    fn described(
        schema: &str,
        binding: EvidenceProducerBinding,
        status: &RuntimeStatus,
    ) -> Result<Self, RuntimeError> {
        binding.validate()?;
        let bytes =
            serde_json::to_vec(&(schema, &binding)).map_err(|_| RuntimeError::RequestInvalid)?;
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
