//! The identity of the engine that wrote stored CIGAR data. Only the engine
//! compiled into Guard writes data, so its release and protocols are the whole
//! producer identity.
use super::producer_binding::{BuiltinEvidenceBinding, EvidenceProducerBinding};
use super::*;
use crate::{BundleApproval, RuntimeStatus, VerifiedRuntime};
use guard_cigar_release::Feature;

#[derive(Clone)]
pub struct EvidenceUpgradeProducer {
    binding: EvidenceProducerBinding,
    pub(super) features: Vec<Feature>,
    pub(super) fingerprint: String,
}
impl EvidenceUpgradeProducer {
    pub(crate) fn metadata_preparation_qualified(&self) -> bool {
        self.binding.validate().is_ok()
    }
    pub(crate) fn data_preparation_qualified(&self) -> bool {
        self.metadata_preparation_qualified() && self.features.contains(&Feature::Persistence)
    }
    /// Historical labels/hashes only; never paths or execution authority.
    pub fn describe(&self) -> serde_json::Value {
        serde_json::json!({"schema":"guard-cigar-evidence-producer-summary.v1",
            "producer_sha256":self.fingerprint,"release":self.binding,"authority_granted":false})
    }
    pub fn identity_sha256(&self) -> &str {
        &self.fingerprint
    }
    pub(crate) fn release_binding(&self) -> Result<EvidenceProducerBinding, RuntimeError> {
        self.binding.validate()?;
        Ok(self.binding.clone())
    }
    pub(crate) fn check_runtime(&self, runtime: &VerifiedRuntime) -> Result<(), RuntimeError> {
        if !runtime.status().persistence_compile_verified {
            return Err(RuntimeError::ApprovalMismatch);
        }
        self.revalidate_runtime(runtime)
    }
    /// Match a live measured producer without requiring a persistence opt-in.
    /// This still grants no file scope or CIGAR client authority.
    pub fn revalidate_runtime(&self, runtime: &VerifiedRuntime) -> Result<(), RuntimeError> {
        if Self::from_runtime(runtime)?.fingerprint != self.fingerprint {
            return Err(RuntimeError::ApprovalMismatch);
        }
        Ok(())
    }
    /// Describes the running built-in engine. This object describes
    /// historical data, not execution consent.
    pub fn from_runtime(runtime: &VerifiedRuntime) -> Result<Self, RuntimeError> {
        let status = runtime.status();
        if !status.active || !status.compile_verified || !runtime.is_builtin() {
            return Err(RuntimeError::ApprovalMismatch);
        }
        Self::builtin_description(runtime.bundle_approval(), status)
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
        Self::described(
            BuiltinEvidenceBinding {
                schema: BuiltinEvidenceBinding::SCHEMA.into(),
                core_version: status.core_version.clone(),
                worker_protocol: status.protocol.clone(),
                broker_protocol: guard_cigar_native::BROKER_PROTOCOL.into(),
                platform: approval.platform.clone(),
                worker_sha256: approval.worker_sha256.clone(),
            },
            features,
        )
    }

    fn described(
        binding: BuiltinEvidenceBinding,
        features: Vec<Feature>,
    ) -> Result<Self, RuntimeError> {
        let binding = EvidenceProducerBinding::Builtin(Box::new(binding));
        binding.validate()?;
        let bytes = serde_json::to_vec(&(BuiltinEvidenceBinding::SCHEMA, &binding))
            .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(Self {
            binding,
            features,
            fingerprint: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    /// A built-in producer with persistence, for storage tests that do not
    /// start an engine. Different worker hashes give different producers.
    #[cfg(all(test, unix))]
    pub(crate) fn for_test(worker_sha256: &str) -> Self {
        Self::described(
            BuiltinEvidenceBinding {
                schema: BuiltinEvidenceBinding::SCHEMA.into(),
                core_version: guard_cigar_native::CORE_VERSION.into(),
                worker_protocol: guard_cigar_native::WORKER_PROTOCOL.into(),
                broker_protocol: guard_cigar_native::BROKER_PROTOCOL.into(),
                platform: "darwin-arm64".into(),
                worker_sha256: worker_sha256.into(),
            },
            vec![Feature::Graph, Feature::Persistence],
        )
        .unwrap()
    }
}
