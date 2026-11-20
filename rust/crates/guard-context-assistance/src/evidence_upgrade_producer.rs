//! An exact SDK plus complete interpreter identity. A storage version label or
//! matching worker executable cannot hide changed SDK dependencies or Python.
use super::producer_binding::EvidenceProducerBinding;
use super::*;
use crate::{release::RuntimeRelease, BundleApproval};
use guard_cigar_release::{Feature, ResolvedRelease};

#[path = "evidence_upgrade_producer_legacy.rs"]
mod legacy;

#[derive(Clone)]
pub struct EvidenceUpgradeProducer {
    release: Option<ResolvedRelease>,
    binding: EvidenceProducerBinding,
    pub(super) features: Vec<Feature>,
    pub(super) fingerprint: String,
}
impl EvidenceUpgradeProducer {
    pub(super) fn activation_qualified(&self) -> bool {
        self.release
            .as_ref()
            .is_none_or(|r| r.activation_qualified())
    }
    pub(super) fn supported_data_format(&self) -> bool {
        match &self.release {
            Some(release) => {
                release.profile().evidence_schema == 1
                    && release.profile().broker_storage == "sqlite-checkpoint.v1"
            }
            None => self.binding.validate().is_ok(),
        }
    }
    pub(crate) fn metadata_preparation_qualified(&self) -> bool {
        self.activation_qualified() && self.supported_data_format()
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
    pub(crate) fn check_runtime(
        &self,
        runtime: &crate::VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        if !runtime.status().persistence_compile_verified {
            return Err(RuntimeError::ApprovalMismatch);
        }
        self.revalidate_runtime(runtime)
    }
    /// Match a live measured producer without requiring a persistence opt-in.
    /// This still grants no file scope or CIGAR client authority.
    pub fn revalidate_runtime(&self, runtime: &crate::VerifiedRuntime) -> Result<(), RuntimeError> {
        if !runtime.status().active || !runtime.status().compile_verified {
            return Err(RuntimeError::ApprovalMismatch);
        }
        let current = match &self.release {
            Some(release) => Self::new(release, runtime.bundle_approval())?,
            None => Self::from_enrolled_runtime(runtime)?,
        };
        if current.fingerprint != self.fingerprint {
            return Err(RuntimeError::ApprovalMismatch);
        }
        Ok(())
    }
    pub fn new(release: &ResolvedRelease, approval: &BundleApproval) -> Result<Self, RuntimeError> {
        let p = release.platform();
        if !RuntimeRelease::catalog(release)?.matches(approval)
            || !valid_key(&approval.python_sha256)
            || approval.platform != p.platform
            || Some(&approval.package_tree_sha256) != p.package_tree_sha256.as_ref()
            || approval.worker_sha256 != p.worker_sha256
        {
            return Err(RuntimeError::PackageMismatch);
        }
        if let Some(python) = &approval.python_bundle {
            python
                .validate()
                .map_err(|_| RuntimeError::PackageMismatch)?;
            if python.platform != p.platform || python.executable_sha256 != approval.python_sha256 {
                return Err(RuntimeError::PackageMismatch);
            }
        }
        let locks: BTreeMap<_, _> = p
            .wheel
            .iter()
            .chain(&p.dependencies)
            .map(|w| {
                (
                    &w.distribution,
                    (&w.version, &w.filename, &w.sha256, w.bytes),
                )
            })
            .collect();
        let binding = release
            .binding()
            .map_err(|_| RuntimeError::PackageMismatch)?;
        // Preserve the original catalog producer identity and wire shape.
        let bytes = serde_json::to_vec(&(
            "guard-cigar-evidence-producer.v1",
            &binding,
            &p.worker_sha256,
            &p.package_tree_sha256,
            locks,
            &approval.python_sha256,
            &approval.python_bundle,
        ))
        .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(Self {
            release: Some(release.clone()),
            binding: EvidenceProducerBinding::Catalog(Box::new(binding)),
            features: p.features.clone(),
            fingerprint: format!("{:x}", Sha256::digest(bytes)),
        })
    }
}
