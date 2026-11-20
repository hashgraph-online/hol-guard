//! A shipped adapter plus trusted exact release data; never a browser-selected path.
use crate::{BundleApproval, RuntimeError};
use guard_cigar_release::{legacy_candidate_profile, ReleaseBinding, ResolvedRelease};

#[derive(Clone)]
pub(crate) struct RuntimeRelease {
    pub sdk_version: String,
    pub core_version: String,
    pub worker_protocol: String,
    pub broker_protocol: String,
    pub adapter_id: String,
    pub adapter_revision: u32,
    pub binding: Option<ReleaseBinding>,
    pub platform: Option<String>,
    pub package_tree_sha256: Option<String>,
    pub worker_sha256: Option<String>,
    python_release: Option<ResolvedRelease>,
}
impl RuntimeRelease {
    pub fn legacy() -> Result<Self, RuntimeError> {
        let (legacy, profile) =
            legacy_candidate_profile().map_err(|_| RuntimeError::PackageMismatch)?;
        Ok(Self {
            sdk_version: legacy.sdk_version,
            core_version: legacy.core_version,
            worker_protocol: profile.worker_protocol,
            broker_protocol: profile.broker_protocol,
            adapter_id: profile.adapter_id,
            adapter_revision: profile.adapter_revision,
            binding: None,
            platform: None,
            package_tree_sha256: None,
            worker_sha256: None,
            python_release: None,
        })
    }
    /// The CIGAR engine compiled into this Guard executable.
    pub fn builtin() -> Self {
        let approval = crate::runtime::builtin_approval();
        Self {
            sdk_version: guard_cigar_native::CORE_VERSION.into(),
            core_version: guard_cigar_native::CORE_VERSION.into(),
            worker_protocol: guard_cigar_native::WORKER_PROTOCOL.into(),
            broker_protocol: guard_cigar_native::BROKER_PROTOCOL.into(),
            adapter_id: crate::runtime::BUILTIN_ADAPTER.into(),
            adapter_revision: 1,
            binding: None,
            platform: Some(approval.platform),
            package_tree_sha256: Some(approval.package_tree_sha256),
            worker_sha256: Some(approval.worker_sha256),
            python_release: None,
        }
    }
    pub(crate) fn is_builtin(&self) -> bool {
        self.adapter_id == crate::runtime::BUILTIN_ADAPTER
    }
    pub fn catalog(release: &ResolvedRelease) -> Result<Self, RuntimeError> {
        guard_cigar_release::check_shipped_adapter(release.profile())
            .map_err(|_| RuntimeError::PackageMismatch)?;
        Ok(Self {
            sdk_version: release.build().identity.sdk_version.clone(),
            core_version: release.build().identity.core_version.clone(),
            worker_protocol: release.profile().worker_protocol.clone(),
            broker_protocol: release.profile().broker_protocol.clone(),
            adapter_id: release.profile().adapter_id.clone(),
            adapter_revision: release.profile().adapter_revision,
            binding: Some(
                release
                    .binding()
                    .map_err(|_| RuntimeError::PackageMismatch)?,
            ),
            platform: Some(release.platform().platform.clone()),
            package_tree_sha256: release.platform().package_tree_sha256.clone(),
            worker_sha256: Some(release.platform().worker_sha256.clone()),
            python_release: Some(release.clone()),
        })
    }
    pub fn check_python_version(&self, version: [u16; 3]) -> Result<(), RuntimeError> {
        if let Some(release) = &self.python_release {
            release.check_python_version(version).map_err(|_| {
                RuntimeError::Interpreter(crate::UnavailableReason::PythonReleaseIncompatible)
            })?;
        }
        Ok(())
    }
    pub fn matches(&self, approval: &BundleApproval) -> bool {
        if self.is_builtin() {
            return *approval == crate::runtime::builtin_approval();
        }
        let schema = match (self.binding.is_some(), approval.python_bundle.is_some()) {
            (true, true) => "guard-cigar-bundle-approval.v3",
            (true, false) => "guard-cigar-bundle-approval.v2",
            (false, false) => "guard-cigar-bundle-approval.v1",
            (false, true) => return false,
        };
        approval.schema == schema && approval.release == self.binding
    }
    pub fn bridge(&self) -> Result<&'static str, RuntimeError> {
        match (self.adapter_id.as_str(), self.adapter_revision) {
            ("guard-cigar-python-sdk-v1", 1) => {
                Ok(include_str!("../../../../integrations/cigar/bridge.py"))
            }
            _ => Err(RuntimeError::PackageMismatch),
        }
    }
}
