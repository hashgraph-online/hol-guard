//! Compile authenticated policy once before publishing an immutable generation.

use super::{CompiledEffectivePolicy, PolicySnapshotV3};

/// An immutable authenticated snapshot and the selector indexes derived from
/// that exact value. No mutable dereference is exposed, so a generation cannot
/// silently retain indexes from a different effective policy.
#[derive(Debug)]
pub(crate) struct AdmittedPolicySnapshot {
    snapshot: PolicySnapshotV3,
    pub(super) compiled: CompiledEffectivePolicy,
    pub(crate) command_extensions:
        Option<guard_command::native_command_controls::CompiledNativeCommandControls>,
    pub(super) business_policy: Option<super::policy_enforcement_business::CompiledBusinessPolicy>,
}

impl AdmittedPolicySnapshot {
    #[cfg(test)]
    pub(crate) fn new(snapshot: PolicySnapshotV3) -> Result<Self, String> {
        Self::with_command_loader(
            snapshot,
            guard_command::native_command_controls::CompiledNativeCommandControls::new,
        )
    }

    pub(crate) fn with_command_loader(
        snapshot: PolicySnapshotV3,
        loader: impl FnOnce(
            &guard_contracts::NativeCommandControlBindingV1,
        ) -> Result<
            guard_command::native_command_controls::CompiledNativeCommandControls,
            &'static str,
        >,
    ) -> Result<Self, String> {
        let compiled = CompiledEffectivePolicy::new(&snapshot.effective_policy)?;
        let business_policy = snapshot
            .business_policy
            .as_ref()
            .map(super::policy_enforcement_business::CompiledBusinessPolicy::new)
            .transpose()?;
        let command_extensions = snapshot
            .command_extensions
            .as_ref()
            .map(loader)
            .transpose()
            .map_err(ToOwned::to_owned)?;
        Ok(Self {
            snapshot,
            compiled,
            command_extensions,
            business_policy,
        })
    }

    pub(crate) fn snapshot(&self) -> &PolicySnapshotV3 {
        &self.snapshot
    }
}

impl std::ops::Deref for AdmittedPolicySnapshot {
    type Target = PolicySnapshotV3;

    fn deref(&self) -> &Self::Target {
        self.snapshot()
    }
}
