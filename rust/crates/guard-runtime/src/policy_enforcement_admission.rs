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
}

impl AdmittedPolicySnapshot {
    pub(crate) fn new(snapshot: PolicySnapshotV3) -> Result<Self, String> {
        let compiled = CompiledEffectivePolicy::new(&snapshot.effective_policy)?;
        let command_extensions = snapshot
            .command_extensions
            .as_ref()
            .map(guard_command::native_command_controls::CompiledNativeCommandControls::new)
            .transpose()
            .map_err(ToOwned::to_owned)?;
        Ok(Self {
            snapshot,
            compiled,
            command_extensions,
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
