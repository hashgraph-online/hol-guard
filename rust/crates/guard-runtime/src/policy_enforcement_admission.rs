//! Compile authenticated policy once before publishing an immutable generation.

use super::{CompiledEffectivePolicy, PolicySnapshotV3};
use guard_policy_snapshot::PolicySnapshotV4;

/// An immutable authenticated snapshot and the selector indexes derived from
/// that exact value. No mutable dereference is exposed, so a generation cannot
/// silently retain indexes from a different effective policy.
#[derive(Debug)]
pub(crate) struct AdmittedSnapshot<S> {
    snapshot: S,
    pub(crate) compiled: CompiledEffectivePolicy,
    pub(crate) command_extensions:
        Option<guard_command::native_command_controls::CompiledNativeCommandControls>,
}

pub(crate) type AdmittedPolicySnapshot = AdmittedSnapshot<PolicySnapshotV3>;
pub(crate) type AdmittedScopedPolicySnapshot = AdmittedSnapshot<PolicySnapshotV4>;

impl<S> AdmittedSnapshot<S> {
    pub(crate) fn snapshot(&self) -> &S {
        &self.snapshot
    }
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
}

impl AdmittedScopedPolicySnapshot {
    pub(crate) fn new(snapshot: PolicySnapshotV4) -> Result<Self, String> {
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
}

impl<S> std::ops::Deref for AdmittedSnapshot<S> {
    type Target = S;
    fn deref(&self) -> &Self::Target {
        self.snapshot()
    }
}
