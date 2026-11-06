//! Keep the authenticated policy and control mutation leases through dispatch.

use std::sync::{Arc, MutexGuard};

use guard_contracts::GuardHookEnvelopeV2;

use crate::policy_enforcement::AdmittedPolicySnapshot;
#[cfg(target_os = "macos")]
use crate::policy_store::policy_store_authority;
use crate::policy_store::{
    now_ms, policy_store_command_authority::CommandAuthorityLease, PolicySnapshotStore, PolicyState,
};

pub(crate) struct LaunchPolicyFence<'store> {
    // Struct fields drop in declaration order. Release the cross-process
    // control lease before unblocking a policy push on the state mutex.
    _command: Option<CommandAuthorityLease>,
    snapshot: Arc<AdmittedPolicySnapshot>,
    _state: MutexGuard<'store, PolicyState>,
    #[cfg(target_os = "macos")]
    store: &'store PolicySnapshotStore,
}

impl LaunchPolicyFence<'_> {
    pub(crate) fn snapshot(&self) -> &AdmittedPolicySnapshot {
        self.snapshot.as_ref()
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn require_current(&self) -> Result<(), String> {
        if self.snapshot.expires_at_ms <= now_ms()?
            || self
                .store
                .authority_changed
                .load(std::sync::atomic::Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self.store)
        {
            return Err("native_policy_snapshot_context_mismatch".to_owned());
        }
        Ok(())
    }
}

impl PolicySnapshotStore {
    /// The caller must release this lease on dispatch acknowledgment or any
    /// aborted launch. It must not hold it for the user program's execution.
    pub(crate) fn fence_for_launch(
        &self,
        envelope: &GuardHookEnvelopeV2,
    ) -> Result<LaunchPolicyFence<'_>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let snapshot = self.validate_request_snapshot_locked(
            &state,
            &envelope.policy_snapshot,
            &envelope.source.guard_home,
            envelope.policy_generation,
            now_ms()?,
        )?;
        let command = self.command_authority_lease(snapshot.snapshot())?;
        Ok(LaunchPolicyFence {
            _state: state,
            _command: command,
            snapshot,
            #[cfg(target_os = "macos")]
            store: self,
        })
    }
}

#[cfg(test)]
#[path = "policy_store_launch_fence_tests.rs"]
mod tests;
