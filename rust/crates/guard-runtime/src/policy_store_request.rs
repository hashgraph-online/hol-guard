//! Validate admitted versioned snapshots and their bounded current references.

use super::*;

impl PolicySnapshotStore {
    #[cfg(test)]
    pub(crate) fn validate_request_snapshot(
        &self,
        value: &Value,
        guard_home: &str,
        generation: u64,
    ) -> Result<Arc<AdmittedPolicySnapshot>, String> {
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let snapshot =
            self.validate_request_snapshot_locked(&state, value, guard_home, generation, now)?;
        Ok(Arc::clone(snapshot.as_v3()?))
    }

    pub(super) fn validate_request_snapshot_locked(
        &self,
        state: &PolicyState,
        value: &Value,
        guard_home: &str,
        generation: u64,
        now: u64,
    ) -> Result<Arc<AdmittedVersionedPolicySnapshot>, String> {
        if self.authority_changed.load(Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self)
        {
            return Err("native_policy_snapshot_context_mismatch".to_owned());
        }
        if state.invalid_on_startup {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        let Some(current) = state.snapshot.as_ref() else {
            return Err("native_policy_snapshot_missing".to_owned());
        };
        if *current.expires_at_ms() <= now {
            return Err("snapshot_expired".to_owned());
        }
        if generation != *current.generation() {
            return Err("native_policy_snapshot_not_current".to_owned());
        }
        if !current.matches_reference(
            value,
            &self.expected_runtime_identity,
            &state.canonical_bytes,
        )? {
            return Err("native_policy_snapshot_request_mismatch".to_owned());
        }
        if canonical_scope_text(guard_home) != self.expected_guard_home
            || current.scope_contract().scope_digest != self.expected_scope_digest
        {
            return Err("native_policy_snapshot_scope_mismatch".to_owned());
        }
        Ok(Arc::clone(current))
    }

    #[allow(dead_code)]
    pub(crate) fn validate_versioned_request_snapshot(
        &self,
        value: &Value,
        guard_home: &str,
        generation: u64,
    ) -> Result<Arc<AdmittedVersionedPolicySnapshot>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        self.validate_request_snapshot_locked(&state, value, guard_home, generation, now_ms()?)
    }

    /// Fence an approval challenge to the resident's current authenticated
    /// snapshot. The callback runs while the state mutex is held, so action
    /// reconstruction and binding derivation cannot observe a policy push in
    /// between. The callback must not call APIs that reacquire `state`.
    pub(crate) fn with_approval_fence<F, T>(
        &self,
        envelope: &guard_contracts::GuardHookEnvelopeV2,
        callback: F,
    ) -> Result<T, String>
    where
        F: FnOnce(&AdmittedPolicySnapshot) -> Result<T, String>,
    {
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let snapshot = self.validate_request_snapshot_locked(
            &state,
            &envelope.policy_snapshot,
            &envelope.source.guard_home,
            envelope.policy_generation,
            now,
        )?;
        let _command_lease =
            self.command_authority_lease_for_binding(snapshot.command_extensions())?;
        let result = callback(snapshot.as_v3()?.as_ref())?;
        self.validate_request_snapshot_locked(
            &state,
            &envelope.policy_snapshot,
            &envelope.source.guard_home,
            envelope.policy_generation,
            now_ms()?,
        )?;
        Ok(result)
    }

    pub(crate) fn current_snapshot(&self) -> Result<PolicySnapshotV3, String> {
        let now = now_ms()?;
        if self.authority_changed.load(Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self)
        {
            return Err("native_policy_snapshot_context_mismatch".to_owned());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| "native_policy_snapshot_missing".to_owned())?;
        snapshot.authenticated().validate(
            state.generation_floor.max(1),
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )?;
        Ok(snapshot.as_v3()?.snapshot().clone())
    }
}
