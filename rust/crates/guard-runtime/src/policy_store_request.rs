//! Validation of current snapshots and their bounded request references.

use super::*;

impl PolicySnapshotStore {
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
        self.validate_request_snapshot_locked(&state, value, guard_home, generation, now)
    }

    pub(super) fn validate_request_snapshot_locked(
        &self,
        state: &PolicyState,
        value: &Value,
        guard_home: &str,
        generation: u64,
        now: u64,
    ) -> Result<Arc<AdmittedPolicySnapshot>, String> {
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
        if current.expires_at_ms <= now {
            return Err("snapshot_expired".to_owned());
        }
        if generation != current.generation {
            return Err("native_policy_snapshot_not_current".to_owned());
        }
        let Some(reference) = value.as_object() else {
            return Err("native_policy_snapshot_invalid".to_owned());
        };
        let compact_keys = ["generation", "policy_digest", "runtime_identity"];
        let is_compact_reference = reference.len() == compact_keys.len()
            && compact_keys.iter().all(|key| reference.contains_key(*key));
        if is_compact_reference {
            let reference_generation = reference
                .get("generation")
                .and_then(Value::as_u64)
                .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
            let policy_digest = reference
                .get("policy_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
            let runtime_identity = reference
                .get("runtime_identity")
                .and_then(Value::as_str)
                .ok_or_else(|| "native_policy_snapshot_invalid".to_owned())?;
            if reference_generation != current.generation
                || policy_digest != current.policy_digest
                || runtime_identity != self.expected_runtime_identity
            {
                return Err("native_policy_snapshot_request_mismatch".to_owned());
            }
        } else {
            let incoming: PolicySnapshotV3 = serde_json::from_value(value.clone())
                .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
            let incoming_bytes = snapshot_bytes(&incoming).map_err(snapshot_error)?;
            if incoming.generation != current.generation || incoming_bytes != state.canonical_bytes
            {
                return Err("native_policy_snapshot_request_mismatch".to_owned());
            }
        }
        if canonical_scope_text(guard_home) != self.expected_guard_home
            || current.scope_contract.scope_digest != self.expected_scope_digest
        {
            return Err("native_policy_snapshot_scope_mismatch".to_owned());
        }
        Ok(Arc::clone(current))
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
        validate_v3(
            snapshot,
            state.generation_floor.max(1),
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        Ok(snapshot.snapshot().clone())
    }
}
