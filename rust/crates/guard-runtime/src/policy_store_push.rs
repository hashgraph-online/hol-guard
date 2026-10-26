//! Candidate admission is control-path work; decisions retain the previous Arc.
use super::*;

impl PolicySnapshotStore {
    pub(super) fn push_locked(&self, request: PolicySnapshotPushV1) -> Result<Vec<u8>, String> {
        self.push_locked_with_admission(request, policy_store_command_packs::admit)
    }

    pub(super) fn push_locked_with_admission(
        &self,
        mut request: PolicySnapshotPushV1,
        admit: impl FnOnce(PolicySnapshotV3, &Path) -> Result<AdmittedPolicySnapshot, String>,
    ) -> Result<Vec<u8>, String> {
        let direct_lane = request.direct_lane.take();
        let _command_lease = self.command_authority_lease(&request.snapshot)?;
        let snapshot_bytes = snapshot_bytes(&request.snapshot).map_err(snapshot_error)?;
        let now = now_ms()?;
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if state.invalid_on_startup && state.generation_floor == 0 {
            return Err("native_policy_snapshot_invalid".to_owned());
        }
        // Validate the candidate before considering authenticated floor recovery.
        let minimum_generation = if state.snapshot.is_none()
            && state.policy_digest.is_some()
            && request.snapshot.generation <= state.generation_floor
        {
            1
        } else {
            state.generation_floor.max(1)
        };
        validate_v3(
            &request.snapshot,
            minimum_generation,
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now,
        )
        .map_err(snapshot_error)?;
        if request.snapshot.scope_contract.scope_digest != self.expected_scope_digest {
            return Err("native_policy_snapshot_scope_mismatch".to_owned());
        }
        if let Some(current) = state.snapshot.as_ref() {
            if request.snapshot.generation < current.generation {
                return Err("native_policy_snapshot_generation_downgrade".to_owned());
            }
            if request.snapshot.generation == current.generation {
                if snapshot_bytes != state.canonical_bytes {
                    return Err("native_policy_snapshot_generation_reused".to_owned());
                }
                // An idempotent push refreshes what the same snapshot is
                // bound to, so the publisher can reopen the lane after a
                // benign input change without allocating a generation.
                self.bind_direct_lane(current.generation, &current.policy_digest, direct_lane);
                return encode_ack(current.as_ref(), true, self.resident_generation);
            }
        } else if request.snapshot.generation <= state.generation_floor {
            // There is no current snapshot to compare for normal idempotent
            // retry.  The authenticated floor is still authoritative, so
            // equal/older input must force the publisher to allocate a new
            // generation rather than silently reusing the floor.
            return encode_requires_new_generation(&state, self.resident_generation);
        }
        let control_floor = policy_store_command_floor::next_floor(
            state.command_control_floor.as_ref(),
            &request.snapshot,
        )?;
        let business_floor = policy_store_business_floor::next_floor(
            state.business_policy_floor.as_deref(),
            &request.snapshot,
        )?;
        let expected_generation = state.generation_floor;
        let expected_digest = state.policy_digest.clone();
        let expected_snapshot = state.snapshot.clone();
        let expected_invalid = state.invalid_on_startup;
        let expected_control_floor = state.command_control_floor.clone();
        let expected_business_floor = state.business_policy_floor.clone();
        drop(state);
        // File reads, JSON admission and collection construction must not hold
        // the mutex used by concurrent decisions on the previous snapshot.
        let admitted = Arc::new(admit(request.snapshot, &self.state_base)?);
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        let same_snapshot = match (&state.snapshot, &expected_snapshot) {
            (Some(current), Some(previous)) => Arc::ptr_eq(current, previous),
            (None, None) => true,
            _ => false,
        };
        if !same_snapshot
            || state.generation_floor != expected_generation
            || state.policy_digest != expected_digest
            || state.invalid_on_startup != expected_invalid
            || state.command_control_floor != expected_control_floor
            || state.business_policy_floor != expected_business_floor
        {
            return Err("native_policy_snapshot_admission_obsolete".to_owned());
        }
        validate_v3(
            admitted.snapshot(),
            minimum_generation,
            &self.expected_runtime_identity,
            &self.expected_rule_digest,
            &self.verifier_key,
            now_ms()?,
        )
        .map_err(snapshot_error)?;
        let mut observed = match self.authority_observed.lock() {
            Ok(observed) => observed,
            Err(_) => {
                self.authority_changed.store(true, Ordering::SeqCst);
                return Err("native_policy_snapshot_context_mismatch".to_owned());
            }
        };
        // The watcher samples the authority while holding this same lock. Keep
        // it across the atomic replacement and expected-fingerprint publication
        // so a legitimate push never presents a new file with an old expected
        // identity to the watcher.
        persist_authority_with_control_floor(
            &self.authority_path,
            admitted.generation,
            &admitted.policy_digest,
            Some(admitted.snapshot()),
            &self.verifier_key,
            control_floor.as_ref(),
            business_floor.as_deref(),
        )?;
        state.generation_floor = admitted.generation;
        state.policy_digest = Some(admitted.policy_digest.clone());
        state.snapshot = Some(Arc::clone(&admitted));
        state.verified = None;
        state.canonical_bytes = snapshot_bytes;
        state.invalid_on_startup = false;
        state.command_control_floor = control_floor;
        state.business_policy_floor = business_floor;
        self.bind_direct_lane(admitted.generation, &admitted.policy_digest, direct_lane);
        *observed = authority_fingerprint(&self.authority_path);
        drop(observed);
        self.authority_changed.store(
            !policy_store_authority::authorities_unchanged(self),
            Ordering::SeqCst,
        );
        encode_ack(admitted.snapshot(), false, self.resident_generation)
    }
}
