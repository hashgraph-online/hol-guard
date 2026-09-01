use super::*;
use std::sync::atomic::Ordering;

pub(crate) struct ApprovalPolicyFence<'a> {
    pub(crate) generation: u64,
    pub(crate) policy_digest: &'a str,
    pub(crate) rule_digest: &'a str,
    pub(crate) runtime_identity: &'a str,
}

impl PolicySnapshotStore {
    #[cfg(test)]
    pub(crate) fn test_approval_signing_seed(&self) -> [u8; 32] {
        [17u8; 32]
    }

    #[cfg(test)]
    pub(crate) fn test_authorities_unchanged(&self) -> bool {
        policy_store_authority::authorities_unchanged(self)
    }

    pub(crate) fn approval_binding(&self, purpose_domain: &[u8]) -> Result<String, String> {
        let authority = self
            .approval_authority
            .as_ref()
            .ok_or_else(|| "native_approval_signing_authority_unavailable".to_owned())?;
        if !policy_store_authority::authorities_unchanged(self) {
            return Err("native_approval_signing_authority_replaced".to_owned());
        }
        if purpose_domain == guard_contracts::NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN {
            return Ok(authority.device_binding.clone());
        }
        if purpose_domain == guard_contracts::NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN {
            return Ok(authority.installation_binding.clone());
        }
        Err("native_approval_binding_invalid".to_owned())
    }

    pub(crate) fn approval_signing_key_id(&self) -> Result<String, String> {
        if !policy_store_authority::authorities_unchanged(self) {
            return Err("native_approval_signing_authority_replaced".to_owned());
        }
        self.approval_authority
            .as_ref()
            .map(|authority| authority.key_id.clone())
            .ok_or_else(|| "native_approval_signing_authority_unavailable".to_owned())
    }

    pub(crate) fn read_approval_public_key(&self) -> Result<[u8; 32], String> {
        let authority = self
            .approval_authority
            .as_ref()
            .ok_or_else(|| "native_approval_signing_authority_unavailable".to_owned())?;
        if !policy_store_authority::authorities_unchanged(self) {
            return Err("native_approval_signing_authority_replaced".to_owned());
        }
        Ok(authority.public_key)
    }

    pub(crate) fn approval_resident_epoch(&self) -> &str {
        self.approval_replay_memory.epoch()
    }

    pub(crate) fn register_approval_challenge(
        &self,
        nonce_digest: &str,
        binding: crate::approval::ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        self.approval_replay_memory
            .register_pending(nonce_digest, binding, now)
    }

    pub(crate) fn claim_approval_nonce_fenced<F>(
        &self,
        resident_epoch: &str,
        nonce_digest: &str,
        binding: &crate::approval::ApprovalReplayBinding,
        now: u64,
        expected: &ApprovalPolicyFence<'_>,
        emit: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce() -> Result<Vec<u8>, String>,
    {
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if self.authority_changed.load(Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self)
        {
            return Err("native_approval_policy_context_mismatch".to_owned());
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| "native_policy_snapshot_missing".to_owned())?;
        if state.invalid_on_startup
            || snapshot.generation != expected.generation
            || snapshot.policy_digest != expected.policy_digest
            || snapshot.rule_digest != expected.rule_digest
            || snapshot.runtime_identity != expected.runtime_identity
        {
            return Err("native_approval_policy_context_mismatch".to_owned());
        }
        if snapshot.expires_at_ms <= now {
            return Err("native_approval_receipt_expired".to_owned());
        }
        self.approval_replay_memory
            .claim_and_emit(resident_epoch, nonce_digest, binding, now, emit)
    }

    pub(crate) fn consume_approval_nonce_fenced<F>(
        &self,
        resident_epoch: &str,
        nonce_digest: &str,
        binding: &crate::approval::ApprovalReplayBinding,
        now: u64,
        expected: &ApprovalPolicyFence<'_>,
        emit: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce() -> Result<Vec<u8>, String>,
    {
        let state = self
            .state
            .lock()
            .map_err(|_| "native_policy_snapshot_state_unavailable".to_owned())?;
        if self.authority_changed.load(Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(self)
        {
            return Err("native_approval_policy_context_mismatch".to_owned());
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or_else(|| "native_policy_snapshot_missing".to_owned())?;
        if state.invalid_on_startup
            || snapshot.generation != expected.generation
            || snapshot.policy_digest != expected.policy_digest
            || snapshot.rule_digest != expected.rule_digest
            || snapshot.runtime_identity != expected.runtime_identity
        {
            return Err("native_approval_policy_context_mismatch".to_owned());
        }
        if snapshot.expires_at_ms <= now {
            return Err("native_approval_receipt_expired".to_owned());
        }
        self.approval_replay_memory.consume_and_emit(
            resident_epoch,
            nonce_digest,
            binding,
            now,
            emit,
        )
    }
}
