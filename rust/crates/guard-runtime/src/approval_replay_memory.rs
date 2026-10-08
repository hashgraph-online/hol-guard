#![forbid(unsafe_code)]

//! Resident-memory replay fencing for native approvals; replay state never
//! leaves the resident process.

use guard_contracts::{
    NATIVE_APPROVAL_MAX_STRING_BYTES, NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES,
};
use std::collections::HashMap;
use std::sync::Mutex;

const HEX_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayStatus {
    Pending,
    Claimed,
    Consumed,
}

#[derive(Debug, Clone, Copy)]
enum ReplayTransition {
    Claim,
    Consume,
}

#[derive(Debug, Clone)]
struct ReplayEntry {
    binding: ApprovalReplayBinding,
    status: ReplayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayKey {
    epoch: String,
    nonce_digest: String,
}

#[derive(Default)]
struct ReplayState {
    entries: HashMap<ReplayKey, ReplayEntry>,
}

/// Bounded resident replay state; only native-owned durable V4 proof can restore a claim.
pub(crate) struct ApprovalReplayMemory {
    epoch: String,
    state: Mutex<ReplayState>,
}

/// Privacy-safe identity beside a live challenge; no raw command or payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalReplayBinding {
    pub(crate) request_id_digest: String,
    pub(crate) request_digest: String,
    pub(crate) action_digest: String,
    pub(crate) policy_generation: u64,
    pub(crate) policy_digest: String,
    pub(crate) rule_digest: String,
    pub(crate) runtime_identity: String,
    pub(crate) runtime_binary_identity: String,
    pub(crate) harness: String,
    pub(crate) workspace_binding: Option<String>,
    pub(crate) device_binding: Option<String>,
    pub(crate) installation_binding: Option<String>,
    pub(crate) publisher_binding: Option<String>,
    pub(crate) artifact_binding: Option<String>,
    pub(crate) scope_contract_version: String,
    pub(crate) scope_contract_digest: String,
    pub(crate) scope_binding: Option<String>,
    pub(crate) expires_at_ms: u64,
}

impl ApprovalReplayBinding {
    fn is_bounded_and_well_formed(&self, now: u64) -> bool {
        self.expires_at_ms > now
            && self.policy_generation > 0
            && self.harness.len() <= NATIVE_APPROVAL_MAX_STRING_BYTES
            && !self.harness.trim().is_empty()
            && [
                self.request_id_digest.as_str(),
                self.request_digest.as_str(),
                self.action_digest.as_str(),
                self.policy_digest.as_str(),
                self.rule_digest.as_str(),
                self.runtime_identity.as_str(),
                self.scope_contract_digest.as_str(),
            ]
            .iter()
            .all(|value| valid_hex(value))
            && is_bounded_hex_option(&self.workspace_binding)
            && is_bounded_hex_option(&self.device_binding)
            && is_bounded_hex_option(&self.installation_binding)
            && is_bounded_hex_option(&self.publisher_binding)
            && is_bounded_hex_option(&self.artifact_binding)
            && is_bounded_hex_option(&self.scope_binding)
            && is_bounded_text(&self.runtime_binary_identity)
            && is_bounded_text(&self.scope_contract_version)
    }
}

fn is_bounded_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= NATIVE_APPROVAL_MAX_STRING_BYTES
}

fn is_bounded_hex_option(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|value| valid_hex(value))
}

fn valid_hex(value: &str) -> bool {
    value.len() == HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_epoch() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "native_approval_random_failed".to_owned())?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("native_approval_random_failed".to_owned());
    }
    Ok(hex::encode(bytes))
}

fn nonce_digest_key(epoch: &str, nonce_digest: &str) -> Result<ReplayKey, String> {
    if !valid_hex(epoch) || !valid_hex(nonce_digest) {
        return Err("native_approval_receipt_invalid".to_owned());
    }
    Ok(ReplayKey {
        epoch: epoch.to_owned(),
        nonce_digest: nonce_digest.to_owned(),
    })
}

impl ApprovalReplayMemory {
    pub(crate) fn new() -> Result<Self, String> {
        Ok(Self {
            epoch: random_epoch()?,
            state: Mutex::new(ReplayState::default()),
        })
    }

    pub(crate) fn epoch(&self) -> &str {
        &self.epoch
    }

    pub(crate) fn register_pending(
        &self,
        nonce_digest: &str,
        binding: ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        if binding.expires_at_ms <= now {
            return Err("native_approval_time_invalid".to_owned());
        }
        if !binding.is_bounded_and_well_formed(now) {
            return Err("native_approval_binding_invalid".to_owned());
        }
        let key = nonce_digest_key(&self.epoch, nonce_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_approval_replay_unavailable".to_owned())?;
        state
            .entries
            .retain(|_, entry| entry.binding.expires_at_ms > now);
        if state.entries.len() >= NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES {
            return Err("native_approval_replay_full".to_owned());
        }
        if state.entries.contains_key(&key) {
            return Err("native_approval_replay".to_owned());
        }
        state.entries.insert(
            key,
            ReplayEntry {
                binding,
                status: ReplayStatus::Pending,
            },
        );
        Ok(())
    }

    pub(crate) fn restore_claimed(
        &self,
        durable: &crate::policy_store::native_cloud_review_v4::DurableInstalledApproval,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        if binding.expires_at_ms <= now {
            return Err("native_approval_receipt_expired".to_owned());
        }
        let key = nonce_digest_key(durable.resident_epoch(), nonce_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_approval_replay_unavailable".to_owned())?;
        state
            .entries
            .retain(|_, entry| entry.binding.expires_at_ms > now);
        if let Some(entry) = state.entries.get_mut(&key) {
            if entry.binding != *binding {
                return Err("native_approval_receipt_binding_mismatch".to_owned());
            }
            if entry.status == ReplayStatus::Consumed {
                return Err("native_approval_receipt_consumed".to_owned());
            }
            entry.status = ReplayStatus::Claimed;
            return Ok(());
        }
        if state.entries.len() >= NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES {
            return Err("native_approval_replay_full".to_owned());
        }
        state.entries.insert(
            key,
            ReplayEntry {
                binding: binding.clone(),
                status: ReplayStatus::Claimed,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn claim(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        self.transition_and_emit(
            epoch,
            nonce_digest,
            binding,
            now,
            ReplayTransition::Claim,
            || Ok(Vec::new()),
        )
        .map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn consume(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        self.transition_and_emit(
            epoch,
            nonce_digest,
            binding,
            now,
            ReplayTransition::Consume,
            || Ok(Vec::new()),
        )
        .map(|_| ())
    }

    pub(crate) fn claim_and_emit<F>(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
        emit: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce() -> Result<Vec<u8>, String>,
    {
        self.transition_and_emit(
            epoch,
            nonce_digest,
            binding,
            now,
            ReplayTransition::Claim,
            emit,
        )
    }

    pub(crate) fn consume_and_emit<F>(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
        emit: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce() -> Result<Vec<u8>, String>,
    {
        self.transition_and_emit(
            epoch,
            nonce_digest,
            binding,
            now,
            ReplayTransition::Consume,
            emit,
        )
    }

    fn transition_and_emit<F>(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
        transition: ReplayTransition,
        emit: F,
    ) -> Result<Vec<u8>, String>
    where
        F: FnOnce() -> Result<Vec<u8>, String>,
    {
        let key = nonce_digest_key(epoch, nonce_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_approval_replay_unavailable".to_owned())?;
        // Prune on every transition, preserving the target-specific expiry error.
        let target_expired = state
            .entries
            .get(&key)
            .is_some_and(|entry| entry.binding.expires_at_ms <= now);
        state
            .entries
            .retain(|_, entry| entry.binding.expires_at_ms > now);
        if target_expired {
            return Err("native_approval_receipt_expired".to_owned());
        }
        let Some(entry) = state.entries.get_mut(&key) else {
            return Err("native_approval_receipt_not_claimed".to_owned());
        };
        if &entry.binding != binding {
            return Err("native_approval_binding_mismatch".to_owned());
        }
        let previous_status = entry.status;
        match (transition, previous_status) {
            (ReplayTransition::Claim, ReplayStatus::Pending) => {
                entry.status = ReplayStatus::Claimed
            }
            (ReplayTransition::Claim, ReplayStatus::Claimed | ReplayStatus::Consumed) => {
                return Err("native_approval_replay".to_owned());
            }
            (ReplayTransition::Consume, ReplayStatus::Pending) => {
                return Err("native_approval_receipt_not_claimed".to_owned());
            }
            (ReplayTransition::Consume, ReplayStatus::Claimed) => {
                entry.status = ReplayStatus::Consumed
            }
            (ReplayTransition::Consume, ReplayStatus::Consumed) => {
                return Err("native_approval_receipt_consumed".to_owned());
            }
        }

        // Keep the lock while emitting so a failed emission can roll back atomically.
        match emit() {
            Ok(value) => Ok(value),
            Err(error) => {
                if let Some(entry) = state.entries.get_mut(&key) {
                    entry.status = previous_status;
                }
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "approval_replay_memory_tests.rs"]
mod tests;
