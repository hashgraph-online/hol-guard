#![forbid(unsafe_code)]

//! Resident-memory replay fencing for native approvals.
//!
//! Approval artifacts are useful only to the resident that issued their
//! challenge.  A fresh random epoch is generated for every resident start;
//! pending, claimed, and consumed nonces never leave that process.  This
//! deliberately avoids same-UID files and secrets for replay state.

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

/// Bounded one-resident replay state.  The epoch is intentionally not
/// persisted; restarting the resident invalidates every prior artifact.
pub(crate) struct ApprovalReplayMemory {
    epoch: String,
    state: Mutex<ReplayState>,
}

/// Privacy-safe identity held beside a live challenge. The resident retains
/// only bounded identifiers/digests, never raw command text or hook payloads.
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

    pub(crate) fn claim(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        let key = nonce_digest_key(epoch, nonce_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_approval_replay_unavailable".to_owned())?;
        let Some(entry) = state.entries.get_mut(&key) else {
            return Err("native_approval_receipt_not_claimed".to_owned());
        };
        if entry.binding.expires_at_ms <= now {
            state.entries.remove(&key);
            return Err("native_approval_receipt_expired".to_owned());
        }
        if &entry.binding != binding {
            return Err("native_approval_binding_mismatch".to_owned());
        }
        match entry.status {
            ReplayStatus::Pending => {
                entry.status = ReplayStatus::Claimed;
                Ok(())
            }
            ReplayStatus::Claimed | ReplayStatus::Consumed => {
                Err("native_approval_replay".to_owned())
            }
        }
    }

    pub(crate) fn consume(
        &self,
        epoch: &str,
        nonce_digest: &str,
        binding: &ApprovalReplayBinding,
        now: u64,
    ) -> Result<(), String> {
        let key = nonce_digest_key(epoch, nonce_digest)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "native_approval_replay_unavailable".to_owned())?;
        let Some(entry) = state.entries.get_mut(&key) else {
            return Err("native_approval_receipt_not_claimed".to_owned());
        };
        if entry.binding.expires_at_ms <= now {
            state.entries.remove(&key);
            return Err("native_approval_receipt_expired".to_owned());
        }
        if &entry.binding != binding {
            return Err("native_approval_binding_mismatch".to_owned());
        }
        match entry.status {
            ReplayStatus::Pending => Err("native_approval_receipt_not_claimed".to_owned()),
            ReplayStatus::Claimed => {
                entry.status = ReplayStatus::Consumed;
                Ok(())
            }
            ReplayStatus::Consumed => Err("native_approval_receipt_consumed".to_owned()),
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
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn binding(expires_at_ms: u64) -> ApprovalReplayBinding {
        ApprovalReplayBinding {
            request_id_digest: "1".repeat(64),
            request_digest: "2".repeat(64),
            action_digest: "3".repeat(64),
            policy_generation: 1,
            policy_digest: "4".repeat(64),
            rule_digest: "5".repeat(64),
            runtime_identity: "6".repeat(64),
            runtime_binary_identity: "6".repeat(64),
            harness: "test".to_owned(),
            workspace_binding: Some("7".repeat(64)),
            device_binding: Some("8".repeat(64)),
            installation_binding: Some("9".repeat(64)),
            publisher_binding: None,
            artifact_binding: None,
            scope_contract_version: "guard-native-scope.v1".to_owned(),
            scope_contract_digest: "8".repeat(64),
            scope_binding: Some("a".repeat(64)),
            expires_at_ms,
        }
    }

    #[test]
    fn restart_epoch_rejects_old_artifact_state() {
        let first = ApprovalReplayMemory::new().unwrap();
        let now = 10;
        let nonce = "a".repeat(64);
        let epoch = first.epoch().to_owned();
        let replay_binding = binding(100);
        first
            .register_pending(&nonce, replay_binding.clone(), now)
            .unwrap();
        let second = ApprovalReplayMemory::new().unwrap();
        assert_ne!(epoch, second.epoch());
        assert_eq!(
            second
                .claim(&epoch, &nonce, &replay_binding, now)
                .unwrap_err(),
            "native_approval_receipt_not_claimed"
        );
    }

    #[test]
    fn expiry_and_double_consume_are_atomic() {
        let memory = Arc::new(ApprovalReplayMemory::new().unwrap());
        let nonce = "b".repeat(64);
        let epoch = memory.epoch().to_owned();
        let expired_binding = binding(20);
        memory
            .register_pending(&nonce, expired_binding.clone(), 10)
            .unwrap();
        assert_eq!(
            memory
                .claim(&epoch, &nonce, &expired_binding, 20)
                .unwrap_err(),
            "native_approval_receipt_expired"
        );

        let nonce = "c".repeat(64);
        let replay_binding = binding(100);
        memory
            .register_pending(&nonce, replay_binding.clone(), 10)
            .unwrap();
        memory.claim(&epoch, &nonce, &replay_binding, 10).unwrap();
        let first = Arc::clone(&memory);
        let second = Arc::clone(&memory);
        let first_epoch = epoch.clone();
        let second_epoch = epoch.clone();
        let first_nonce = nonce.clone();
        let second_nonce = nonce.clone();
        let first_binding = replay_binding.clone();
        let second_binding = replay_binding;
        let first_thread =
            thread::spawn(move || first.consume(&first_epoch, &first_nonce, &first_binding, 10));
        let second_thread = thread::spawn(move || {
            second.consume(&second_epoch, &second_nonce, &second_binding, 10)
        });
        let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(outcome, Err(error) if error == "native_approval_receipt_consumed")
                })
                .count(),
            1
        );
    }

    #[test]
    fn capacity_is_bounded_without_eviction() {
        let memory = ApprovalReplayMemory::new().unwrap();
        let replay_binding = binding(100);
        for index in 0..NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES {
            memory
                .register_pending(&format!("{index:064x}"), replay_binding.clone(), 10)
                .unwrap();
        }
        assert_eq!(memory.len(), NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES);
        assert_eq!(
            memory
                .register_pending(&"f".repeat(64), replay_binding, 10)
                .unwrap_err(),
            "native_approval_replay_full"
        );
    }

    #[test]
    fn full_binding_mutation_is_rejected_before_state_transition() {
        let memory = ApprovalReplayMemory::new().unwrap();
        let nonce = "d".repeat(64);
        let epoch = memory.epoch().to_owned();
        let original = binding(100);
        memory
            .register_pending(&nonce, original.clone(), 10)
            .unwrap();
        let mut altered = original.clone();
        altered.scope_binding = Some("b".repeat(64));
        assert_eq!(
            memory.claim(&epoch, &nonce, &altered, 10).unwrap_err(),
            "native_approval_binding_mismatch"
        );
        memory.claim(&epoch, &nonce, &original, 10).unwrap();
    }
}
