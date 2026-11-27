//! One-use proofs for the protected provider integration routes (PRD 6.9, BP-T130).
//!
//! A preview issues a random challenge bound to the provider, the action and a digest of the exact
//! body it showed. The matching apply spends it once. Only the SHA-256 of a challenge is kept, so a
//! lookup never compares the secret itself.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// How long a preview's challenge may be spent.
pub const PROOF_TTL_MS: u64 = 120_000;
/// Most challenges outstanding at once. The oldest is dropped first.
pub const MAX_PENDING_PROOFS: usize = 64;

/// What a challenge authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAction {
    Connect,
    Settings,
    Disconnect,
}

#[derive(Debug, Clone)]
struct PendingProof {
    provider_id: String,
    action: ProofAction,
    body_digest: [u8; 32],
    expires_at_ms: u64,
}

/// The challenges outstanding.
#[derive(Debug, Default)]
pub struct ProofLedger {
    pending: BTreeMap<[u8; 32], PendingProof>,
}

impl ProofLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// A fresh challenge for `action` on `provider_id`, bound to `body_digest`. `None` only when
    /// the system has no randomness.
    pub fn issue(
        &mut self,
        provider_id: &str,
        action: ProofAction,
        body_digest: [u8; 32],
        now_ms: u64,
    ) -> Option<(String, u64)> {
        self.pending.retain(|_, proof| proof.expires_at_ms > now_ms);
        while self.pending.len() >= MAX_PENDING_PROOFS {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, proof)| proof.expires_at_ms)
                .map(|(key, _)| *key)?;
            self.pending.remove(&oldest);
        }
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).ok()?;
        let challenge = hex::encode(bytes);
        let expires_at_ms = now_ms.saturating_add(PROOF_TTL_MS);
        self.pending.insert(
            Sha256::digest(challenge.as_bytes()).into(),
            PendingProof {
                provider_id: provider_id.to_owned(),
                action,
                body_digest,
                expires_at_ms,
            },
        );
        Some((challenge, expires_at_ms))
    }

    /// Spends `proof`. True only when it was issued for exactly this provider, action and body and
    /// has not expired. A proof that matched a pending entry is spent either way.
    /// Drops a presented proof without honouring it.
    pub fn discard(&mut self, proof: &str) {
        let key: [u8; 32] = Sha256::digest(proof.as_bytes()).into();
        self.pending.remove(&key);
    }

    pub fn spend(
        &mut self,
        proof: &str,
        provider_id: &str,
        action: ProofAction,
        body_digest: [u8; 32],
        now_ms: u64,
    ) -> bool {
        let key: [u8; 32] = Sha256::digest(proof.as_bytes()).into();
        let Some(pending) = self.pending.remove(&key) else {
            return false;
        };
        pending.provider_id == provider_id
            && pending.action == action
            && pending.body_digest == body_digest
            && now_ms < pending.expires_at_ms
    }
}
