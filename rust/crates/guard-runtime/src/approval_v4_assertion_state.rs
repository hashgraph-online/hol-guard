//! In-memory assertion binding retained between V4 validation and consume.

use super::approval_v4_authority::ApprovalV4Authority;
use guard_contracts::NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssertionBinding {
    pub(crate) digest: String,
    pub(crate) expires_at_ms: u64,
}

pub(crate) fn remember_assertion(
    authority: &ApprovalV4Authority,
    nonce_digest: &str,
    assertion_digest: String,
    expires_at_ms: u64,
    now: u64,
) -> Result<(), String> {
    if expires_at_ms <= now {
        return Err("native_approval_receipt_expired".to_owned());
    }
    let mut assertions = authority
        .assertions
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?;
    assertions.retain(|_, value| value.expires_at_ms > now);
    if assertions.len() >= NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES
        && !assertions.contains_key(nonce_digest)
    {
        return Err("native_approval_replay_full".to_owned());
    }
    assertions.insert(
        nonce_digest.to_owned(),
        AssertionBinding {
            digest: assertion_digest,
            expires_at_ms,
        },
    );
    Ok(())
}

pub(crate) fn assertion_matches(
    authority: &ApprovalV4Authority,
    nonce_digest: &str,
    assertion_digest: &str,
    now: u64,
) -> Result<bool, String> {
    let mut assertions = authority
        .assertions
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?;
    assertions.retain(|_, value| value.expires_at_ms > now);
    Ok(assertions
        .get(nonce_digest)
        .is_some_and(|value| value.digest == assertion_digest))
}

pub(crate) fn forget_assertion(
    authority: &ApprovalV4Authority,
    nonce_digest: &str,
) -> Result<(), String> {
    authority
        .assertions
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?
        .remove(nonce_digest);
    Ok(())
}
