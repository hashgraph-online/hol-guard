//! In-memory assertion binding retained between V4 validation and consume.

use super::approval_v4_authority::ApprovalV4Authority;
use guard_contracts::NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES;

pub(crate) fn remember_assertion(
    authority: &ApprovalV4Authority,
    nonce_digest: &str,
    assertion_digest: String,
) -> Result<(), String> {
    let mut assertions = authority
        .assertions
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?;
    if assertions.len() >= NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES
        && !assertions.contains_key(nonce_digest)
    {
        return Err("native_approval_replay_full".to_owned());
    }
    assertions.insert(nonce_digest.to_owned(), assertion_digest);
    Ok(())
}

pub(crate) fn assertion_matches(
    authority: &ApprovalV4Authority,
    nonce_digest: &str,
    assertion_digest: &str,
) -> Result<bool, String> {
    Ok(authority
        .assertions
        .lock()
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?
        .get(nonce_digest)
        .is_some_and(|value| value == assertion_digest))
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
