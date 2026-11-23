//! The policy-integrity key `approve` signs a grant with and `consume`
//! verifies it with: the caller's copy, or the one in the home's own vault.

use super::{Request, INVALID};
use crate::command_envelope_op::resident_key;

/// The key and key id a grant is signed or verified with. A missing pair is
/// refused by the envelope code itself, as `local_signing_key_unavailable`.
pub(super) struct SigningKey {
    b64: Option<String>,
    id: Option<String>,
}

impl SigningKey {
    pub(super) fn b64(&self) -> Option<&str> {
        self.b64.as_deref()
    }

    pub(super) fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// The key this request signs or verifies with. With `vault_key` the ledger
/// reads it from `guard_home`'s vault and refuses a request that also names
/// a key or a key id, so a caller cannot mix its own key with the home's.
pub(super) fn signing_key(request: &Request) -> Result<SigningKey, String> {
    if !request.vault_key {
        return Ok(SigningKey {
            b64: request.integrity_key_b64.clone(),
            id: request.integrity_key_id.clone(),
        });
    }
    if request.integrity_key_b64.is_some() || request.integrity_key_id.is_some() {
        return Err(INVALID.to_owned());
    }
    let (b64, id) = resident_key(Some(&request.guard_home));
    Ok(SigningKey { b64, id })
}
