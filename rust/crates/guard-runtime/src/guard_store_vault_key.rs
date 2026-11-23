//! `vault_key`: a Guard store call that lets the resident read the
//! policy-integrity key from its own home's vault instead of carrying it.
//!
//! A caller whose store keeps the key in the plain encrypted-file vault sends
//! `"vault_key": true` and no key fields. The resident replaces the flag with
//! `integrity_key_b64` and `integrity_key_id` read from the vault, so every
//! method sees the key exactly as if the caller had sent it, and the key never
//! crosses the socket. Only the resident reads a vault, and only its own: a
//! call for another home, or one with no resident home, sees no key, which
//! each method already treats as no signing authority.

use std::path::Path;

use guard_contracts::GuardStoreRequestV1;
use serde_json::Value;

use crate::command_envelope_op::resident_key;
use crate::guard_store_db::{StoreError, StoreResult};

const FLAG: &str = "vault_key";
const KEY: &str = "integrity_key_b64";
const KEY_ID: &str = "integrity_key_id";
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// The request with the vault's key in place of `vault_key`, or `None` when
/// the call did not ask. A flag that is not `true`, or one sent beside a key
/// or key id, is refused: a caller must not mix its own key with the home's.
pub(super) fn resolve(
    request: &GuardStoreRequestV1,
    resident_home: Option<&Path>,
) -> StoreResult<Option<GuardStoreRequestV1>> {
    match request.args.get(FLAG) {
        None => return Ok(None),
        Some(Value::Bool(true)) => {}
        Some(_) => return Err(INVALID),
    }
    if request.args.contains_key(KEY) || request.args.contains_key(KEY_ID) {
        return Err(INVALID);
    }
    let home = Path::new(&request.guard_home);
    let readable = resident_home.is_some_and(|resident| same_home(resident, home));
    let mut resolved = request.clone();
    resolved.args.remove(FLAG);
    if readable {
        if let (Some(key), Some(key_id)) = resident_key(Some(home)) {
            resolved.args.insert(KEY.to_owned(), Value::from(key));
            resolved.args.insert(KEY_ID.to_owned(), Value::from(key_id));
        }
    }
    Ok(Some(resolved))
}

fn same_home(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
#[path = "guard_store_vault_key_tests.rs"]
mod tests;
