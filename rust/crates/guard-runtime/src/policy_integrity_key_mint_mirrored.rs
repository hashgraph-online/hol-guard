//! The first mint for the Linux store that mirrors the desktop keyring into
//! the encrypted-file vault: `MirroredPolicyIntegritySecretStore`
//! (`store_policy_integrity_backend.py`).
//!
//! It runs under the same mint lock, after the vault is ready, and keeps that
//! store's rules for the signing key:
//!
//! - a key in either copy is the stored key, as `get_secret` returns it;
//! - while the vault carries the fallback-preferred marker Python reads the
//!   vault alone, and its next write restores the keyring from it first, so a
//!   marked store is never minted here;
//! - a new key goes to the keyring and then to the vault. When the keyring
//!   write fails, the vault keeps the key and the marker, as `set_secret`
//!   leaves them, so the vault stays authoritative until the keyring catches up.
//! - a keyring write that timed out may still commit, and one that succeeded
//!   is in the keyring, so a key this mint cannot then confirm in either copy
//!   answers `busy`, never `unavailable`: Python's fallback mint must not write
//!   a second key that the first would replace or contradict. The next mint
//!   reads whatever landed. A write the keyring refused still answers
//!   `unavailable`, so Python's mint, which may unlock the keyring, runs.

use std::path::Path;

use super::{armed, fresh_key, Minted};
use crate::encrypted_secret_store::EncryptedFileSecretStore;

/// `MirroredPolicyIntegritySecretStore._FALLBACK_PREFERENCE_PREFIX`.
const FALLBACK_PREFERENCE_PREFIX: &str = "hol-guard:fallback-preferred:";

/// How a keyring write failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteFailure {
    /// The keyring answered with an error, or the write never started.
    Refused,
    /// The write started and gave no answer before the deadline; it may still
    /// commit.
    Unsettled,
}

/// The keyring copy: any read error is an unreadable keyring.
pub(super) trait Primary {
    fn get(&self, secret_id: &str) -> Result<Option<String>, ()>;
    fn set(&self, secret_id: &str, value: &str) -> Result<(), WriteFailure>;
}

pub(super) fn mint(
    home: &Path,
    key_ref: &str,
    vault: &mut EncryptedFileSecretStore,
    primary: &dyn Primary,
) -> Minted {
    let marker = format!("{FALLBACK_PREFERENCE_PREFIX}{key_ref}");
    if vault.get_secret(&marker).as_deref() == Some("1") {
        return if vault.get_secret(key_ref).is_some() {
            Minted::Present
        } else {
            Minted::Unavailable
        };
    }
    let Ok(primary_key) = primary.get(key_ref) else {
        return Minted::Unavailable;
    };
    if primary_key.is_some() || vault.get_secret(key_ref).is_some() {
        return Minted::Present;
    }
    if armed(home) {
        return Minted::Armed;
    }
    let Some(key) = fresh_key() else {
        return Minted::Unavailable;
    };
    let written = primary.set(key_ref, &key);
    // A key that may be in the keyring, though this mint cannot read it back.
    let unconfirmed = match written {
        Ok(()) | Err(WriteFailure::Unsettled) => Minted::Busy,
        Err(WriteFailure::Refused) => Minted::Unavailable,
    };
    if written.is_ok() {
        vault.delete_secret(&marker);
        // Mirroring is best effort, as in `set_secret`: the keyring holds the key.
        let _ = vault.set_secret(key_ref, &key);
    } else if vault.set_secret(key_ref, &key).is_err() || vault.set_secret(&marker, "1").is_err() {
        return unconfirmed;
    }
    if matches!(primary.get(key_ref), Ok(Some(_))) || vault.get_secret(key_ref).is_some() {
        Minted::Present
    } else {
        unconfirmed
    }
}

/// What a read of the keyring copy of one secret found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Existing {
    /// The session bus gave no Secret Service. That may be a headless host
    /// or a bus that is only down for now, with a keyring copy behind it.
    NoService,
    /// The keyring answered and holds no copy.
    Absent,
    /// The keyring holds a copy, which Python prefers on its next read, with
    /// the control generation it stores when it carries one.
    Present(Option<u64>),
    /// A Secret Service answered but its copy could not be read: locked, or
    /// the exchange failed or ran out of time.
    Unreadable,
}

/// Whether the vault write of a control state may stand. A keyring copy
/// Python would prefer must be brought in step, and a refused update or an
/// unreadable copy refuses the write, since the stale copy would roll the
/// generation back. An update that gave no answer may still commit, so the
/// vault cannot be put back under it: like a missing Secret Service, the
/// vault must first be marked as the preferred copy (`prefer_vault`), after
/// which Python reads the vault alone whatever the keyring ends up holding.
/// A vault that cannot be marked refuses the write too. A keyring copy at a
/// higher generation than `writing` is never replaced: Python would trust the
/// lowered copy on its next read, so the write is refused as for an
/// unreadable copy. An equal generation is brought in step.
pub(super) fn mirror_control_state(
    found: Existing,
    writing: Option<u64>,
    update: impl FnOnce() -> Result<(), WriteFailure>,
    prefer_vault: impl FnOnce() -> bool,
) -> bool {
    match found {
        Existing::Absent => true,
        Existing::NoService => prefer_vault(),
        Existing::Present(Some(stored)) if writing.is_none_or(|writing| stored > writing) => false,
        Existing::Present(_) => match update() {
            Ok(()) => true,
            Err(WriteFailure::Unsettled) => prefer_vault(),
            Err(WriteFailure::Refused) => false,
        },
        Existing::Unreadable => false,
    }
}

/// Whether the vault already carries the fallback-preferred marker for
/// `key_ref`. Python then reads and writes the vault alone, so a control write
/// stands on the vault without consulting the keyring.
pub(super) fn vault_preferred(vault: &EncryptedFileSecretStore, key_ref: &str) -> bool {
    let marker = format!("{FALLBACK_PREFERENCE_PREFIX}{key_ref}");
    vault.get_secret(&marker).as_deref() == Some("1")
}

/// Marks the vault as the copy Python reads for `key_ref` and its control
/// state, as `set_secret` does after a failed keyring write. Python then reads
/// the vault alone, and its next key write restores the keyring from it.
pub(super) fn prefer_vault(vault: &mut EncryptedFileSecretStore, key_ref: &str) -> bool {
    let marker = format!("{FALLBACK_PREFERENCE_PREFIX}{key_ref}");
    vault_preferred(vault, key_ref) || vault.set_secret(&marker, "1").is_ok()
}

#[cfg(test)]
#[path = "policy_integrity_key_mint_mirrored_tests.rs"]
mod tests;
