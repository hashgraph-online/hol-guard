//! Provider API keys (BP-T120, PRD 6.7).
//!
//! A provider's key lives in the encrypted secret store under `provider:<provider id>:api-key` and
//! nowhere else. The rules this module keeps:
//!
//! - A key is checked against the manifest's `keyFormat` before it is stored, so a pasted URL, a
//!   note or a key for another service is refused at connect rather than sent to the provider.
//! - Every in-memory copy is a [`ProviderKey`], which zeroes its bytes on drop and whose `Debug`
//!   prints no part of the key. Refusals carry a code only.
//! - Disconnect deletes one provider's key; uninstall and "forget this device" delete every
//!   provider key ([`delete_all_provider_keys`]).

use std::fs;
use std::path::Path;

use guard_command::provider_integration_compile::{CompiledProviderAuthV1, ProviderKeyCharsetV1};
use guard_contracts::{provider_id_is_valid, PROVIDER_KEY_MAX_BYTES};
use zeroize::Zeroizing;

use crate::encrypted_secret_store::EncryptedFileSecretStore;
#[cfg(not(test))]
use crate::secret_reference::SecretReference;
#[cfg(not(test))]
use crate::secret_store_platform;

const SECRET_PREFIX: &str = "provider:";
const SECRET_SUFFIX: &str = ":api-key";
/// The secret store's file name for a provider key: `:` becomes `_`, then `.enc`.
const FILE_PREFIX: &str = "provider_provider.";
const FILE_SUFFIX: &str = "_api-key.enc";

/// A provider API key held in memory. Zeroed on drop; never printed.
pub struct ProviderKey(Zeroizing<String>);

impl ProviderKey {
    pub fn new(key: Zeroizing<String>) -> Self {
        Self(key)
    }

    /// The key, for the one place that needs it: the credential header of a provider request.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ProviderKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderKey(redacted)")
    }
}

/// Why a key or provider id was refused. Carries no part of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSecretError {
    ProviderIdInvalid,
    KeyTooShort,
    KeyTooLong,
    KeyCharset,
    /// The secret store could not be written.
    StoreUnavailable,
}

impl ProviderSecretError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderIdInvalid => "provider_id_invalid",
            Self::KeyTooShort => "provider_key_too_short",
            Self::KeyTooLong => "provider_key_too_long",
            Self::KeyCharset => "provider_key_charset",
            Self::StoreUnavailable => "provider_key_store_unavailable",
        }
    }
}

impl std::fmt::Display for ProviderSecretError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProviderSecretError {}

/// `provider:<provider id>:api-key`, or `None` for an id outside the contract.
pub fn provider_secret_id(provider_id: &str) -> Option<String> {
    provider_id_is_valid(provider_id)
        .then(|| format!("{SECRET_PREFIX}{provider_id}{SECRET_SUFFIX}"))
}

#[cfg(not(test))]
fn native_account(provider_id: &str) -> Option<String> {
    let reference =
        SecretReference::parse(&format!("guard-secret://{provider_id}/connection/api-key")).ok()?;
    Some(reference.canonical_digest())
}

fn charset_allows(charset: ProviderKeyCharsetV1, key: &str) -> bool {
    let bytes = key.as_bytes();
    let body_end = match charset {
        ProviderKeyCharsetV1::Base64 | ProviderKeyCharsetV1::Base64url => {
            let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
            if padding > 2 {
                return false;
            }
            bytes.len() - padding
        }
        ProviderKeyCharsetV1::Hex | ProviderKeyCharsetV1::Alphanumeric => bytes.len(),
    };
    bytes[..body_end].iter().all(|byte| match charset {
        ProviderKeyCharsetV1::Base64url => {
            byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_'
        }
        ProviderKeyCharsetV1::Base64 => {
            byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/'
        }
        ProviderKeyCharsetV1::Hex => byte.is_ascii_hexdigit(),
        ProviderKeyCharsetV1::Alphanumeric => byte.is_ascii_alphanumeric(),
    })
}

/// Checks a key against the manifest's `keyFormat` and Guard's own cap.
pub fn check_key_format(
    key: &str,
    auth: &CompiledProviderAuthV1,
) -> Result<(), ProviderSecretError> {
    let length = key.len();
    if length > PROVIDER_KEY_MAX_BYTES || length > auth.key_max_length as usize {
        return Err(ProviderSecretError::KeyTooLong);
    }
    if length < auth.key_min_length as usize {
        return Err(ProviderSecretError::KeyTooShort);
    }
    if !charset_allows(auth.key_charset, key) {
        return Err(ProviderSecretError::KeyCharset);
    }
    Ok(())
}

/// Checks the key format, then stores the key. Nothing is written when a check fails.
pub fn store_provider_key(
    store: &mut EncryptedFileSecretStore,
    provider_id: &str,
    key: &ProviderKey,
    auth: &CompiledProviderAuthV1,
) -> Result<(), ProviderSecretError> {
    let secret_id =
        provider_secret_id(provider_id).ok_or(ProviderSecretError::ProviderIdInvalid)?;
    check_key_format(key.expose(), auth)?;
    store
        .set_secret(&secret_id, key.expose())
        .map_err(|_| ProviderSecretError::StoreUnavailable)
}

/// Production provider-key write. The file-store argument remains in the route API for
/// compatibility, but provider credentials are stored in the native OS secret store.
#[cfg(not(test))]
pub fn store_provider_key_runtime(
    _store: &mut EncryptedFileSecretStore,
    provider_id: &str,
    key: &ProviderKey,
    auth: &CompiledProviderAuthV1,
) -> Result<(), ProviderSecretError> {
    check_key_format(key.expose(), auth)?;
    let account = native_account(provider_id).ok_or(ProviderSecretError::ProviderIdInvalid)?;
    secret_store_platform::write(&account, key.expose())
        .map_err(|_| ProviderSecretError::StoreUnavailable)
}

#[cfg(test)]
pub fn store_provider_key_runtime(
    store: &mut EncryptedFileSecretStore,
    provider_id: &str,
    key: &ProviderKey,
    auth: &CompiledProviderAuthV1,
) -> Result<(), ProviderSecretError> {
    store_provider_key(store, provider_id, key, auth)
}

/// Puts back a key Guard stored earlier, without checking it against the current manifest's
/// `keyFormat`: a rollback must not lose a key because the format changed since it was stored.
pub fn restore_provider_key(
    store: &mut EncryptedFileSecretStore,
    provider_id: &str,
    key: &ProviderKey,
) -> Result<(), ProviderSecretError> {
    let secret_id =
        provider_secret_id(provider_id).ok_or(ProviderSecretError::ProviderIdInvalid)?;
    store
        .set_secret(&secret_id, key.expose())
        .map_err(|_| ProviderSecretError::StoreUnavailable)
}

#[cfg(not(test))]
pub fn restore_provider_key_runtime(
    _store: &mut EncryptedFileSecretStore,
    provider_id: &str,
    key: &ProviderKey,
) -> Result<(), ProviderSecretError> {
    let account = native_account(provider_id).ok_or(ProviderSecretError::ProviderIdInvalid)?;
    secret_store_platform::write(&account, key.expose())
        .map_err(|_| ProviderSecretError::StoreUnavailable)
}

#[cfg(test)]
pub fn restore_provider_key_runtime(
    store: &mut EncryptedFileSecretStore,
    provider_id: &str,
    key: &ProviderKey,
) -> Result<(), ProviderSecretError> {
    restore_provider_key(store, provider_id, key)
}

/// The stored key, or `None` when the provider has none or the id is outside the contract.
pub fn load_provider_key(
    store: &mut EncryptedFileSecretStore,
    provider_id: &str,
) -> Option<ProviderKey> {
    let secret_id = provider_secret_id(provider_id)?;
    store
        .get_secret(&secret_id)
        .map(|key| ProviderKey::new(Zeroizing::new(key)))
}

#[cfg(not(test))]
pub fn load_provider_key_runtime(
    _store: &mut EncryptedFileSecretStore,
    provider_id: &str,
) -> Option<ProviderKey> {
    let account = native_account(provider_id)?;
    secret_store_platform::read(&account)
        .ok()
        .flatten()
        .map(|secret| ProviderKey::new(secret.into_inner()))
}

#[cfg(test)]
pub fn load_provider_key_runtime(
    store: &mut EncryptedFileSecretStore,
    provider_id: &str,
) -> Option<ProviderKey> {
    load_provider_key(store, provider_id)
}

/// Disconnect: deletes one provider's key file. The store's encryption is not set up first, so an
/// unreadable store key never leaves the provider key behind. A key that is already gone is not an
/// error; any other failure to remove the file is returned.
pub fn delete_provider_key(
    store: &EncryptedFileSecretStore,
    provider_id: &str,
) -> std::io::Result<()> {
    let Some(secret_id) = provider_secret_id(provider_id) else {
        return Ok(());
    };
    match fs::remove_file(store.path_for(&secret_id)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

#[cfg(not(test))]
pub fn delete_provider_key_runtime(
    _store: &EncryptedFileSecretStore,
    provider_id: &str,
) -> std::io::Result<()> {
    let Some(account) = native_account(provider_id) else {
        return Ok(());
    };
    secret_store_platform::delete(&account).map_err(std::io::Error::other)
}

#[cfg(test)]
pub fn delete_provider_key_runtime(
    store: &EncryptedFileSecretStore,
    provider_id: &str,
) -> std::io::Result<()> {
    delete_provider_key(store, provider_id)
}

/// Uninstall and "forget this device": deletes every provider key under `guard_home`. Other
/// secrets are left alone. Returns how many keys were deleted.
pub fn delete_all_provider_keys(guard_home: &Path) -> std::io::Result<usize> {
    let directory = guard_home.join("secrets");
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut deleted = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_provider_key = name
            .strip_prefix(FILE_PREFIX)
            .and_then(|rest| rest.strip_suffix(FILE_SUFFIX))
            .is_some_and(|slug| provider_id_is_valid(&format!("provider.{slug}")));
        if is_provider_key && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
#[path = "provider_integration_secret_tests.rs"]
mod tests;
