#![forbid(unsafe_code)]

//! Purpose-scoped secure state for the V4 WebAuthn credential and counter.
//!
//! This account is intentionally separate from the V3 enrollment metadata.
//! Tests use an owner-private fixture; production always uses the platform
//! secure store and never falls back to the state directory.

use std::path::Path;

#[cfg(not(test))]
use super::approval_enrollment::{read_platform_secret_for_v4, write_platform_secret_for_v4};

const MAX_SECRET_TEXT_BYTES: usize = 16 * 1024;
#[cfg(test)]
const V4_SECURE_STATE_FILE_NAME: &str = "approval-webauthn-v4-state.test.json";
#[cfg(not(test))]
const V4_SECURE_STATE_ACCOUNT_SUFFIX: &str = ":webauthn-v4";

/// Load the V4 counter record from its purpose-scoped secure account.
pub(super) fn load(state_base: &Path) -> Result<Option<String>, String> {
    #[cfg(test)]
    {
        let path = state_base.join(V4_SECURE_STATE_FILE_NAME);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("native_approval_v4_secure_state_unavailable".to_owned()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("native_approval_v4_secure_state_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("native_approval_v4_secure_state_invalid".to_owned());
            }
        }
        let value = std::fs::read_to_string(path)
            .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?;
        if value.len() > MAX_SECRET_TEXT_BYTES {
            return Err("native_approval_v4_secure_state_invalid".to_owned());
        }
        Ok(Some(value))
    }
    #[cfg(not(test))]
    {
        let account = format!(
            "{}{}",
            super::approval_enrollment::account_for_state_base(state_base)?,
            V4_SECURE_STATE_ACCOUNT_SUFFIX
        );
        read_platform_secret_for_v4(&account).map_err(map_platform_error)
    }
}

/// Store the V4 counter record. The caller supplies only canonical,
/// provenance-bound JSON assembled by Rust.
pub(super) fn store(state_base: &Path, value: &str) -> Result<(), String> {
    if value.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_approval_v4_secure_state_invalid".to_owned());
    }
    #[cfg(test)]
    {
        let path = state_base.join(V4_SECURE_STATE_FILE_NAME);
        super::policy_store_persistence::persist_private_bytes(
            &path,
            value.as_bytes(),
            MAX_SECRET_TEXT_BYTES as u64,
            "v4_secure_state",
        )
        .map_err(|_| "native_approval_v4_secure_state_unavailable".to_owned())?;
        Ok(())
    }
    #[cfg(not(test))]
    {
        let account = format!(
            "{}{}",
            super::approval_enrollment::account_for_state_base(state_base)?,
            V4_SECURE_STATE_ACCOUNT_SUFFIX
        );
        write_platform_secret_for_v4(&account, value).map_err(map_platform_error)
    }
}

#[cfg(not(test))]
fn map_platform_error(error: String) -> String {
    match error.as_str() {
        "native_approval_secure_state_invalid" => {
            "native_approval_v4_secure_state_invalid".to_owned()
        }
        "native_approval_secure_state_unavailable" => {
            "native_approval_v4_secure_state_unavailable".to_owned()
        }
        _ => error,
    }
}
