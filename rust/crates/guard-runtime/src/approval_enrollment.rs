#![forbid(unsafe_code)]

//! OS-protected enrollment state for the external approval authority.
//! This module stores enrollment provenance and per-install/device bindings only; it contains no replay secret.
//! Request replay state lives in the resident process and is invalidated by its random epoch.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::Path;

#[path = "approval_enrollment_platform.rs"]
mod platform;
#[path = "approval_enrollment_state.rs"]
mod state;
use platform::{read_platform_secret, write_platform_secret};
use state::encode_state;
pub(super) use state::load_unlocked;
#[cfg(test)]
pub(super) use state::write_test_enrollment_bindings;
pub(crate) use state::SecureApprovalState;

#[cfg(not(test))]
pub(super) fn read_platform_secret_for_v4(account: &str) -> Result<Option<String>, String> {
    read_platform_secret(account)
}

#[cfg(not(test))]
pub(super) fn write_platform_secret_for_v4(account: &str, value: &str) -> Result<(), String> {
    write_platform_secret(account, value)
}

const STATE_VERSION: u16 = 4;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE_NAME: &str = "org.hashgraphonline.hol-guard.native-approval-enrollment.v1";
const ACCOUNT_DOMAIN: &[u8] = b"hol-guard-native-approval-enrollment-account-v1\0";
const DEVICE_ACCOUNT_DOMAIN: &[u8] = b"hol-guard-native-approval-device-v1\0";
const DEVICE_BINDING_DOMAIN: &[u8] = b"hol-guard-native-approval-device-binding-v1\0";
const INSTALLATION_BINDING_DOMAIN: &[u8] = b"hol-guard-native-approval-installation-binding-v1\0";
const MAX_SECRET_TEXT_BYTES: usize = 16 * 1024;
const TRANSITION_LOCK_FILE_NAME: &str = "approval-authority-transition.v1.lock";

/// Owner-private inter-process fence for enrollment and authority changes.
/// The inode is retained; the OS lock, not a writable PID/same-UID marker, supplies ownership.
pub(crate) struct TransitionLock {
    _file: File,
    #[cfg(unix)]
    _directory: crate::state_directory_lock::DirectoryLock,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

struct OpenedTransitionLock {
    file: File,
    #[cfg(windows)]
    directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

fn transition_lock_path(state_base: &Path) -> Result<std::path::PathBuf, String> {
    super::validate_private_directory(state_base)?;
    Ok(state_base.join(TRANSITION_LOCK_FILE_NAME))
}

fn validate_transition_lock(path: &Path, file: &File) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|_| "native_approval_authority_lock_invalid".to_owned())?;
    if !opened.is_file() {
        return Err("native_approval_authority_lock_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path_metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "native_approval_authority_lock_invalid".to_owned())?;
        let parent_uid = path
            .parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .map(|metadata| metadata.uid());
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || opened.dev() != path_metadata.dev()
            || opened.ino() != path_metadata.ino()
            || opened.nlink() != 1
            || parent_uid != Some(opened.uid())
            || opened.permissions().mode() & 0o077 != 0
        {
            return Err("native_approval_authority_lock_not_private".to_owned());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if opened.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("native_approval_authority_lock_invalid".to_owned());
        }
        let private_root = path
            .parent()
            .ok_or_else(|| "native_approval_authority_lock_invalid".to_owned())
            .and_then(crate::resident_state::private_root_for_state_base)?;
        crate::resident_state::verify_windows_private_path(path, false, &private_root)?;
    }
    Ok(())
}

#[cfg(unix)]
fn open_transition_lock(
    path: &Path,
    directory: &crate::state_directory_lock::DirectoryLock,
) -> Result<OpenedTransitionLock, String> {
    let _ = path;
    let file = directory
        .open_child_file(TRANSITION_LOCK_FILE_NAME)
        .map_err(|error| match error {
            crate::state_directory_lock::DirectoryLockError::Busy => {
                "native_approval_authority_busy".to_owned()
            }
            crate::state_directory_lock::DirectoryLockError::Invalid
            | crate::state_directory_lock::DirectoryLockError::NotPrivate
            | crate::state_directory_lock::DirectoryLockError::PathReplaced => {
                "native_approval_authority_directory_lock_invalid".to_owned()
            }
            crate::state_directory_lock::DirectoryLockError::Open
            | crate::state_directory_lock::DirectoryLockError::Failed => {
                "native_approval_authority_directory_lock_failed".to_owned()
            }
        })?;
    Ok(OpenedTransitionLock { file })
}

#[cfg(not(unix))]
fn open_transition_lock(path: &Path) -> Result<OpenedTransitionLock, String> {
    let private_root = path
        .parent()
        .ok_or_else(|| "native_approval_authority_lock_invalid".to_owned())
        .and_then(crate::resident_state::private_root_for_state_base)?;
    #[cfg(windows)]
    let (file, directory_binding) = crate::resident_state::private_lock_file(path, &private_root)?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(path, &private_root)?;
    Ok(OpenedTransitionLock {
        file,
        #[cfg(windows)]
        directory_binding,
    })
}

pub(crate) fn with_transition_lock<T, F>(state_base: &Path, operation: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let path = transition_lock_path(state_base)?;
    #[cfg(unix)]
    let directory =
        crate::state_directory_lock::acquire(state_base).map_err(|error| match error {
            crate::state_directory_lock::DirectoryLockError::Busy => {
                "native_approval_authority_busy".to_owned()
            }
            crate::state_directory_lock::DirectoryLockError::Open
            | crate::state_directory_lock::DirectoryLockError::Failed => {
                "native_approval_authority_directory_lock_failed".to_owned()
            }
            crate::state_directory_lock::DirectoryLockError::Invalid
            | crate::state_directory_lock::DirectoryLockError::NotPrivate
            | crate::state_directory_lock::DirectoryLockError::PathReplaced => {
                "native_approval_authority_directory_lock_invalid".to_owned()
            }
        })?;
    #[cfg(unix)]
    let _directory_transition = directory.try_transition().map_err(|error| match error {
        crate::state_directory_lock::DirectoryLockError::Busy => {
            "native_approval_authority_busy".to_owned()
        }
        crate::state_directory_lock::DirectoryLockError::PathReplaced
        | crate::state_directory_lock::DirectoryLockError::Invalid
        | crate::state_directory_lock::DirectoryLockError::NotPrivate => {
            "native_approval_authority_directory_lock_invalid".to_owned()
        }
        crate::state_directory_lock::DirectoryLockError::Open
        | crate::state_directory_lock::DirectoryLockError::Failed => {
            "native_approval_authority_directory_lock_failed".to_owned()
        }
    })?;
    #[cfg(unix)]
    let opened = open_transition_lock(&path, &directory)?;
    #[cfg(not(unix))]
    let opened = open_transition_lock(&path)?;
    validate_transition_lock(&path, &opened.file)?;
    fs2::FileExt::try_lock_exclusive(&opened.file).map_err(|error| {
        if crate::resident_state::is_lock_contention(&error) {
            "native_approval_authority_busy".to_owned()
        } else {
            "native_approval_authority_lock_failed".to_owned()
        }
    })?;
    #[cfg(unix)]
    directory.revalidate().map_err(|error| match error {
        crate::state_directory_lock::DirectoryLockError::PathReplaced
        | crate::state_directory_lock::DirectoryLockError::Invalid
        | crate::state_directory_lock::DirectoryLockError::NotPrivate => {
            "native_approval_authority_directory_lock_invalid".to_owned()
        }
        crate::state_directory_lock::DirectoryLockError::Open
        | crate::state_directory_lock::DirectoryLockError::Failed => {
            "native_approval_authority_directory_lock_failed".to_owned()
        }
        crate::state_directory_lock::DirectoryLockError::Busy => {
            "native_approval_authority_busy".to_owned()
        }
    })?;
    let _lock = TransitionLock {
        _file: opened.file,
        #[cfg(unix)]
        _directory: directory.clone(),
        #[cfg(windows)]
        _directory_binding: opened.directory_binding,
    };
    operation()
}

pub(super) fn account_for_state_base(state_base: &Path) -> Result<String, String> {
    super::validate_private_directory(state_base)?;
    let canonical = std::fs::canonicalize(state_base)
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    super::validate_private_directory(&canonical)?;
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_DOMAIN);
    hasher.update(canonical.as_os_str().as_encoded_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn account_for_device() -> String {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_ACCOUNT_DOMAIN);
    hex::encode(hasher.finalize())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn binding_for_secret(domain: &[u8], secret: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

fn random_secret() -> Result<[u8; 32], String> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| "native_approval_random_failed".to_owned())?;
    if secret.iter().all(|byte| *byte == 0) {
        return Err("native_approval_random_failed".to_owned());
    }
    Ok(secret)
}

fn load_or_create_device_binding() -> Result<String, String> {
    let account = account_for_device();
    let secret = match read_platform_secret(&account)? {
        Some(encoded) => {
            let bytes = hex::decode(encoded.trim())
                .map_err(|_| "native_approval_device_identity_invalid".to_owned())?;
            bytes
                .try_into()
                .map_err(|_| "native_approval_device_identity_invalid".to_owned())?
        }
        None => {
            let secret = random_secret()?;
            write_platform_secret(&account, &hex::encode(secret))?;
            secret
        }
    };
    Ok(binding_for_secret(DEVICE_BINDING_DOMAIN, &secret))
}

/// Begin an enrollment ceremony; public bindings leave the random identities outside Python and the state directory.
pub(crate) fn prepare_enrollment(state_base: &Path) -> Result<(String, String), String> {
    with_transition_lock(state_base, || prepare_enrollment_unlocked(state_base))
}

pub(super) fn prepare_enrollment_unlocked(state_base: &Path) -> Result<(String, String), String> {
    if let Some(existing) = load_unlocked(state_base)? {
        if existing.pending {
            return Ok((existing.device_binding, existing.installation_binding));
        }
        return Err("native_approval_authority_already_enrolled".to_owned());
    }
    let device_binding = load_or_create_device_binding()?;
    let installation_secret = random_secret()?;
    let installation_binding =
        binding_for_secret(INSTALLATION_BINDING_DOMAIN, &installation_secret);
    let state = SecureApprovalState {
        generation: 0,
        device_binding: device_binding.clone(),
        installation_binding: installation_binding.clone(),
        key_id: String::new(),
        status: "pending".to_owned(),
        pending: true,
        pending_record_digest: String::new(),
    };
    let encoded = encode_state(&state)?;
    write_platform_secret(&account_for_state_base(state_base)?, &encoded)?;
    Ok((device_binding, installation_binding))
}

pub(super) fn begin_transition_unlocked(
    state_base: &Path,
    record_digest: &str,
    generation: u64,
    key_id: &str,
    status: &str,
    device_binding: &str,
    installation_binding: &str,
) -> Result<SecureApprovalState, String> {
    if generation == 0
        || !valid_digest(record_digest)
        || !valid_digest(key_id)
        || !matches!(status, "active" | "revoked")
        || !valid_digest(device_binding)
        || !valid_digest(installation_binding)
        || device_binding == installation_binding
    {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let existing = load_unlocked(state_base)?
        .ok_or_else(|| "native_approval_enrollment_required".to_owned())?;
    if existing.pending
        && existing.generation == generation
        && existing.key_id == key_id
        && existing.status == status
        && existing.device_binding == device_binding
        && existing.installation_binding == installation_binding
        && existing.pending_record_digest == record_digest
    {
        return Ok(existing);
    }
    if (existing.generation > 0 && generation <= existing.generation)
        || existing.device_binding != device_binding
        || existing.installation_binding != installation_binding
    {
        return Err("native_approval_authority_generation_rollback".to_owned());
    }
    let state = SecureApprovalState {
        generation,
        device_binding: device_binding.to_owned(),
        installation_binding: installation_binding.to_owned(),
        key_id: key_id.to_owned(),
        status: status.to_owned(),
        pending: true,
        pending_record_digest: record_digest.to_owned(),
    };
    let encoded = encode_state(&state)?;
    if encoded.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    write_platform_secret(&account_for_state_base(state_base)?, &encoded)?;
    Ok(state)
}

pub(super) fn complete_transition_unlocked(
    state_base: &Path,
    record_digest: &str,
    generation: u64,
    key_id: &str,
    status: &str,
    device_binding: &str,
    installation_binding: &str,
) -> Result<SecureApprovalState, String> {
    if !valid_digest(record_digest) {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let existing = load_unlocked(state_base)?
        .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?;
    if !existing.pending
        && existing.generation == generation
        && existing.key_id == key_id
        && existing.status == status
        && existing.device_binding == device_binding
        && existing.installation_binding == installation_binding
    {
        return Ok(existing);
    }
    if existing.generation != generation
        || existing.key_id != key_id
        || existing.status != status
        || existing.device_binding != device_binding
        || existing.installation_binding != installation_binding
        || existing.pending_record_digest != record_digest
        || !existing.pending
    {
        return Err("native_approval_authority_provenance_mismatch".to_owned());
    }
    let state = SecureApprovalState {
        pending: false,
        pending_record_digest: String::new(),
        ..existing
    };
    let encoded = encode_state(&state)?;
    write_platform_secret(&account_for_state_base(state_base)?, &encoded)?;
    Ok(state)
}

#[cfg(not(test))]
pub(crate) fn matches_authority(
    state: &SecureApprovalState,
    generation: u64,
    key_id: &str,
    status: &str,
    device_binding: &str,
    installation_binding: &str,
) -> bool {
    !state.pending
        && state.generation == generation
        && state.key_id == key_id
        && state.status == status
        && state.device_binding == device_binding
        && state.installation_binding == installation_binding
}

#[cfg(test)]
#[path = "approval_enrollment_tests.rs"]
mod tests;
