#![forbid(unsafe_code)]

//! OS-protected enrollment state for the external approval authority.
//!
//! This module stores only enrollment provenance and per-install/device
//! bindings. It deliberately contains no replay secret: request replay state
//! lives in the resident process and is invalidated by its random epoch.

use guard_policy_snapshot::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::path::Path;

#[path = "approval_enrollment_platform.rs"]
mod platform;
use platform::{read_platform_secret, write_platform_secret};

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
/// The inode is retained permanently; ownership is provided by the OS lock,
/// not by a writable PID or a same-UID marker.
pub(crate) struct TransitionLock {
    _file: File,
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
        crate::resident_state::verify_windows_private_path(path, false)?;
    }
    Ok(())
}

fn open_transition_lock(path: &Path) -> Result<File, String> {
    let mut create = OpenOptions::new();
    create.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        create
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    match create.open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                existing.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                const FILE_SHARE_READ: u32 = 0x0000_0001;
                const FILE_SHARE_WRITE: u32 = 0x0000_0002;
                existing
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            existing
                .open(path)
                .map_err(|_| "native_approval_authority_lock_failed".to_owned())
        }
        Err(_) => Err("native_approval_authority_lock_failed".to_owned()),
    }
}

pub(crate) fn with_transition_lock<T, F>(state_base: &Path, operation: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let path = transition_lock_path(state_base)?;
    let file = open_transition_lock(&path)?;
    validate_transition_lock(&path, &file)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "native_approval_authority_busy".to_owned()
        } else {
            "native_approval_authority_lock_failed".to_owned()
        }
    })?;
    let _lock = TransitionLock { _file: file };
    operation()
}

#[derive(Debug, Clone)]
pub(crate) struct SecureApprovalState {
    pub(crate) generation: u64,
    pub(crate) device_binding: String,
    pub(crate) installation_binding: String,
    pub(crate) key_id: String,
    pub(crate) status: String,
    pub(crate) pending: bool,
    /// Digest of the exact canonical, root-signed authority record awaiting
    /// installation. It makes an interrupted transition retryable only for
    /// the same authenticated candidate.
    pub(crate) pending_record_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecureApprovalStateRecord {
    version: u16,
    generation: u64,
    device_binding: String,
    installation_binding: String,
    key_id: String,
    status: String,
    pending: bool,
    pending_record_digest: String,
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

fn encode_state(state: &SecureApprovalState) -> Result<String, String> {
    let record = SecureApprovalStateRecord {
        version: STATE_VERSION,
        generation: state.generation,
        device_binding: state.device_binding.clone(),
        installation_binding: state.installation_binding.clone(),
        key_id: state.key_id.clone(),
        status: state.status.clone(),
        pending: state.pending,
        pending_record_digest: state.pending_record_digest.clone(),
    };
    let value = serde_json::to_value(record)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    Ok(hex::encode(bytes))
}

fn decode_state(value: &str) -> Result<SecureApprovalState, String> {
    if value.is_empty() || value.len() > MAX_SECRET_TEXT_BYTES || value.len() % 2 != 0 {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let bytes =
        hex::decode(value).map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    let record: SecureApprovalStateRecord = serde_json::from_slice(&bytes)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if record.version != STATE_VERSION
        || (record.generation == 0 && !record.pending)
        || (record.generation > 0 && record.pending && record.key_id.is_empty())
        || !valid_digest(&record.device_binding)
        || !valid_digest(&record.installation_binding)
        || record.device_binding == record.installation_binding
    {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    if record.generation == 0 {
        if !record.key_id.is_empty() || record.status != "pending" {
            return Err("native_approval_secure_state_invalid".to_owned());
        }
        if !record.pending_record_digest.is_empty() {
            return Err("native_approval_secure_state_invalid".to_owned());
        }
    } else if !valid_digest(&record.key_id)
        || !matches!(record.status.as_str(), "active" | "revoked")
    {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    if record.pending && !valid_digest(&record.pending_record_digest) {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    if !record.pending && !record.pending_record_digest.is_empty() {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(SecureApprovalState {
        generation: record.generation,
        device_binding: record.device_binding,
        installation_binding: record.installation_binding,
        key_id: record.key_id,
        status: record.status,
        pending: record.pending,
        pending_record_digest: record.pending_record_digest,
    })
}

pub(super) fn load_unlocked(state_base: &Path) -> Result<Option<SecureApprovalState>, String> {
    let account = account_for_state_base(state_base)?;
    let Some(value) = read_platform_secret(&account)? else {
        return Ok(None);
    };
    Ok(Some(decode_state(&value)?))
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

/// Begin an enrollment ceremony. The returned bindings are public ceremony
/// inputs; the underlying random identities never enter Python or the state
/// directory.
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
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root() -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-approval-enrollment-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    #[test]
    fn transition_lock_rejects_concurrent_owner_and_recovers_on_release() {
        let root = test_root();
        let path = transition_lock_path(&root).unwrap();
        let file = open_transition_lock(&path).unwrap();
        validate_transition_lock(&path, &file).unwrap();
        fs2::FileExt::try_lock_exclusive(&file).unwrap();

        assert_eq!(
            with_transition_lock(&root, || Ok::<(), String>(())).unwrap_err(),
            "native_approval_authority_busy"
        );
        drop(file);
        with_transition_lock(&root, || Ok::<(), String>(())).unwrap();
    }
}
