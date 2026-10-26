#![forbid(unsafe_code)]

//! Provision the derived policy verifier key the resident reads at startup.
//!
//! The resident cannot serve a request until this key exists, so provisioning
//! can never be a resident RPC: it runs as a one-shot native invocation before
//! any resident is asked for an answer. Creation never replaces an existing
//! key. A changed policy master is a safe, explicit failure instead of an
//! implicit verifier reset that would invalidate the generation floor.

use crate::policy_store::{read_verifier_key, VERIFIER_KEY_BYTES, VERIFIER_KEY_FILE_NAME};
use crate::resident_state::{
    ensure_private_directory_under, private_file, private_root_for_state_base,
};
use crate::resident_transport::constant_time_eq;
use guard_policy_snapshot::derive_verifier_key;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A provisioner on a filesystem without hard links creates the final path
/// before writing it. Give an in-flight writer a bounded window to finish
/// before a short file is reported as tampering.
const PARTIAL_KEY_RETRIES: usize = 20;
const PARTIAL_KEY_RETRY: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifierKeyProvision {
    /// This call published the key.
    Created,
    /// A key was already present and matched the derived bytes.
    Verified,
}

impl VerifierKeyProvision {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Verified => "verified",
        }
    }
}

/// Read the key already at `state_base`, waiting out a partial write.
///
/// `Ok(None)` means no key is there yet. Every other failure keeps its own
/// code: the caller must not rewrite a key it could not read.
fn existing_key(state_base: &Path) -> Result<Option<[u8; VERIFIER_KEY_BYTES]>, String> {
    let mut attempt = 0usize;
    loop {
        match read_verifier_key(state_base) {
            Ok(key) => return Ok(Some(key)),
            Err(code) if code == "native_policy_verifier_key_missing" => return Ok(None),
            Err(code) if code == "native_policy_verifier_key_invalid" => {
                // Only a short file is a possible in-flight write; anything
                // else invalid stays invalid however long we wait.
                if attempt >= PARTIAL_KEY_RETRIES || !key_is_short(state_base) {
                    return Err(code);
                }
                attempt += 1;
                std::thread::sleep(PARTIAL_KEY_RETRY);
            }
            Err(code) => return Err(code),
        }
    }
}

/// Report whether the key file exists and is a regular file still shorter than
/// a whole key, which is the only shape a concurrent writer can leave behind.
fn key_is_short(state_base: &Path) -> bool {
    let path = state_base.join(VERIFIER_KEY_FILE_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            metadata.file_type().is_file() && metadata.len() < VERIFIER_KEY_BYTES as u64
        }
        Err(_) => false,
    }
}

fn temporary_name() -> Result<String, String> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|_| "native_policy_verifier_key_write_failed".to_owned())?;
    Ok(format!(
        "{VERIFIER_KEY_FILE_NAME}.{}.tmp",
        hex::encode(nonce)
    ))
}

/// A failed key write, and whether this call created the file it failed on.
///
/// Only the creator of a half-written file may remove it, so the two cases
/// cannot share one error.
struct KeyWriteFailure {
    code: String,
    created: bool,
}

/// Write `derived` into a fresh private file and flush it to disk.
fn write_private_key(
    path: &Path,
    derived: &[u8; VERIFIER_KEY_BYTES],
    private_root: &Path,
) -> Result<(), KeyWriteFailure> {
    let mut file = private_file(path, true, private_root).map_err(|code| KeyWriteFailure {
        code,
        created: false,
    })?;
    if file.write_all(derived).is_err() || file.sync_all().is_err() {
        return Err(KeyWriteFailure {
            code: "native_policy_verifier_key_write_failed".to_owned(),
            created: true,
        });
    }
    Ok(())
}

/// Make the directory entry for a freshly published key durable.
fn sync_directory(state_base: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let directory = std::fs::File::open(state_base)
            .map_err(|_| "native_policy_verifier_key_sync_failed".to_owned())?;
        directory
            .sync_all()
            .map_err(|_| "native_policy_verifier_key_sync_failed".to_owned())?;
    }
    #[cfg(not(unix))]
    let _ = state_base;
    Ok(())
}

/// Publish `temporary` at `path` without replacing an existing key.
///
/// `Ok(true)` means this call published it, `Ok(false)` that another writer
/// got there first. `Err(None)` reports a filesystem that cannot link at all,
/// which leaves the create-the-final-path fallback as the only route.
#[cfg(unix)]
fn publish_without_replacing(
    temporary: &Path,
    path: &Path,
    _private_root: &Path,
) -> Result<bool, Option<String>> {
    match std::fs::hard_link(temporary, path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        // Only a filesystem that refuses links at all may take the fallback.
        // A full disk, a denied directory or an I/O error says nothing about
        // link support, and publishing those as "cannot link" would turn a
        // one-off failure into a create of the final path.
        Err(error)
            if error.kind() == std::io::ErrorKind::Unsupported
                || matches!(
                    error.raw_os_error(),
                    Some(libc::EPERM) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
                ) =>
        {
            Err(None)
        }
        Err(_) => Err(Some("native_policy_verifier_key_write_failed".to_owned())),
    }
}

#[cfg(not(unix))]
fn publish_without_replacing(
    temporary: &Path,
    path: &Path,
    private_root: &Path,
) -> Result<bool, Option<String>> {
    #[cfg(windows)]
    {
        match crate::resident_state::publish_new_windows_private_file(temporary, path, private_root)
        {
            Ok(published) => Ok(published),
            Err(code) => Err(Some(code)),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (temporary, path, private_root);
        Err(None)
    }
}

/// Create the key under `state_base`, or confirm the one already there.
///
/// `policy_integrity_key` is the policy master. It is never written: only the
/// HMAC derived from it reaches the filesystem.
pub(crate) fn provision_verifier_key(
    state_base: &Path,
    policy_integrity_key: &[u8],
) -> Result<VerifierKeyProvision, String> {
    if policy_integrity_key.len() != VERIFIER_KEY_BYTES {
        return Err("native_policy_verifier_master_invalid".to_owned());
    }
    let derived = derive_verifier_key(policy_integrity_key);
    let private_root = private_root_for_state_base(state_base)?;
    ensure_private_directory_under(state_base, &private_root, true)?;
    let path = state_base.join(VERIFIER_KEY_FILE_NAME);

    if let Some(existing) = existing_key(state_base)? {
        if !constant_time_eq(&existing, &derived) {
            return Err("native_policy_verifier_key_mismatch".to_owned());
        }
        return Ok(VerifierKeyProvision::Verified);
    }

    let temporary: PathBuf = state_base.join(temporary_name()?);
    let written = write_private_key(&temporary, &derived, &private_root);
    let published = written.map_err(|failure| failure.code).and_then(|()| {
        match publish_without_replacing(&temporary, &path, &private_root) {
            Ok(published) => Ok(Some(published)),
            Err(Some(code)) => Err(code),
            Err(None) => Ok(None),
        }
    });
    let _ = std::fs::remove_file(&temporary);
    let published = published?;

    match published {
        Some(true) => {
            sync_directory(state_base)?;
            Ok(VerifierKeyProvision::Created)
        }
        Some(false) => {
            // Another provisioner won the race. Validate its key rather than
            // replacing it, and make its directory entry durable first.
            sync_directory(state_base)?;
            confirm_existing(state_base, &derived)
        }
        None => create_final_key(state_base, &path, &derived, &private_root),
    }
}

/// Publish the key at its final path, for a filesystem that cannot link.
///
/// The exclusive create still never replaces a key; a reader may briefly see
/// the file short, which `existing_key` waits out.
fn create_final_key(
    state_base: &Path,
    path: &Path,
    derived: &[u8; VERIFIER_KEY_BYTES],
    private_root: &Path,
) -> Result<VerifierKeyProvision, String> {
    match write_private_key(path, derived, private_root) {
        Ok(()) => {
            sync_directory(state_base)?;
            Ok(VerifierKeyProvision::Created)
        }
        Err(failure) if failure.created => {
            // This call created the file, so removing it cannot destroy a key
            // another provisioner published. Left behind, a short key would
            // fail every later provisioning and the resident's own startup
            // check until someone deleted it by hand.
            let _ = std::fs::remove_file(path);
            Err(failure.code)
        }
        Err(failure) => {
            // The create itself failed. Another provisioner winning the race
            // is the one reason to confirm a key instead of reporting the
            // failure; with nothing there, the write error is the answer.
            if std::fs::symlink_metadata(path).is_ok() {
                confirm_existing(state_base, derived)
            } else {
                Err(failure.code)
            }
        }
    }
}

fn confirm_existing(
    state_base: &Path,
    derived: &[u8; VERIFIER_KEY_BYTES],
) -> Result<VerifierKeyProvision, String> {
    let existing =
        existing_key(state_base)?.ok_or_else(|| "native_policy_verifier_key_missing".to_owned())?;
    if !constant_time_eq(&existing, derived) {
        return Err("native_policy_verifier_key_mismatch".to_owned());
    }
    Ok(VerifierKeyProvision::Verified)
}

#[cfg(test)]
#[path = "policy_verifier_key_provision_tests.rs"]
mod tests;
