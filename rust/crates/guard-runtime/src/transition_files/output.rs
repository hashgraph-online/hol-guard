//! Publishing one generation of a transition file.
//!
//! `write_no_follow` and `remove_no_follow` port `safe_output`: on POSIX every
//! directory is opened relative to the last without following a link and the
//! file is created and renamed through the held descriptor; on Windows the
//! ancestry is locked against replacement and the file is renamed or deleted
//! by handle. `managed_write` and `restore_absent` port `atomic_write_bytes`
//! and `restore_private_file(path, None)` from `codex_hook_integrity`, and
//! return the identity record `record_codex_mutation` appends for them.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

use super::inspect::sha256_hex;
use super::{Fault, Step};

const PRIVATE_KEY_NAME: &str = "hook-manifest.key";

fn random_hex() -> std::io::Result<String> {
    let mut token = [0_u8; 16];
    getrandom::fill(&mut token).map_err(std::io::Error::other)?;
    Ok(hex::encode(token))
}

fn file_name(path: &Path) -> std::io::Result<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "output path has no name")
        })
}

/// One `record_codex_mutation` call, digests withheld for the private key.
fn mutation(operation: &str, path: &Path, before: Option<&[u8]>, after: Option<&[u8]>) -> Value {
    let private = path
        .file_name()
        .is_some_and(|name| name == PRIVATE_KEY_NAME);
    let digest = |bytes: Option<&[u8]>| bytes.filter(|_| !private).map(sha256_hex);
    json!({ "mutation": {
        "operation": operation,
        "path": path.to_string_lossy(),
        "before_present": before.is_some(),
        "after_present": after.is_some(),
        "before_digest": digest(before),
        "after_digest": digest(after),
    } })
}

fn not_regular(message: String) -> Fault {
    Fault::Integrity("codex_hook_manifest_not_regular".to_owned(), message)
}

/// `snapshot_regular_file`.
fn snapshot_regular(path: &Path) -> Step<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => Err(not_regular(
            "Guard refused to replace a non-regular Codex hook manifest.".to_owned(),
        )),
        Ok(_) => Ok(Some(fs::read(path)?)),
    }
}

/// What the journal records as the replaced content.
fn before_content(path: &Path) -> Step<Option<Vec<u8>>> {
    if path
        .file_name()
        .is_some_and(|name| name == PRIVATE_KEY_NAME)
    {
        return Ok(path.exists().then(Vec::new));
    }
    snapshot_regular(path)
}

/// `durable_io.fsync_directory`: a no-op where directories cannot be synced.
#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    let unsupported = |error: &std::io::Error| {
        matches!(
            error.raw_os_error(),
            Some(libc::EINVAL | libc::ENOTSUP | libc::EISDIR | libc::EBADF)
        )
    };
    match fs::File::open(path).and_then(|directory| directory.sync_all()) {
        Err(error) if unsupported(&error) => Ok(()),
        other => other,
    }
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(mode & 0o200 == 0);
    fs::set_permissions(path, permissions)
}

/// `atomic_write_bytes(path, payload, mode=mode, private=False)`.
pub(crate) fn managed_write(path: &Path, payload: &[u8], mode: u32) -> Step<Value> {
    let parent = path.parent().ok_or(Fault::Transition("files_invalid"))?;
    fs::create_dir_all(parent)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(Fault::Integrity(
                "codex_hook_transaction_target_not_regular".to_owned(),
                format!(
                    "Guard refused to replace a non-regular managed file at {}.",
                    path.display()
                ),
            ));
        }
        _ => {}
    }
    let before = before_content(path)?;
    let temporary = parent.join(format!(".{}.{}.tmp", file_name(path)?, random_hex()?));
    let published = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.write_all(payload)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        set_mode(path, mode)?;
        sync_directory(parent)
    })();
    let _ = fs::remove_file(&temporary);
    published?;
    Ok(mutation("publish", path, before.as_deref(), Some(payload)))
}

/// `restore_private_file(path, None)`.
pub(crate) fn restore_absent(path: &Path) -> Step<Value> {
    managed_remove(path, "restore_absent")
}

/// Unlink one managed file and journal it as `kind`; absent is not an error.
pub(crate) fn managed_remove(path: &Path, kind: &str) -> Step<Value> {
    if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(not_regular(
            "Guard refused to replace a symlink in place of the Codex hook manifest.".to_owned(),
        ));
    }
    let before = before_content(path)?;
    match fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    if let Some(parent) = path.parent().filter(|parent| parent.exists()) {
        sync_directory(parent)?;
    }
    Ok(mutation(kind, path, before.as_deref(), None))
}

#[cfg(unix)]
pub(crate) use posix::{remove_no_follow, write_no_follow};
#[cfg(windows)]
pub(crate) use windows::{remove_no_follow, write_no_follow};

#[cfg(unix)]
#[path = "output_posix.rs"]
mod posix;
#[cfg(windows)]
#[path = "output_windows.rs"]
mod windows;
