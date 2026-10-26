//! The small private files the managed-resident supervisor keeps beside a
//! scope: the crash-loop restart budget and the note a child leaves when it
//! was asked to stop.
//!
//! Both are written the same way -- a private temporary file replaced into
//! place -- and read back through the same checks, so a foreign, swapped or
//! symlinked file fails closed whichever one is being read. The error
//! strings keep their `native_resident_restart_budget_*` names: they are
//! reason codes a caller can already be matching on, and the budget is still
//! the reason this writer exists.

#[cfg(unix)]
use std::fs::File;
#[cfg(not(windows))]
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(super) fn write_private(path: &Path, bytes: &[u8], private_root: &Path) -> Result<(), String> {
    let temporary = temporary_path(path)?;
    if existing_private_file(&temporary, private_root)? {
        #[cfg(windows)]
        crate::resident_state::remove_windows_private_file(&temporary, private_root)
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
        #[cfg(not(windows))]
        fs::remove_file(&temporary)
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    }
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let mut file = crate::resident_state::private_file(&temporary, true, private_root)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    #[cfg(not(windows))]
    let mut file = options
        .open(&temporary)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    let write_result = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned());
    drop(file);
    if write_result.is_err() {
        #[cfg(windows)]
        let _ = crate::resident_state::remove_windows_private_file(&temporary, private_root);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return write_result;
    }
    let replace_result = replace_temporary(&temporary, path, private_root);
    if replace_result.is_err() {
        #[cfg(windows)]
        let _ = crate::resident_state::remove_windows_private_file(&temporary, private_root);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return replace_result;
    }
    #[cfg(unix)]
    File::open(
        path.parent()
            .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?,
    )
    .and_then(|directory| directory.sync_all())
    .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(())
}

pub(super) fn existing_private_file(path: &Path, private_root: &Path) -> Result<bool, String> {
    #[cfg(not(windows))]
    let _ = private_root;

    #[cfg(windows)]
    {
        // Existence and type are established by one validated handle.  Do
        // not use pathname metadata here: a same-name replacement between a
        // stat and the subsequent open must never be treated as our budget
        // file, and foreign-owner/reparse objects must fail closed.
        crate::resident_state::open_private_read(path, 4096, "restart_budget", private_root)
            .map(|file| file.is_some())
            .map_err(|_| "native_resident_restart_budget_invalid".to_owned())
    }

    #[cfg(not(windows))]
    {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err("native_resident_restart_budget_stat_failed".to_owned()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let owner = path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok())
                .map(|parent| parent.uid());
            if owner != Some(metadata.uid()) || metadata.permissions().mode() & 0o077 != 0 {
                return Err("native_resident_restart_budget_invalid".to_owned());
            }
        }
        Ok(true)
    }
}

#[cfg(not(windows))]
fn replace_temporary(temporary: &Path, path: &Path, _private_root: &Path) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|_| {
        let _ = fs::remove_file(temporary);
        "native_resident_restart_budget_write_failed".to_owned()
    })
}

#[cfg(windows)]
fn replace_temporary(temporary: &Path, path: &Path, private_root: &Path) -> Result<(), String> {
    crate::resident_state::replace_windows_private_file(temporary, path, private_root)
        .map_err(|_| "native_resident_restart_budget_write_failed".to_owned())
}

#[cfg(windows)]
pub(super) fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("json.previous")
}

#[cfg(windows)]
pub(super) fn recover_interrupted_replace(path: &Path, private_root: &Path) -> Result<(), String> {
    let backup = backup_path(path);
    let path_exists = existing_private_file(path, private_root)
        .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    let backup_exists = existing_private_file(&backup, private_root)
        .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())?;
    match (path_exists, backup_exists) {
        (false, true) => {
            crate::resident_state::replace_windows_private_file(&backup, path, private_root)
                .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned())
        }
        (true, true) => crate::resident_state::remove_windows_private_file(&backup, private_root)
            .map(|_| ())
            .map_err(|_| "native_resident_restart_budget_recovery_failed".to_owned()),
        _ => Ok(()),
    }
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "native_resident_restart_budget_write_failed".to_owned())?;
    Ok(path.with_file_name(format!(".{name}.{}.tmp", std::process::id())))
}

/// Read one small private file this module owns. The budget and the
/// requested-stop note sit in the same directory and are validated the same
/// way, so a foreign or swapped file fails closed whichever one is read.
pub(super) fn read_private_bytes(
    path: &Path,
    private_root: &Path,
    label: &'static str,
) -> Result<Option<Vec<u8>>, String> {
    if !existing_private_file(path, private_root)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    let file = {
        #[cfg(windows)]
        {
            crate::resident_state::open_private_read(path, 4096, label, private_root)?
                .ok_or_else(|| "native_resident_restart_budget_read_failed".to_owned())?
        }
        #[cfg(not(windows))]
        {
            let _ = label;
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            options
                .open(path)
                .map_err(|_| "native_resident_restart_budget_read_failed".to_owned())?
        }
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4096 {
        return Err("native_resident_restart_budget_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|_| "native_resident_restart_budget_stat_failed".to_owned())?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
            || path
                .parent()
                .and_then(|parent| fs::symlink_metadata(parent).ok())
                .map(|parent| parent.uid())
                != Some(metadata.uid())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_restart_budget_invalid".to_owned());
        }
    }
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_resident_restart_budget_read_failed".to_owned())?;
    Ok(Some(bytes))
}

/// Removing one of this module's files is best effort in the same way
/// writing it is: the budget is rewritten from scratch on the next spawn and
/// a stop note is only ever honoured for the one child it names, so a failed
/// removal costs nothing but the file.
pub(super) fn remove_private(path: &Path, private_root: &Path) {
    #[cfg(windows)]
    let _ = crate::resident_state::remove_windows_private_file(path, private_root);
    #[cfg(not(windows))]
    {
        let _ = private_root;
        let _ = fs::remove_file(path);
    }
}
