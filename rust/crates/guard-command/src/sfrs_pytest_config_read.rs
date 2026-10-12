//! Bounded, symlink-refusing read of one pytest config file
//! (`pytest_config._read_config_bytes`).
//!
//! The file is opened without following a final symlink, read twice and its
//! identity compared before and after, so a file that changes under the read is
//! reported instead of parsed.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_py::PyPath;

pub(crate) const MAX_PYTEST_CONFIG_FILE_BYTES: usize = 1_000_000;
pub(crate) const PATH_INVALID: &str = "pytest_config_path_invalid";
pub(crate) const SYMLINK: &str = "pytest_config_symlink";
pub(crate) const NOT_REGULAR: &str = "pytest_config_not_regular";
pub(crate) const OVERSIZE: &str = "pytest_config_oversize";
pub(crate) const IO_ERROR: &str = "pytest_config_io_error";
pub(crate) const FILE_CHANGED: &str = "pytest_config_file_changed";

/// `_ConfigRead`.
pub(crate) struct ConfigRead {
    pub(crate) present: bool,
    pub(crate) content: Option<Vec<u8>>,
    pub(crate) reason_code: Option<&'static str>,
}

fn refused(present: bool, reason: Option<&'static str>) -> ConfigRead {
    ConfigRead {
        present,
        content: None,
        reason_code: reason,
    }
}

/// `_read_config_bytes`.
#[cfg(unix)]
pub(crate) fn read_config_bytes(workspace_root: &Path, relative_path: &str) -> ConfigRead {
    use std::fs;
    use std::io::{ErrorKind, Read, Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let relative = PyPath::new(relative_path);
    if relative_path.is_empty()
        || relative.is_absolute()
        || relative.components().iter().any(|part| part == "..")
    {
        return refused(false, Some(PATH_INVALID));
    }
    let Ok(root) = fs::canonicalize(workspace_root) else {
        return refused(false, Some(IO_ERROR));
    };
    let mut current = root.clone();
    for part in relative.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return refused(true, Some(SYMLINK));
            }
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return refused(false, None);
            }
            Err(_) => return refused(true, Some(IO_ERROR)),
        }
    }
    let resolved = match fs::canonicalize(&current) {
        Ok(resolved) if resolved.starts_with(&root) => resolved,
        _ => return refused(true, Some(PATH_INVALID)),
    };
    let Ok(before) = fs::metadata(&resolved) else {
        return refused(true, Some(PATH_INVALID));
    };
    if !before.is_file() {
        return refused(true, Some(NOT_REGULAR));
    }
    if before.len() > MAX_PYTEST_CONFIG_FILE_BYTES as u64 {
        return refused(true, Some(OVERSIZE));
    }
    type Identity = (u64, u64, u64, i64, i64, i64, i64);
    let identity = |meta: &fs::Metadata| -> Identity {
        (
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        )
    };
    let short = |meta: &fs::Metadata| (meta.dev(), meta.ino(), meta.size());
    let io_failure = |error: &std::io::Error| {
        if error.kind() == ErrorKind::NotFound {
            refused(true, Some(FILE_CHANGED))
        } else {
            refused(true, Some(IO_ERROR))
        }
    };
    let mut handle = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&resolved)
    {
        Ok(handle) => handle,
        Err(error) => return io_failure(&error),
    };
    let opened = match handle.metadata() {
        Ok(meta) => meta,
        Err(error) => return io_failure(&error),
    };
    if short(&opened) != short(&before) {
        return refused(true, Some(FILE_CHANGED));
    }
    let limit = (MAX_PYTEST_CONFIG_FILE_BYTES + 1) as u64;
    let mut content = Vec::new();
    if let Err(error) = (&mut handle).take(limit).read_to_end(&mut content) {
        return io_failure(&error);
    }
    let after_read = match handle.metadata() {
        Ok(meta) => meta,
        Err(error) => return io_failure(&error),
    };
    if let Err(error) = handle.seek(SeekFrom::Start(0)) {
        return io_failure(&error);
    }
    let mut verified = Vec::new();
    if let Err(error) = (&mut handle).take(limit).read_to_end(&mut verified) {
        return io_failure(&error);
    }
    let after_verify = match handle.metadata() {
        Ok(meta) => meta,
        Err(error) => return io_failure(&error),
    };
    if content.len() > MAX_PYTEST_CONFIG_FILE_BYTES || verified.len() > MAX_PYTEST_CONFIG_FILE_BYTES
    {
        return refused(true, Some(OVERSIZE));
    }
    if verified != content {
        return refused(true, Some(FILE_CHANGED));
    }
    let opened_identity = identity(&opened);
    if identity(&after_read) != opened_identity || identity(&after_verify) != opened_identity {
        return refused(true, Some(FILE_CHANGED));
    }
    match fs::metadata(&resolved) {
        Ok(after) if identity(&after) == opened_identity => ConfigRead {
            present: true,
            content: Some(content),
            reason_code: None,
        },
        Ok(_) => refused(true, Some(FILE_CHANGED)),
        Err(error) => io_failure_after(&error),
    }
}

#[cfg(unix)]
fn io_failure_after(error: &std::io::Error) -> ConfigRead {
    // The final `resolved.stat()` is inside the same `try`: a missing file is a
    // change, anything else an I/O error.
    if error.kind() == std::io::ErrorKind::NotFound {
        refused(true, Some(FILE_CHANGED))
    } else {
        refused(true, Some(IO_ERROR))
    }
}

/// Without POSIX file identity the read cannot be verified, so it fails closed.
#[cfg(not(unix))]
pub(crate) fn read_config_bytes(_workspace_root: &Path, relative_path: &str) -> ConfigRead {
    let relative = PyPath::new(relative_path);
    if relative_path.is_empty()
        || relative.is_absolute()
        || relative.components().iter().any(|part| part == "..")
    {
        return refused(false, Some(PATH_INVALID));
    }
    refused(true, Some(IO_ERROR))
}
