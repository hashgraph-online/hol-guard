//! `safe_output_windows`: publish and remove through a locked ancestry.
//!
//! Each directory from the drive root down is opened sharing read only, so
//! none can be renamed, deleted or turned into a junction while the file is
//! written. The temporary file is renamed into the final directory by handle,
//! and a removal deletes the file through a handle opened without following
//! a reparse point.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use guard_runtime_windows_process::{mark_handle_for_delete, rename_into_directory};

use super::random_hex;

const DELETE: u32 = 0x0001_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_TRAVERSE: u32 = 0x0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ: u32 = 0x0001;
const FILE_SHARE_WRITE: u32 = 0x0002;
const FILE_SHARE_DELETE: u32 = 0x0004;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_SHARING_VIOLATION: i32 = 32;
const SHARING_WAIT: Duration = Duration::from_secs(3);
const WRITE_CHUNK: usize = 1024 * 1024;

fn missing(error: &std::io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
    )
}

fn refuse_reparse(handle: &fs::File, path: &Path, what: &str) -> std::io::Result<()> {
    if handle.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(format!(
            "refusing reparse-point {what}: {}",
            path.display()
        )));
    }
    Ok(())
}

/// `_open_locked_directory`: denying write and delete sharing conflicts with
/// any open writer, so a short-lived one is waited out.
fn lock_directory(path: &Path) -> std::io::Result<fs::File> {
    let deadline = Instant::now() + SHARING_WAIT;
    let mut delay = Duration::from_millis(5);
    let handle = loop {
        let opened = fs::OpenOptions::new()
            .access_mode(FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path);
        match opened {
            Ok(handle) => break handle,
            Err(error)
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    };
    refuse_reparse(&handle, path, "output directory")?;
    Ok(handle)
}

/// `_open_rename_directory`: the directory the rename is relative to.
fn rename_directory(path: &Path) -> std::io::Result<fs::File> {
    let handle = fs::OpenOptions::new()
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    refuse_reparse(&handle, path, "output directory")?;
    Ok(handle)
}

fn absolute(path: &Path) -> std::io::Result<PathBuf> {
    std::path::absolute(path)
}

/// The drive root, then each directory below it.
fn ancestry(parent: &Path) -> Vec<PathBuf> {
    let mut current = PathBuf::new();
    let mut chain = Vec::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        chain.push(current.clone());
    }
    chain
}

/// `write_bytes_atomic_no_follow_windows`. The mode is POSIX-only.
pub(crate) fn write_no_follow(path: &Path, payload: &[u8], _mode: u32) -> std::io::Result<()> {
    let target = absolute(path)?;
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(std::io::Error::other("output path is invalid"));
    };
    let mut locked = Vec::new();
    for directory in ancestry(parent) {
        // A drive root answers access denied rather than "already exists",
        // so an existing directory is accepted whatever the error says; the
        // lock below still refuses a reparse point.
        if let Err(error) = fs::create_dir(&directory) {
            if error.kind() != std::io::ErrorKind::AlreadyExists && !directory.is_dir() {
                return Err(error);
            }
        }
        locked.push(lock_directory(&directory)?);
    }
    let temporary = parent.join(format!(".{}.{}", name.to_string_lossy(), random_hex()?));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_WRITE | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&temporary)?;
    let renamed = publish_handle(&mut file, payload, parent, name, &mut locked);
    if renamed.is_err() {
        let _ = mark_handle_for_delete(&file);
    }
    renamed
}

fn publish_handle(
    file: &mut fs::File,
    payload: &[u8],
    parent: &Path,
    name: &OsStr,
    locked: &mut Vec<fs::File>,
) -> std::io::Result<()> {
    for chunk in payload.chunks(WRITE_CHUNK) {
        file.write_all(chunk)?;
    }
    file.sync_all()?;
    let directory = rename_directory(parent)?;
    drop(locked.pop());
    rename_into_directory(&directory, file, name, true)
}

/// `remove_file_no_follow_windows`: delete by handle under a locked ancestry.
pub(crate) fn remove_no_follow(path: &Path) -> std::io::Result<()> {
    let target = absolute(path)?;
    let Some(parent) = target.parent() else {
        return Err(std::io::Error::other("output path is invalid"));
    };
    let mut locked = Vec::new();
    for directory in ancestry(parent) {
        match lock_directory(&directory) {
            Ok(handle) => locked.push(handle),
            Err(error) if missing(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    let file = match fs::OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&target)
    {
        Ok(file) => file,
        Err(error) if missing(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let attributes = file.metadata()?.file_attributes();
    if attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(std::io::Error::other(
            "refusing non-regular output file removal",
        ));
    }
    let deleted = mark_handle_for_delete(&file);
    drop(file);
    drop(locked);
    deleted
}
