//! What the machine vouches for, and how this runtime writes a file only the
//! machine can read.
//!
//! Port of `mdm/managed_file_trust.py`: a machine-managed file is authority
//! only when every component from the file to the filesystem root is owned by
//! root, is not group- or world-writable, and is reached without a symlink.
//! Ownership that needs native security APIs to read - a Windows ACL - is not
//! checked here and is therefore never trusted.
//!
//! The same walk answers the other direction too. Before this runtime writes
//! the policy cache, the directory it writes into has to be one no other
//! account can replace, and the write itself has to land on a file it created
//! rather than on whatever a name already pointed at.

use std::fs;
use std::path::Path;

use crate::managed_policy_load::MachineSystem;

/// Whether the walk ends at a file or at a directory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Leaf {
    File,
    Directory,
}

/// `machine_controlled_file_is_trusted` (mdm/managed_file_trust.py:45).
pub(crate) fn machine_controlled_file_is_trusted(path: &Path, system: MachineSystem) -> bool {
    machine_controlled_path_is_trusted(path, system, Leaf::File)
}

/// The same answer for the directory a machine-owned file is written into.
pub(crate) fn machine_controlled_directory_is_trusted(path: &Path, system: MachineSystem) -> bool {
    machine_controlled_path_is_trusted(path, system, Leaf::Directory)
}

fn machine_controlled_path_is_trusted(path: &Path, system: MachineSystem, leaf: Leaf) -> bool {
    if system == MachineSystem::Windows {
        return false;
    }
    if !path.is_absolute() {
        return false;
    }
    posix_path_is_root_owned_and_restricted(path, leaf)
}

/// `posix_path_is_root_owned_and_restricted` (mdm/managed_file_trust.py:21).
///
/// Walk from the path to the filesystem root requiring the expected kind at the
/// leaf, directories above it, no symlink anywhere, root ownership throughout,
/// and no group or world write bit on any component.
#[cfg(unix)]
fn posix_path_is_root_owned_and_restricted(path: &Path, leaf: Leaf) -> bool {
    use std::os::unix::fs::MetadataExt;

    let mut current = path.to_path_buf();
    loop {
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            return false;
        }
        if current == path {
            let expected = match leaf {
                Leaf::File => metadata.is_file(),
                Leaf::Directory => metadata.is_dir(),
            };
            if !expected {
                return false;
            }
        } else if !metadata.is_dir() {
            return false;
        }
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return false;
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent.to_path_buf(),
            _ => return true,
        }
    }
}

#[cfg(not(unix))]
fn posix_path_is_root_owned_and_restricted(_path: &Path, _leaf: Leaf) -> bool {
    false
}

#[cfg(unix)]
pub(crate) fn create_restricted_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    if path.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(path)
}

#[cfg(not(unix))]
pub(crate) fn create_restricted_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)
}

/// Write `bytes` and put them at `path`, replacing whatever is there.
///
/// Python writes its cache through a predictable `.tmp` name
/// (`_write_policy_cache`, mdm/policy.py:311), which an account that can write
/// the directory can turn into a symlink before an administrator's refresh
/// lands on it. This runtime writes a name no other process can predict, under
/// a create that fails if anything already holds the name and never follows a
/// link, so the bytes reach a file this process made or reach nothing at all.
/// The rename then replaces the destination itself, link or not.
pub(crate) fn replace_restricted_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = temporary_sibling(path)?;
    match write_restricted_file(&temporary, bytes).and_then(|()| fs::rename(&temporary, path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

/// A name beside `path` that no other process holds: this process, this write.
fn temporary_sibling(path: &Path) -> std::io::Result<std::path::PathBuf> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("managed policy cache has no file name"))?
        .to_string_lossy()
        .into_owned();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or_default();
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("managed policy cache has no directory"))?;
    Ok(parent.join(format!(".{name}.{}.{nanos}.tmp", std::process::id())))
}

#[cfg(unix)]
fn write_restricted_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        // `create_new` is `O_EXCL`: the open fails rather than writing through
        // a name another account planted, and `O_NOFOLLOW` refuses a link even
        // where `O_EXCL` would not.
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_restricted_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
#[path = "managed_policy_file_trust_tests.rs"]
mod tests;
