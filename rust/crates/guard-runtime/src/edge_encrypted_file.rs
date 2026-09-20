//! Read the generated owner-private temporary file through held directory/file descriptors.
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use super::{deadline_check, error};

const PREFIX: &str = "hol-guard-hook-payload-";

fn directory_identity(metadata: &Metadata) -> (u64, u64, u32, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    directory: (u64, u64, u32, u32),
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        directory: directory_identity(metadata),
        links: metadata.nlink(),
        bytes: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

// Compare native stat fields directly, retaining each platform's dev/mode widths.
fn same_node(left: &FileStat, right: &FileStat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_nlink == right.st_nlink
}

#[cfg(target_os = "macos")]
fn darwin_temporary_root(root: &Path) -> bool {
    let parts: Vec<_> = root.iter().collect();
    [Path::new("/var/folders"), Path::new("/private/var/folders")]
        .iter()
        .any(|prefix| {
            let base: Vec<_> = prefix.iter().collect();
            parts.starts_with(&base)
                && parts.len() == base.len() + 3
                && parts[base.len()].len() == 2
                && !parts[base.len() + 1].is_empty()
                && parts[base.len() + 2] == "T"
        })
}

fn trusted_root(parent: &Path) -> Result<PathBuf, String> {
    let root = parent.parent().ok_or_else(|| error("path_invalid"))?;
    let roots = [
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ];
    let lexical = roots.iter().any(|value| value == root);
    #[cfg(target_os = "macos")]
    let lexical = lexical
        || matches!(root.to_str(), Some("/private/tmp" | "/private/var/tmp"))
        || darwin_temporary_root(root);
    // Match the existing producer reader's lexical temporary-path gate before
    // resolving the permitted platform temporary-root aliases.
    if !lexical {
        return Err(error("path_invalid"));
    }
    let resolved = root.canonicalize().map_err(|_| error("path_invalid"))?;
    if roots
        .iter()
        .filter_map(|value| value.canonicalize().ok())
        .any(|value| value == resolved)
    {
        return Ok(resolved);
    }
    #[cfg(target_os = "macos")]
    if darwin_temporary_root(&resolved) {
        let metadata = std::fs::symlink_metadata(&resolved).map_err(|_| error("path_invalid"))?;
        if metadata.is_dir() && metadata.uid() == nix::unistd::getuid().as_raw() {
            return Ok(resolved);
        }
    }
    Err(error("path_invalid"))
}

pub(super) fn read(
    path: &Path,
    maximum: usize,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, String> {
    read_checked(path, maximum, deadline, || {})
}

fn read_checked(
    path: &Path,
    maximum: usize,
    deadline: Option<Instant>,
    after_open: impl FnOnce(),
) -> Result<Vec<u8>, String> {
    deadline_check(deadline)?;
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(error("path_invalid"));
    }
    let parent = path.parent().ok_or_else(|| error("path_invalid"))?;
    let directory_name = parent.file_name().ok_or_else(|| error("path_invalid"))?;
    let directory_text = directory_name
        .to_str()
        .ok_or_else(|| error("path_invalid"))?;
    if !directory_text.starts_with(PREFIX) || directory_text.len() <= PREFIX.len() {
        return Err(error("path_invalid"));
    }
    let filename = path.file_name().ok_or_else(|| error("path_invalid"))?;
    let root = trusted_root(parent)?;
    let directory_flags =
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let root =
        File::from(open(&root, directory_flags, Mode::empty()).map_err(|_| error("read_failed"))?);
    let parent = File::from(
        openat(&root, directory_name, directory_flags, Mode::empty())
            .map_err(|_| error("read_failed"))?,
    );
    let parent_before = parent.metadata().map_err(|_| error("read_failed"))?;
    let uid = nix::unistd::getuid().as_raw();
    if !parent_before.is_dir() || parent_before.uid() != uid || parent_before.mode() & 0o077 != 0 {
        return Err(error("not_private"));
    }
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    let mut file = File::from(
        openat(&parent, filename, flags, Mode::empty()).map_err(|_| error("read_failed"))?,
    );
    let before = file.metadata().map_err(|_| error("read_failed"))?;
    if !before.is_file() || before.uid() != uid || before.mode() & 0o077 != 0 || before.nlink() != 1
    {
        return Err(error("not_private"));
    }
    if before.len() > maximum as u64 {
        return Err(error("size_invalid"));
    }
    after_open();
    let mut output = Vec::with_capacity(before.len() as usize);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        deadline_check(deadline)?;
        let count = file.read(&mut buffer).map_err(|_| error("read_failed"))?;
        if count == 0 {
            break;
        }
        if output.len() + count > maximum {
            return Err(error("size_invalid"));
        }
        output.extend_from_slice(&buffer[..count]);
    }
    deadline_check(deadline)?;
    let after = file.metadata().map_err(|_| error("read_failed"))?;
    let parent_after = parent.metadata().map_err(|_| error("read_failed"))?;
    let descriptor = fstat(&file).map_err(|_| error("read_failed"))?;
    let parent_descriptor = fstat(&parent).map_err(|_| error("read_failed"))?;
    let named = fstatat(&parent, filename, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| error("path_changed"))?;
    let named_parent = fstatat(&root, directory_name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| error("path_changed"))?;
    if file_identity(&before) != file_identity(&after)
        || before.len() != output.len() as u64
        || !same_node(&named, &descriptor)
        || directory_identity(&parent_before) != directory_identity(&parent_after)
        || !same_node(&named_parent, &parent_descriptor)
    {
        return Err(error("path_changed"));
    }
    Ok(output)
}

#[cfg(test)]
#[path = "edge_encrypted_file_tests.rs"]
mod tests;
