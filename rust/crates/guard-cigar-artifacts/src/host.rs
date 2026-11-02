//! File-system facts that mean the same thing on every supported system.
//!
//! Unix code compares owners, permission bits and `(dev, ino)` directly.
//! Windows has no permission bits or inode numbers, so the counterparts are
//! the security owner, the read-only attribute and the volume file ID read
//! through a handle opened without following a link.
use std::path::{Component, Path};

/// Whether `path` is the spelling `std::fs::canonicalize` gives back. A
/// Windows canonical path carries the `\\?\` verbatim prefix that an
/// ordinary drive path leaves off; both name the same object.
pub fn is_canonical(path: &Path) -> std::io::Result<bool> {
    let canonical = std::fs::canonicalize(path)?;
    if canonical == path {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        Ok(strip_verbatim(&canonical) == strip_verbatim(path))
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

#[cfg(windows)]
fn strip_verbatim(path: &Path) -> std::path::PathBuf {
    let text = path.as_os_str().to_string_lossy();
    match text.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}").into(),
        None => text.strip_prefix(r"\\?\").unwrap_or(&text).into(),
    }
}

/// `path` below `root` as a `/`-separated name, or `None` when it is not
/// below `root` or is not UTF-8.
pub fn relative_name(path: &Path, root: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let mut name = String::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(part.to_str()?);
    }
    Some(name)
}

#[cfg(windows)]
pub use windows::*;

#[cfg(windows)]
mod windows {
    use std::fs::{File, Metadata, OpenOptions};
    use std::io;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    pub use guard_runtime_windows_process::FileId;

    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const READ_CONTROL: u32 = 0x0002_0000;
    const SHARE_ALL: u32 = 0x0001 | 0x0002 | 0x0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    /// Open `path` itself for its attributes, never a link's target. A file
    /// or a directory opens the same way.
    pub fn open_unfollowed(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }

    /// The volume and file ID of `path` itself, the `(dev, ino)` pair.
    pub fn node_id(path: &Path) -> io::Result<FileId> {
        handle_node_id(&open_unfollowed(path)?)
    }

    /// The volume and file ID of an open handle.
    pub fn handle_node_id(file: &File) -> io::Result<FileId> {
        guard_runtime_windows_process::handle_file_id(file)
    }

    /// Whether the current user (or LocalSystem or Administrators, who can
    /// already rewrite anything the user owns) owns `path`, and no other
    /// account may change it. Ownership alone says nothing about who else
    /// the access list lets write, which the Unix mode check covers.
    pub fn owned(path: &Path) -> bool {
        guard_runtime_windows_process::owned_by_current_user(path)
            && guard_runtime_windows_process::writable_only_by_trusted(path)
    }

    /// Whether `metadata` is a link, junction or other reparse point.
    pub fn reparse(metadata: &Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Whether the read-only attribute is set, the counterpart of a Unix
    /// file with no write bits.
    pub fn read_only(metadata: &Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0
    }

    /// Whether `path` is a directory the current user owns that is not a
    /// link or junction.
    pub fn private_directory(path: &Path, metadata: &Metadata) -> bool {
        metadata.is_dir() && !reparse(metadata) && owned(path)
    }

    /// Whether `path` is a regular file the current user owns that is not a
    /// link, and has exactly one name.
    pub fn private_file(path: &Path, metadata: &Metadata) -> bool {
        metadata.is_file()
            && !reparse(metadata)
            && owned(path)
            && guard_runtime_windows_process::is_single_link_file(path).unwrap_or(false)
    }

    /// Stamp of the attributes a same-user rewrite changes: ID, attribute
    /// bits, length and the creation and last-write times.
    pub fn stamp(path: &Path) -> io::Result<(FileId, u32, u64, u64, u64)> {
        let file = open_unfollowed(path)?;
        let metadata = file.metadata()?;
        Ok((
            handle_node_id(&file)?,
            metadata.file_attributes(),
            metadata.file_size(),
            metadata.creation_time(),
            metadata.last_write_time(),
        ))
    }
}
