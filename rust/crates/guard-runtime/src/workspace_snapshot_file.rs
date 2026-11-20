//! Directory handles and stable reads for workspace snapshot files.
//!
//! On Unix every step below the root is relative to a directory descriptor
//! the walk already verified: entries are classified with `fstatat` without
//! following a symlink, child directories are opened with `O_NOFOLLOW` and
//! must be the directory that was classified, and files are opened the same
//! way. Replacing a directory with a symlink mid-walk therefore cannot move
//! the walk outside the root. A file is hashed only when the open descriptor
//! is the file the walk saw and its size, mtime and inode held still for the
//! whole read.

use std::fs::File;
use std::io::Read;

use sha2::{Digest, Sha256};

#[cfg(unix)]
#[path = "workspace_snapshot_dir_unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "workspace_snapshot_dir_path.rs"]
mod platform;

pub(crate) use platform::DirHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    File,
    Directory,
    Symlink,
    Special,
}

/// What the walk saw of one entry, without following it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Node {
    pub(crate) kind: Kind,
    pub(crate) len: u64,
    pub(crate) mtime_ns: i128,
    pub(crate) ino: u64,
    pub(crate) dev: u64,
}

impl Node {
    pub(crate) fn same_object(&self, other: &Node) -> bool {
        self.kind == other.kind && self.ino == other.ino && self.dev == other.dev
    }

    fn unchanged(&self, other: &Node) -> bool {
        self.same_object(other) && self.len == other.len && self.mtime_ns == other.mtime_ns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashError {
    Unreadable,
    Unstable,
}

/// Hash one file the walk opened without following a leaf symlink and reject
/// it when the open descriptor is not the file the walk saw, or when its size
/// or mtime moved during the read.
///
/// When `capture` is given, the bytes that were hashed are appended to it, so
/// a detector reads exactly the content the snapshot digest covers. The buffer
/// is only meaningful when the call returns `Ok`.
pub(crate) fn hash_stable(
    mut file: File,
    seen: &Node,
    max_bytes: u64,
    mut capture: Option<&mut Vec<u8>>,
) -> Result<(String, u64), HashError> {
    let before = platform::file_node(&file).map_err(|_| HashError::Unreadable)?;
    if !before.unchanged(seen) {
        return Err(HashError::Unstable);
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut read_total: u64 = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|_| HashError::Unreadable)?;
        if count == 0 {
            break;
        }
        read_total += count as u64;
        if read_total > max_bytes {
            return Err(HashError::Unstable);
        }
        hasher.update(&buffer[..count]);
        if let Some(sink) = capture.as_deref_mut() {
            sink.extend_from_slice(&buffer[..count]);
        }
    }
    let after = platform::file_node(&file).map_err(|_| HashError::Unreadable)?;
    if read_total != before.len || !before.unchanged(&after) {
        return Err(HashError::Unstable);
    }
    Ok((hex::encode(hasher.finalize()), read_total))
}
