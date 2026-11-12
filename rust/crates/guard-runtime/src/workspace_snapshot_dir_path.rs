//! Path-based snapshot traversal for platforms without `openat`.
//!
//! Entries are classified with `symlink_metadata`, which reports symlinks and
//! junctions (name-surrogate reparse points) as symlinks, and files are opened
//! with `FILE_FLAG_OPEN_REPARSE_POINT`. A child directory is re-checked just
//! before it is listed, which narrows but cannot close the window in which a
//! directory could be swapped for a junction.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::path::{Path, PathBuf};

use super::{HashError, Kind, Node};

pub(crate) struct DirHandle {
    path: PathBuf,
}

impl DirHandle {
    pub(crate) fn open_root(path: &Path) -> Option<Self> {
        let metadata = fs::symlink_metadata(path).ok()?;
        (metadata.is_dir() && !metadata.file_type().is_symlink()).then(|| Self {
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn names(&mut self) -> Vec<Option<OsString>> {
        let Ok(reader) = fs::read_dir(&self.path) else {
            return vec![None];
        };
        reader
            .map(|entry| entry.ok().map(|entry| entry.file_name()))
            .collect()
    }

    pub(crate) fn stat(&self, name: &OsStr) -> Option<Node> {
        fs::symlink_metadata(self.path.join(name))
            .ok()
            .map(|metadata| metadata_node(&metadata))
    }

    pub(crate) fn open_dir(&self, name: &OsStr, seen: &Node) -> Result<Self, HashError> {
        let path = self.path.join(name);
        let current = fs::symlink_metadata(&path).map_err(|_| HashError::Unstable)?;
        if !metadata_node(&current).same_object(seen) {
            return Err(HashError::Unstable);
        }
        Ok(Self { path })
    }

    pub(crate) fn open_file(&self, name: &OsStr) -> Option<File> {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a reparse point itself, never its
        // target. `hash_stable` then rejects anything but the file seen.
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(self.path.join(name))
            .ok()
    }

    pub(crate) fn read_link(&self, name: &OsStr) -> Option<OsString> {
        fs::read_link(self.path.join(name))
            .ok()
            .map(PathBuf::into_os_string)
    }
}

pub(super) fn file_node(file: &File) -> std::io::Result<Node> {
    file.metadata().map(|metadata| metadata_node(&metadata))
}

fn metadata_node(metadata: &Metadata) -> Node {
    let kind = metadata.file_type();
    Node {
        kind: if kind.is_symlink() {
            Kind::Symlink
        } else if kind.is_dir() {
            Kind::Directory
        } else if kind.is_file() {
            Kind::File
        } else {
            Kind::Special
        },
        len: metadata.len(),
        mtime_ns: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| {
                i128::try_from(elapsed.as_nanos()).unwrap_or(i128::MAX)
            }),
        ino: 0,
        dev: 0,
    }
}
