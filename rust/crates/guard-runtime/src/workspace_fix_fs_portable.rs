//! Path-based directory access for manifest fixes where `openat` is missing.
//!
//! Each component is classified with `symlink_metadata` before it is entered
//! and a reparse point of any kind is refused. Without descriptors that check
//! narrows, but cannot close, the window in which a directory is swapped for a
//! junction after it was inspected.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::{Code, Entry, Kind};

/// Replacing by path could follow a junction swapped in after the check.
pub(super) const REPLACE_SUPPORTED: bool = false;

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub(super) struct Dir {
    path: PathBuf,
}

fn entry(metadata: &Metadata) -> Entry {
    let kind = metadata.file_type();
    Entry {
        kind: if kind.is_symlink() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            Kind::Symlink
        } else if kind.is_dir() {
            Kind::Directory
        } else if kind.is_file() {
            Kind::File
        } else {
            Kind::Other
        },
        len: metadata.len(),
        mode: 0,
        // Stable std has no file index off Unix; creation and last-write
        // times still tell a replaced or rewritten file from the one inspected.
        id: (metadata.creation_time(), metadata.last_write_time()),
    }
}

impl Dir {
    pub(super) fn open_root(path: &Path) -> Result<Self, Code> {
        let metadata = fs::symlink_metadata(path).map_err(|_| "manifest_root_unavailable")?;
        if entry(&metadata).kind != Kind::Directory {
            return Err("manifest_root_unavailable");
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    pub(super) fn open_child(&self, name: &str) -> Result<Self, Code> {
        let path = self.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if entry(&metadata).kind == Kind::Directory => Ok(Self { path }),
            Ok(_) => Err("manifest_path_invalid"),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err("manifest_missing"),
            Err(_) => Err("manifest_unreadable"),
        }
    }

    pub(super) fn stat(&self, name: &str) -> io::Result<Entry> {
        fs::symlink_metadata(self.path.join(name)).map(|metadata| entry(&metadata))
    }

    pub(super) fn open_read(&self, name: &str) -> io::Result<File> {
        // Open a reparse point itself, never its target; the caller rejects
        // anything that is not the regular file it inspected.
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))
    }

    pub(super) fn create_new(&self, name: &str) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))
    }

    pub(super) fn set_mode(&self, _file: &File, _mode: u32) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        fs::rename(self.path.join(from), self.path.join(to))
    }

    /// Hard-link `from` as `to`; fails with `AlreadyExists` instead of replacing.
    pub(super) fn link_new(&self, from: &str, to: &str) -> io::Result<()> {
        fs::hard_link(self.path.join(from), self.path.join(to))
    }

    pub(super) fn unlink(&self, name: &str) -> io::Result<()> {
        fs::remove_file(self.path.join(name))
    }

    pub(super) fn sync(&self) {}
}

pub(super) fn file_entry(file: &File) -> io::Result<Entry> {
    file.metadata().map(|metadata| entry(&metadata))
}
