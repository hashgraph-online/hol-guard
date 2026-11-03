//! Descriptor-relative snapshot traversal for Unix.

use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{openat, readlinkat, AtFlags, OFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode};

use super::{HashError, Kind, Node};

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

pub(crate) struct DirHandle {
    dir: Dir,
}

impl DirHandle {
    /// Open the canonical root itself; it must not be a symlink.
    pub(crate) fn open_root(path: &Path) -> Option<Self> {
        Dir::open(path, directory_flags(), Mode::empty())
            .ok()
            .map(|dir| Self { dir })
    }

    /// Entry names in readdir order; a trailing `None` marks where readdir
    /// failed. Reading stops at the first error, since `nix`'s iterator calls
    /// readdir again on every `next` and a persistent error would never end.
    pub(crate) fn names(&mut self) -> Vec<Option<OsString>> {
        let mut names = Vec::new();
        for entry in self.dir.iter() {
            match entry {
                Ok(entry) => {
                    let name = entry.file_name().to_bytes();
                    if name != b"." && name != b".." {
                        names.push(Some(OsStr::from_bytes(name).to_owned()));
                    }
                }
                Err(_) => {
                    names.push(None);
                    break;
                }
            }
        }
        names
    }

    pub(crate) fn stat(&self, name: &OsStr) -> Option<Node> {
        fstatat(&self.dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .ok()
            .map(|stat| stat_node(&stat))
    }

    /// Open a child directory without following it, and only when it is the
    /// directory `seen` describes.
    pub(crate) fn open_dir(&self, name: &OsStr, seen: &Node) -> Result<Self, HashError> {
        let dir =
            Dir::openat(&self.dir, name, directory_flags(), Mode::empty()).map_err(|error| {
                match error {
                    Errno::ELOOP | Errno::ENOTDIR | Errno::ENOENT => HashError::Unstable,
                    _ => HashError::Unreadable,
                }
            })?;
        let opened = fstat(&dir).map_err(|_| HashError::Unreadable)?;
        if !stat_node(&opened).same_object(seen) {
            return Err(HashError::Unstable);
        }
        Ok(Self { dir })
    }

    pub(crate) fn open_file(&self, name: &OsStr) -> Option<File> {
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        openat(&self.dir, name, flags, Mode::empty())
            .ok()
            .map(File::from)
    }

    pub(crate) fn read_link(&self, name: &OsStr) -> Option<OsString> {
        readlinkat(&self.dir, name).ok()
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
        len: metadata.size(),
        mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
        ino: metadata.ino(),
        dev: metadata.dev(),
    }
}

// `dev_t`, `ino_t` and `off_t` differ in width and sign across Unix targets;
// these casts match what `std::os::unix::fs::MetadataExt` reports so a
// descriptor's `fstat` and an entry's `fstatat` compare equal.
#[allow(clippy::unnecessary_cast)]
fn stat_node(stat: &FileStat) -> Node {
    let format = stat.st_mode & libc::S_IFMT;
    Node {
        kind: if format == libc::S_IFLNK {
            Kind::Symlink
        } else if format == libc::S_IFDIR {
            Kind::Directory
        } else if format == libc::S_IFREG {
            Kind::File
        } else {
            Kind::Special
        },
        len: stat.st_size as u64,
        mtime_ns: i128::from(stat.st_mtime) * 1_000_000_000 + i128::from(stat.st_mtime_nsec),
        ino: stat.st_ino as u64,
        dev: stat.st_dev as u64,
    }
}
