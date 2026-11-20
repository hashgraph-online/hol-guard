//! Descriptor-relative directory access for manifest fixes on Unix.
//!
//! Every directory below the root is opened with `O_NOFOLLOW` relative to the
//! descriptor of its parent, and every name is resolved relative to a held
//! descriptor, so swapping a parent directory for a symlink after the walk
//! started cannot move a read or a write outside the root.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, fstatat, FileStat, Mode};
use nix::unistd::{fsync, linkat, unlinkat, UnlinkatFlags};

use super::{Code, Entry, Kind};

pub(super) const REPLACE_SUPPORTED: bool = true;

pub(super) struct Dir {
    fd: OwnedFd,
}

fn directory_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

fn io_error(errno: Errno) -> io::Error {
    io::Error::from_raw_os_error(errno as i32)
}

// `dev_t`, `ino_t` and `off_t` differ in width and sign across Unix targets.
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn entry(stat: &FileStat) -> Entry {
    let format = stat.st_mode & libc::S_IFMT;
    Entry {
        kind: if format == libc::S_IFLNK {
            Kind::Symlink
        } else if format == libc::S_IFDIR {
            Kind::Directory
        } else if format == libc::S_IFREG {
            Kind::File
        } else {
            Kind::Other
        },
        len: stat.st_size as u64,
        mode: u32::from(stat.st_mode & 0o7777),
        id: (stat.st_dev as u64, stat.st_ino as u64),
    }
}

impl Dir {
    /// Open the canonical root itself; it must not be a symlink.
    pub(super) fn open_root(path: &Path) -> Result<Self, Code> {
        open(path, directory_flags(), Mode::empty())
            .map(|fd| Self { fd })
            .map_err(|_| "manifest_root_unavailable")
    }

    pub(super) fn open_child(&self, name: &str) -> Result<Self, Code> {
        openat(&self.fd, name, directory_flags(), Mode::empty())
            .map(|fd| Self { fd })
            .map_err(|error| match error {
                Errno::ENOENT => "manifest_missing",
                Errno::ELOOP | Errno::ENOTDIR => "manifest_path_invalid",
                _ => "manifest_unreadable",
            })
    }

    /// What `name` is, without following it.
    pub(super) fn stat(&self, name: &str) -> io::Result<Entry> {
        fstatat(&self.fd, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map(|stat| entry(&stat))
            .map_err(io_error)
    }

    pub(super) fn open_read(&self, name: &str) -> io::Result<File> {
        let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        openat(&self.fd, name, flags, Mode::empty())
            .map(File::from)
            .map_err(io_error)
    }

    /// A new file that must not exist yet, private until its mode is set.
    pub(super) fn create_new(&self, name: &str) -> io::Result<File> {
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        openat(&self.fd, name, flags, Mode::from_bits_truncate(0o600))
            .map(File::from)
            .map_err(io_error)
    }

    // `mode_t` is 16 bits on macOS and 32 on Linux, so the widening is a no-op on one.
    #[allow(clippy::useless_conversion)]
    pub(super) fn set_mode(&self, file: &File, mode: u32) -> io::Result<()> {
        let bits = u16::try_from(mode & 0o7777).unwrap_or(0o600);
        fchmod(file, Mode::from_bits_truncate(bits.into())).map_err(io_error)
    }

    pub(super) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        renameat(&self.fd, from, &self.fd, to).map_err(io_error)
    }

    /// Hard-link `from` as `to`; fails with `AlreadyExists` instead of replacing.
    pub(super) fn link_new(&self, from: &str, to: &str) -> io::Result<()> {
        linkat(&self.fd, from, &self.fd, to, AtFlags::empty()).map_err(io_error)
    }

    pub(super) fn unlink(&self, name: &str) -> io::Result<()> {
        unlinkat(&self.fd, name, UnlinkatFlags::NoRemoveDir).map_err(io_error)
    }

    pub(super) fn sync(&self) {
        let _ = fsync(&self.fd);
    }
}

pub(super) fn file_entry(file: &File) -> io::Result<Entry> {
    fstat(file).map(|stat| entry(&stat)).map_err(io_error)
}
