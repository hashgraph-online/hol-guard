//! The directory-relative file operations the config writer lane needs.
//!
//! Unix resolves every name against a held directory descriptor and never
//! follows a final link. Windows has no `openat`, so a name is joined to the
//! directory's checked path, opened without following a reparse point, and
//! its volume file ID is compared again by the caller. Windows has no
//! permission bits: "private" there means owned by the current user (or by
//! LocalSystem or Administrators) and not a reparse point, and the read-only
//! attribute stands in for a file without its owner write bit.
use std::fs::File;
use std::io;

#[cfg(unix)]
pub(crate) type Node = (u64, u64);
#[cfg(windows)]
pub(crate) type Node = guard_runtime_windows_process::FileId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    File,
    Directory,
    Other,
}

#[derive(Clone, Copy)]
pub(super) enum How {
    Read,
    /// Write without truncating, to prove the existing object is writable.
    Write,
    /// Open or create the lane's lock file.
    Lock,
    CreateNew,
}

/// What a check needs to know about one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub(super) node: Node,
    pub(super) kind: Kind,
    pub(super) links: u64,
    pub(super) len: u64,
    /// Owned by the current user and closed to everyone else.
    pub(super) private: bool,
    /// Owned by the current user and writable by no one else.
    pub(super) guarded: bool,
    /// The owner may write it.
    pub(super) writable: bool,
    /// The times a same-user rewrite changes.
    pub(super) times: (i64, i64, i64, i64),
}

impl Entry {
    /// A private regular file with exactly one name.
    pub(super) fn private_file(&self) -> bool {
        self.kind == Kind::File && self.links == 1 && self.private
    }
    /// A private directory.
    pub(super) fn private_directory(&self) -> bool {
        self.kind == Kind::Directory && self.private
    }
}

pub(super) enum Names {
    Limit,
    Failed,
}

pub(super) use imp::{lock, Dir, Locked};

#[cfg(unix)]
mod imp {
    use super::*;
    use nix::fcntl::{open, openat, renameat, AtFlags, Flock, FlockArg, OFlag};
    use nix::sys::stat::{fstatat, mkdirat, FileStat, Mode, SFlag};
    use nix::unistd::{geteuid, unlinkat, UnlinkatFlags};
    use std::fs::Metadata;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    pub(in super::super) type Locked = Flock<File>;

    pub(in super::super) fn lock(file: File) -> io::Result<Locked> {
        Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| e.into())
    }

    fn metadata_entry(m: &Metadata) -> Entry {
        let owned = m.uid() == geteuid().as_raw();
        Entry {
            node: (m.dev(), m.ino()),
            kind: if m.is_file() {
                Kind::File
            } else if m.is_dir() {
                Kind::Directory
            } else {
                Kind::Other
            },
            links: m.nlink(),
            len: m.len(),
            private: owned && m.mode() & 0o077 == 0,
            guarded: owned && m.mode() & 0o022 == 0,
            writable: m.mode() & 0o200 != 0,
            times: (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()),
        }
    }

    // FileStat field widths differ across Unix targets.
    #[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
    fn stat_entry(s: FileStat) -> Entry {
        let mode = s.st_mode as u32;
        let owned = s.st_uid == geteuid().as_raw();
        let format = SFlag::from_bits_truncate(s.st_mode) & SFlag::S_IFMT;
        Entry {
            node: (s.st_dev as u64, s.st_ino as u64),
            kind: if format == SFlag::S_IFREG {
                Kind::File
            } else if format == SFlag::S_IFDIR {
                Kind::Directory
            } else {
                Kind::Other
            },
            links: s.st_nlink as u64,
            len: u64::try_from(s.st_size).unwrap_or(u64::MAX),
            private: owned && mode & 0o077 == 0,
            guarded: owned && mode & 0o022 == 0,
            writable: mode & 0o200 != 0,
            times: (
                s.st_mtime as i64,
                s.st_mtime_nsec as i64,
                s.st_ctime as i64,
                s.st_ctime_nsec as i64,
            ),
        }
    }

    pub(in super::super) struct Dir(File);

    const DIRECTORY: OFlag = OFlag::O_RDONLY
        .union(OFlag::O_DIRECTORY)
        .union(OFlag::O_NOFOLLOW)
        .union(OFlag::O_CLOEXEC);

    impl Dir {
        pub(in super::super) fn open(path: &Path) -> io::Result<Self> {
            Ok(Self(open(path, DIRECTORY, Mode::empty())?.into()))
        }
        pub(in super::super) fn entry(&self) -> io::Result<Entry> {
            Ok(metadata_entry(&self.0.metadata()?))
        }
        pub(in super::super) fn stat(&self, name: &str) -> io::Result<Entry> {
            Ok(stat_entry(fstatat(
                &self.0,
                name,
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )?))
        }
        pub(in super::super) fn file_entry(&self, _name: &str, file: &File) -> io::Result<Entry> {
            Ok(metadata_entry(&file.metadata()?))
        }
        pub(in super::super) fn open_dir(&self, name: &str) -> io::Result<Self> {
            Ok(Self(
                openat(&self.0, name, DIRECTORY, Mode::empty())?.into(),
            ))
        }
        pub(in super::super) fn open_file(&self, name: &str, how: How) -> io::Result<File> {
            let flags = match how {
                How::Read => OFlag::O_RDONLY | OFlag::O_NONBLOCK,
                How::Write => OFlag::O_WRONLY | OFlag::O_NONBLOCK,
                How::Lock => OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NONBLOCK,
                How::CreateNew => OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            };
            let fd = openat(
                &self.0,
                name,
                flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )?;
            Ok(fd.into())
        }
        pub(in super::super) fn create_dir(&self, name: &str) -> io::Result<()> {
            Ok(mkdirat(&self.0, name, Mode::from_bits_truncate(0o700))?)
        }
        pub(in super::super) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            Ok(renameat(&self.0, from, &self.0, to)?)
        }
        /// Rename only when `to` does not exist.
        pub(in super::super) fn rename_new(&self, from: &str, to: &str) -> io::Result<()> {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                Ok(rustix::fs::renameat_with(
                    &self.0,
                    from,
                    &self.0,
                    to,
                    rustix::fs::RenameFlags::NOREPLACE,
                )?)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = (from, to);
                Err(io::ErrorKind::Unsupported.into())
            }
        }
        pub(in super::super) fn remove_file(&self, name: &str) -> io::Result<()> {
            Ok(unlinkat(&self.0, name, UnlinkatFlags::NoRemoveDir)?)
        }
        pub(in super::super) fn remove_dir(&self, name: &str) -> io::Result<()> {
            Ok(unlinkat(&self.0, name, UnlinkatFlags::RemoveDir)?)
        }
        pub(in super::super) fn sync(&self) -> io::Result<()> {
            self.0.sync_all()
        }
        pub(in super::super) fn names(&self, max: usize) -> Result<Vec<String>, Names> {
            let fd = openat(&self.0, ".", DIRECTORY, Mode::empty()).map_err(|_| Names::Failed)?;
            let mut dir = nix::dir::Dir::from_fd(fd).map_err(|_| Names::Failed)?;
            let mut names = Vec::new();
            for entry in dir.iter() {
                let entry = entry.map_err(|_| Names::Failed)?;
                let name = entry.file_name().to_str().map_err(|_| Names::Failed)?;
                if name == "." || name == ".." {
                    continue;
                }
                if names.len() >= max {
                    return Err(Names::Limit);
                }
                names.push(name.to_owned());
            }
            Ok(names)
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use guard_cigar_artifacts::host;
    use std::fs::{Metadata, OpenOptions};
    use std::ops::Deref;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};

    const SHARE_ALL: u32 = 0x0001 | 0x0002 | 0x0004;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    /// A whole-file `LockFileEx` lock, held while the file stays open.
    pub(in super::super) struct Locked(File);
    impl Deref for Locked {
        type Target = File;
        fn deref(&self) -> &File {
            &self.0
        }
    }

    pub(in super::super) fn lock(file: File) -> io::Result<Locked> {
        fs2::FileExt::try_lock_exclusive(&file)?;
        Ok(Locked(file))
    }

    fn changed() -> io::Error {
        io::Error::other("directory changed")
    }

    fn entry(path: &Path, file: &File, m: &Metadata) -> io::Result<Entry> {
        let reparse = host::reparse(m);
        let private = !reparse && host::owned(path);
        Ok(Entry {
            node: host::handle_node_id(file)?,
            kind: if reparse {
                Kind::Other
            } else if m.is_file() {
                Kind::File
            } else if m.is_dir() {
                Kind::Directory
            } else {
                Kind::Other
            },
            links: if m.is_file() && !guard_runtime_windows_process::is_single_link_handle(file)? {
                2
            } else {
                1
            },
            len: m.len(),
            private,
            guarded: private,
            writable: !host::read_only(m),
            times: (m.last_write_time() as i64, 0, m.creation_time() as i64, 0),
        })
    }

    fn path_entry(path: &Path) -> io::Result<Entry> {
        let file = host::open_unfollowed(path)?;
        entry(path, &file, &file.metadata()?)
    }

    /// No handle is kept on the directory: a held handle would leave a
    /// removed directory pending until it closed. Each use re-checks the
    /// directory's file ID instead.
    pub(in super::super) struct Dir {
        path: PathBuf,
        node: Node,
    }

    impl Dir {
        fn join(&self, name: &str) -> io::Result<PathBuf> {
            if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\', ':']) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            Ok(self.path.join(name))
        }
        fn at(path: PathBuf) -> io::Result<Self> {
            let found = path_entry(&path)?;
            if found.kind != Kind::Directory {
                return Err(changed());
            }
            Ok(Self {
                path,
                node: found.node,
            })
        }
        pub(in super::super) fn open(path: &Path) -> io::Result<Self> {
            Self::at(path.to_path_buf())
        }
        pub(in super::super) fn entry(&self) -> io::Result<Entry> {
            let found = path_entry(&self.path)?;
            if found.node != self.node {
                return Err(changed());
            }
            Ok(found)
        }
        pub(in super::super) fn stat(&self, name: &str) -> io::Result<Entry> {
            self.entry()?;
            path_entry(&self.join(name)?)
        }
        pub(in super::super) fn file_entry(&self, name: &str, file: &File) -> io::Result<Entry> {
            self.entry()?;
            entry(&self.join(name)?, file, &file.metadata()?)
        }
        pub(in super::super) fn open_dir(&self, name: &str) -> io::Result<Self> {
            self.entry()?;
            Self::at(self.join(name)?)
        }
        pub(in super::super) fn open_file(&self, name: &str, how: How) -> io::Result<File> {
            let path = self.join(name)?;
            self.entry()?;
            let mut options = OpenOptions::new();
            match how {
                How::Read => options.read(true),
                How::Write => options.write(true),
                How::Lock => options.read(true).write(true).create(true),
                How::CreateNew => options.write(true).create_new(true),
            };
            // Callers compare the opened file's ID with the name's.
            options
                .share_mode(SHARE_ALL)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
        }
        pub(in super::super) fn create_dir(&self, name: &str) -> io::Result<()> {
            self.entry()?;
            std::fs::create_dir(self.join(name)?)
        }
        pub(in super::super) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            self.entry()?;
            std::fs::rename(self.join(from)?, self.join(to)?)
        }
        /// Rename only when `to` does not exist.
        pub(in super::super) fn rename_new(&self, from: &str, to: &str) -> io::Result<()> {
            self.entry()?;
            guard_runtime_windows_process::rename_no_replace(&self.join(from)?, &self.join(to)?)
        }
        pub(in super::super) fn remove_file(&self, name: &str) -> io::Result<()> {
            self.entry()?;
            std::fs::remove_file(self.join(name)?)
        }
        pub(in super::super) fn remove_dir(&self, name: &str) -> io::Result<()> {
            self.entry()?;
            std::fs::remove_dir(self.join(name)?)
        }
        /// NTFS journals directory entries; there is no directory flush.
        pub(in super::super) fn sync(&self) -> io::Result<()> {
            self.entry().map(|_| ())
        }
        pub(in super::super) fn names(&self, max: usize) -> Result<Vec<String>, Names> {
            self.entry().map_err(|_| Names::Failed)?;
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&self.path).map_err(|_| Names::Failed)? {
                let entry = entry.map_err(|_| Names::Failed)?;
                let name = entry.file_name().into_string().map_err(|_| Names::Failed)?;
                if names.len() >= max {
                    return Err(Names::Limit);
                }
                names.push(name);
            }
            Ok(names)
        }
    }
}
