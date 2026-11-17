//! The failure log's directory, opened once and used by name from then on.
//!
//! On Unix the Guard home and its `logs` directory are each opened without
//! following a link, and every later open, size check and rename goes through
//! the `logs` descriptor. A process that swaps `logs` for a symlink after the
//! directory was opened cannot redirect a record. Every file is opened
//! without following a link and without waiting on a FIFO, kept only if it
//! is a regular file, and made owner-only before anything is written to it.

use std::fs::File;
use std::path::Path;

pub(super) struct LogDirectory(imp::Directory);

impl LogDirectory {
    /// Opens `<guard_home>/<name>`, creating it owner-only when missing.
    pub(super) fn open(guard_home: &Path, name: &str) -> Option<Self> {
        imp::Directory::open(guard_home, name).map(Self)
    }

    /// Opens or creates `name` for writing; `append` selects append mode.
    pub(super) fn open_file(&self, name: &str, append: bool) -> Option<File> {
        self.0.open_file(name, append)
    }

    /// The size of `name`, when it is a regular file.
    pub(super) fn file_len(&self, name: &str) -> Option<u64> {
        self.0.file_len(name)
    }

    /// Renames `from` to `to`, both inside this directory.
    pub(super) fn rename(&self, from: &str, to: &str) -> Option<()> {
        self.0.rename(from, to)
    }
}

#[cfg(unix)]
mod imp {
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::path::Path;

    use nix::errno::Errno;
    use nix::fcntl::{open, openat, renameat, AtFlags, OFlag};
    use nix::sys::stat::{fchmod, fstat, fstatat, mkdirat, FileStat, Mode, SFlag};

    pub(super) struct Directory(OwnedFd);

    fn directory_flags() -> OFlag {
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
    }

    fn private() -> Mode {
        Mode::S_IRUSR | Mode::S_IWUSR
    }

    fn is_regular(metadata: &FileStat) -> bool {
        SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT == SFlag::S_IFREG
    }

    impl Directory {
        pub(super) fn open(guard_home: &Path, name: &str) -> Option<Self> {
            let home = open(guard_home, directory_flags(), Mode::empty()).ok()?;
            match mkdirat(&home, name, Mode::S_IRWXU) {
                Ok(()) | Err(Errno::EEXIST) => {}
                Err(_) => return None,
            }
            openat(&home, name, directory_flags(), Mode::empty())
                .ok()
                .map(Self)
        }

        pub(super) fn open_file(&self, name: &str, append: bool) -> Option<File> {
            let mut flags = OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_NOCTTY
                | OFlag::O_CLOEXEC;
            if append {
                flags |= OFlag::O_APPEND;
            }
            let file: File = openat(&self.0, name, flags, private()).ok()?.into();
            let metadata = fstat(&file).ok()?;
            if !is_regular(&metadata) {
                return None;
            }
            // The creation mode does not reach a file that already existed,
            // so an existing log someone widened is narrowed before use.
            if metadata.st_mode & 0o077 != 0 {
                fchmod(&file, private()).ok()?;
            }
            Some(file)
        }

        pub(super) fn file_len(&self, name: &str) -> Option<u64> {
            let metadata = fstatat(&self.0, name, AtFlags::AT_SYMLINK_NOFOLLOW).ok()?;
            is_regular(&metadata).then(|| u64::try_from(metadata.st_size).ok())?
        }

        pub(super) fn rename(&self, from: &str, to: &str) -> Option<()> {
            renameat(&self.0, from, &self.0, to).ok()
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};

    pub(super) struct Directory(PathBuf);

    fn is_symlink(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    }

    impl Directory {
        pub(super) fn open(guard_home: &Path, name: &str) -> Option<Self> {
            if !guard_home.is_dir() || is_symlink(guard_home) {
                return None;
            }
            let directory = guard_home.join(name);
            match fs::create_dir(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }
            (!is_symlink(&directory) && directory.is_dir()).then_some(Self(directory))
        }

        pub(super) fn open_file(&self, name: &str, append: bool) -> Option<File> {
            let path = self.0.join(name);
            if is_symlink(&path) {
                return None;
            }
            let mut options = OpenOptions::new();
            options.write(true).create(true).append(append);
            let file = options.open(path).ok()?;
            file.metadata()
                .is_ok_and(|metadata| metadata.is_file())
                .then_some(file)
        }

        pub(super) fn file_len(&self, name: &str) -> Option<u64> {
            let metadata = fs::symlink_metadata(self.0.join(name)).ok()?;
            metadata.is_file().then(|| metadata.len())
        }

        pub(super) fn rename(&self, from: &str, to: &str) -> Option<()> {
            let target = self.0.join(to);
            if is_symlink(&target) {
                return None;
            }
            fs::rename(self.0.join(from), target).ok()
        }
    }
}
