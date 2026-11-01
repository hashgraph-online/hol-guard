//! Support files on Unix: every operation is relative to the support
//! directory's descriptor, which was opened without following a link.

use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{openat, renameat, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{fsync, unlinkat, UnlinkatFlags};

use super::{
    changed, failed, non_directory, non_regular, prepare_directory, read_opened, temporary_name,
    BeforeCommit, ExistingFile, FileState, DEFAULT_MODE,
};

/// Device and inode.
pub(super) type Identity = (u64, u64);

pub(super) fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

pub(super) struct SupportDirectory {
    directory: File,
}

impl SupportDirectory {
    pub(super) fn open(path: &Path) -> Result<Self, String> {
        prepare_directory(path)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| match error.raw_os_error() {
                Some(libc::ELOOP | libc::ENOTDIR) => non_directory(path),
                _ => failed(&super::directory_name(path), &error),
            })?;
        Ok(Self { directory })
    }

    pub(super) fn read(&self, name: &str) -> Result<Option<ExistingFile>, String> {
        let flags = OFlag::O_RDONLY
            | OFlag::O_CLOEXEC
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_NOCTTY;
        let file: File = match openat(&self.directory, name, flags, Mode::empty()) {
            Ok(fd) => fd.into(),
            Err(Errno::ENOENT) => return Ok(None),
            Err(Errno::ELOOP) => return Err(non_regular(name)),
            Err(error) => return Err(failed(name, &error)),
        };
        let metadata = file.metadata().map_err(|error| failed(name, &error))?;
        let identity = (metadata.dev(), metadata.ino());
        let mode = metadata.mode() & 0o7777;
        read_opened(file, &metadata, name, identity, mode).map(Some)
    }

    /// Replace `name` with `text` through a new owner-only temporary file,
    /// keeping the mode it had, unless it changed since `existing` was read.
    pub(super) fn write(
        &self,
        name: &str,
        text: &str,
        existing: Option<&ExistingFile>,
        before_commit: BeforeCommit<'_>,
    ) -> Result<(), String> {
        let temporary = temporary_name(name)?;
        let flags =
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
        let file: File = openat(
            &self.directory,
            temporary.as_str(),
            flags,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| failed(&temporary, &error))?
        .into();
        let mode = existing.map_or(DEFAULT_MODE, |file| file.mode);
        let committed = fill(file, text, mode)
            .map_err(|error| failed(&temporary, &error))
            .and_then(|()| {
                before_commit(name);
                self.assert_unchanged(name, existing.map(|file| &file.state))?;
                renameat(&self.directory, temporary.as_str(), &self.directory, name)
                    .map_err(|error| failed(name, &error))?;
                fsync(&self.directory).map_err(|error| failed(name, &error))
            });
        let _ = unlinkat(
            &self.directory,
            temporary.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
        committed
    }

    pub(super) fn unlink(&self, name: &str, expected: &FileState) -> Result<(), String> {
        self.assert_unchanged(name, Some(expected))?;
        unlinkat(&self.directory, name, UnlinkatFlags::NoRemoveDir)
            .map_err(|error| failed(name, &error))?;
        fsync(&self.directory).map_err(|error| failed(name, &error))
    }

    fn assert_unchanged(&self, name: &str, expected: Option<&FileState>) -> Result<(), String> {
        let current = self.read(name)?;
        if current.as_ref().map(|file| &file.state) != expected {
            return Err(changed(name));
        }
        Ok(())
    }
}

fn fill(mut file: File, text: &str, mode: u32) -> std::io::Result<()> {
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    file.set_permissions(Permissions::from_mode(mode))
}
