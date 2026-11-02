//! Private, pinned directories. Mutations use relative descriptors and fixed
//! names; no recursive deletion or permission repair is performed here.
use super::*;
use crate::broker_storage::{ancestry, private};
use nix::fcntl::{openat, renameat, AtFlags, OFlag};
use nix::sys::stat::{fstatat, mkdirat, Mode};
use nix::unistd::{unlinkat, UnlinkatFlags};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub(super) struct Directory {
    pub(super) path: PathBuf,
    pub(super) file: File,
    identity: (u64, u64),
}
fn io(_: std::io::Error) -> RuntimeError {
    RuntimeError::ArtifactUnreadable
}
fn os(_: nix::errno::Errno) -> RuntimeError {
    RuntimeError::ArtifactUnreadable
}
fn identity(m: &Metadata) -> (u64, u64) {
    (m.dev(), m.ino())
}
/// SQLite's exclusive owner uses POSIX byte-range locks, not flock. A saved
/// worker can outlive its Guard parent after a crash; never unlink its store.
pub(super) fn storage_owner(file: &File) -> Result<(), RuntimeError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let lock = nix::libc::flock {
            l_start: 0,
            l_len: 0,
            l_pid: 0,
            l_type: nix::libc::F_WRLCK as _,
            l_whence: nix::libc::SEEK_SET as _,
        };
        match nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_SETLK(&lock)) {
            Ok(_) => Ok(()),
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EACCES) => Err(RuntimeError::Busy),
            Err(_) => Err(RuntimeError::ArtifactUnreadable),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        Err(RuntimeError::PlatformUnqualified)
    }
}
#[cfg(test)]
use super::access::boundary;
use super::access::Access;
#[cfg(test)]
pub(super) use super::access::WRITE_FAULT;
fn flags(access: Access) -> OFlag {
    match access {
        Access::Read => OFlag::O_RDONLY,
        Access::Write => OFlag::O_RDWR,
        Access::WriteOrCreate => OFlag::O_RDWR | OFlag::O_CREAT,
        Access::CreateNew => OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
    }
}
/// The metadata an in-place rewrite changes, for upgrade inventories.
#[allow(clippy::type_complexity)]
pub(super) fn file_stamp(file: &File) -> Result<(u64, u64, u64, i64, i64, i64, i64), RuntimeError> {
    let m = file.metadata().map_err(io)?;
    Ok((
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    ))
}
impl Directory {
    pub(super) fn inspect(path: &Path) -> Result<Self, RuntimeError> {
        ancestry(path)?;
        if path.canonicalize().map_err(io)? != path {
            return Err(RuntimeError::ScopeDenied);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
            .open(path)
            .map_err(io)?;
        let metadata = file.metadata().map_err(io)?;
        private(&metadata, true)?;
        let result = Self {
            path: path.into(),
            file,
            identity: identity(&metadata),
        };
        result.check()?;
        Ok(result)
    }
    /// Make entry changes in this directory durable.
    pub(super) fn sync(&self) -> Result<(), RuntimeError> {
        self.file
            .sync_all()
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
    pub(super) fn check(&self) -> Result<(), RuntimeError> {
        ancestry(&self.path)?;
        for m in [
            self.file.metadata().map_err(io)?,
            std::fs::symlink_metadata(&self.path).map_err(io)?,
        ] {
            private(&m, true)?;
            if identity(&m) != self.identity {
                return Err(RuntimeError::ContextStale);
            }
        }
        Ok(())
    }
    /// The directory handed to the SDK's SQLite store.
    pub(super) fn storage_child(&self, name: &str) -> Result<Self, RuntimeError> {
        self.child(name, true)
    }
    pub(super) fn child(&self, name: &str, create: bool) -> Result<Self, RuntimeError> {
        self.check()?;
        if create {
            match mkdirat(&self.file, name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => self
                    .file
                    .sync_all()
                    .map_err(|_| RuntimeError::StorageOutcomeUnknown)?,
                Err(nix::errno::Errno::EEXIST) => {}
                Err(e) => return Err(os(e)),
            }
        }
        let file: File = openat(
            &self.file,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(os)?
        .into();
        let m = file.metadata().map_err(io)?;
        private(&m, true)?;
        let result = Self {
            path: self.path.join(name),
            file,
            identity: identity(&m),
        };
        self.check()?;
        result.check()?;
        Ok(result)
    }
    pub(super) fn names(&self, max: usize) -> Result<Vec<String>, RuntimeError> {
        self.check()?;
        let fd = openat(
            &self.file,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(os)?;
        let mut dir = nix::dir::Dir::from_fd(fd).map_err(os)?;
        let mut names = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(os)?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| RuntimeError::ScopeDenied)?;
            if matches!(name, "." | "..") {
                continue;
            }
            if names.len() >= max {
                return Err(RuntimeError::ResourceLimit);
            }
            names.push(name.into());
        }
        self.check()?;
        Ok(names)
    }
    pub(super) fn open_file(
        &self,
        name: &str,
        access: Access,
        limit: u64,
    ) -> Result<File, RuntimeError> {
        self.check()?;
        let file: File = openat(
            &self.file,
            name,
            flags(access) | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(os)?
        .into();
        self.check_file(name, &file, limit)?;
        Ok(file)
    }
    pub(super) fn check_file(
        &self,
        name: &str,
        file: &File,
        limit: u64,
    ) -> Result<(), RuntimeError> {
        self.check()?;
        let opened = file.metadata().map_err(io)?;
        private(&opened, false)?;
        let named = fstatat(&self.file, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(os)?;
        #[allow(clippy::unnecessary_cast)] // dev_t differs between Unix targets.
        let named_device = named.st_dev as u64;
        if opened.dev() != named_device || opened.ino() != named.st_ino {
            return Err(RuntimeError::ContextStale);
        }
        if opened.len() > limit {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }
    pub(super) fn read(&self, name: &str) -> Result<Vec<u8>, RuntimeError> {
        self.read_limit(name, STATE_BYTES)
    }
    pub(super) fn read_limit(&self, name: &str, limit: u64) -> Result<Vec<u8>, RuntimeError> {
        let file = self.open_file(name, Access::Read, limit)?;
        let before = file.metadata().map_err(io)?;
        let mut data = Vec::new();
        (&file).take(limit + 1).read_to_end(&mut data).map_err(io)?;
        self.check_file(name, &file, limit)?;
        let after = file.metadata().map_err(io)?;
        if data.len() as u64 != after.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(RuntimeError::ContextStale);
        }
        Ok(data)
    }
    pub(super) fn write_state(&self, data: &[u8]) -> Result<(), RuntimeError> {
        self.write_state_limit(data, STATE_BYTES)
    }
    pub(super) fn write_state_limit(&self, data: &[u8], limit: u64) -> Result<(), RuntimeError> {
        if data.len() as u64 > limit {
            return Err(RuntimeError::ResourceLimit);
        }
        let names = self.names(4)?;
        if names.iter().any(|n| n == "state.next") {
            self.remove_file("state.next", limit)?;
        }
        if names.iter().any(|n| n == "state.json") {
            self.open_file("state.json", Access::Read, limit)?;
        }
        let mut file = self.open_file("state.next", Access::CreateNew, limit)?;
        file.write_all(data).map_err(io)?;
        file.sync_all().map_err(io)?;
        self.check_file("state.next", &file, limit)?;
        #[cfg(test)]
        boundary(1)?;
        renameat(&self.file, "state.next", &self.file, "state.json")
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
        #[cfg(test)]
        boundary(2)?;
        self.file
            .sync_all()
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
        self.check_file("state.json", &file, limit)
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
    pub(super) fn remove_file(&self, name: &str, limit: u64) -> Result<(), RuntimeError> {
        let file = self.open_file(name, Access::Read, limit)?;
        self.check_file(name, &file, limit)?;
        unlinkat(&self.file, name, UnlinkatFlags::NoRemoveDir)
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
        self.file
            .sync_all()
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
    pub(super) fn remove_child(&self, name: &str, child: &Directory) -> Result<(), RuntimeError> {
        self.check()?;
        child.check()?;
        if child.path != self.path.join(name) || !child.names(1)?.is_empty() {
            return Err(RuntimeError::ScopeDenied);
        }
        unlinkat(&self.file, name, UnlinkatFlags::RemoveDir)
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
        self.file
            .sync_all()
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
}
