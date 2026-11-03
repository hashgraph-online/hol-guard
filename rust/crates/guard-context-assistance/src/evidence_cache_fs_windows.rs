//! Windows counterpart of the private directory layer. Windows has no
//! `openat`, so every fixed name is joined to the directory's verified path,
//! and the volume file ID of the directory and of each opened file is
//! compared again after the open. No handle is kept on a directory: an open
//! directory handle would leave a removed directory pending until it closed.
//! NTFS journals directory entries, so there is no directory flush.
#[cfg(test)]
use super::access::boundary;
use super::access::Access;
use super::*;
use crate::broker_storage::{ancestry, handle_node, path_node, private_at, Node};
use guard_cigar_artifacts::host;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

const SHARE_ALL: u32 = 0x0001 | 0x0002 | 0x0004;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

pub(super) struct Directory {
    pub(super) path: PathBuf,
    identity: Node,
}
fn io(_: std::io::Error) -> RuntimeError {
    RuntimeError::ArtifactUnreadable
}
/// Names here are fixed by the store; refuse anything that is not one
/// plain entry name.
fn fixed(name: &str) -> Result<(), RuntimeError> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\', ':']) {
        return Err(RuntimeError::ScopeDenied);
    }
    Ok(())
}
/// SQLite on Windows holds `LockFileEx` byte ranges near offset 1 GiB, and
/// a whole-file exclusive lock conflicts with any of them. The lock lasts
/// as long as `file` stays open. A saved worker can outlive its Guard
/// parent after a crash; never remove its store.
pub(super) fn storage_owner(file: &File) -> Result<(), RuntimeError> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            Err(RuntimeError::Busy)
        }
        Err(_) => Err(RuntimeError::ArtifactUnreadable),
    }
}
/// The facts an in-place rewrite changes, for upgrade inventories.
pub(super) fn file_stamp(file: &File) -> Result<(String, u64, u64, u64, u32), RuntimeError> {
    let m = file.metadata().map_err(io)?;
    Ok((
        handle_node(file)?.to_hex(),
        m.file_size(),
        m.creation_time(),
        m.last_write_time(),
        m.file_attributes(),
    ))
}
impl Directory {
    pub(super) fn inspect(path: &Path) -> Result<Self, RuntimeError> {
        ancestry(path)?;
        if !host::is_canonical(path).map_err(io)? {
            return Err(RuntimeError::ScopeDenied);
        }
        let result = Self {
            path: path.into(),
            identity: path_node(path)?,
        };
        result.check()?;
        Ok(result)
    }
    /// Entry changes are already durable on NTFS.
    pub(super) fn sync(&self) -> Result<(), RuntimeError> {
        Ok(())
    }
    pub(super) fn check(&self) -> Result<(), RuntimeError> {
        ancestry(&self.path)?;
        let metadata = std::fs::symlink_metadata(&self.path).map_err(io)?;
        private_at(&self.path, &metadata, true)?;
        if path_node(&self.path)? != self.identity {
            return Err(RuntimeError::ContextStale);
        }
        Ok(())
    }
    /// The directory handed to the SDK's SQLite store, which on Windows
    /// accepts only a directory the user owns whose protected access list
    /// grants that user alone.
    pub(super) fn storage_child(&self, name: &str) -> Result<Self, RuntimeError> {
        fixed(name)?;
        self.check()?;
        guard_runtime_windows_process::create_owner_only_directory(&self.path.join(name))
            .map_err(io)?;
        self.child(name, false)
    }
    pub(super) fn child(&self, name: &str, create: bool) -> Result<Self, RuntimeError> {
        fixed(name)?;
        self.check()?;
        let path = self.path.join(name);
        if create {
            match std::fs::create_dir(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io(e)),
            }
        }
        let opened = host::open_unfollowed(&path).map_err(io)?;
        let metadata = opened.metadata().map_err(io)?;
        private_at(&path, &metadata, true)?;
        let result = Self {
            identity: handle_node(&opened)?,
            path,
        };
        drop(opened);
        self.check()?;
        result.check()?;
        Ok(result)
    }
    pub(super) fn names(&self, max: usize) -> Result<Vec<String>, RuntimeError> {
        self.check()?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&self.path).map_err(io)? {
            let entry = entry.map_err(io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| RuntimeError::ScopeDenied)?;
            if names.len() >= max {
                return Err(RuntimeError::ResourceLimit);
            }
            names.push(name);
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
        fixed(name)?;
        self.check()?;
        let mut options = OpenOptions::new();
        match access {
            Access::Read => options.read(true),
            Access::Write => options.read(true).write(true),
            Access::WriteOrCreate => options.read(true).write(true).create(true),
            Access::CreateNew => options.write(true).create_new(true),
        };
        // Other handles may rename or remove the name while this one is
        // open; every use compares the file ID again.
        let file = options
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))
            .map_err(io)?;
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
        let path = self.path.join(name);
        let opened = file.metadata().map_err(io)?;
        private_at(&path, &opened, false)?;
        if handle_node(file)? != path_node(&path)? {
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
            || before.last_write_time() != after.last_write_time()
            || before.creation_time() != after.creation_time()
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
        std::fs::rename(self.path.join("state.next"), self.path.join("state.json"))
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)?;
        #[cfg(test)]
        boundary(2)?;
        self.check_file("state.json", &file, limit)
            .map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
    pub(super) fn remove_file(&self, name: &str, limit: u64) -> Result<(), RuntimeError> {
        let file = self.open_file(name, Access::Read, limit)?;
        self.check_file(name, &file, limit)?;
        // Close first so the name goes away now rather than when the last
        // handle closes.
        drop(file);
        std::fs::remove_file(self.path.join(name)).map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
    pub(super) fn remove_child(&self, name: &str, child: &Directory) -> Result<(), RuntimeError> {
        self.check()?;
        child.check()?;
        if child.path != self.path.join(name) || !child.names(1)?.is_empty() {
            return Err(RuntimeError::ScopeDenied);
        }
        std::fs::remove_dir(&child.path).map_err(|_| RuntimeError::StorageOutcomeUnknown)
    }
}
