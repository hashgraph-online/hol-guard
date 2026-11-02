//! Native-only directory capability for the SDK's bounded evidence store.
//! Product callers must derive it from their private Guard data root. It
//! carries no restored grant, source permission or execution authority.
use crate::RuntimeError;
use serde_json::{json, Value};
use std::fs::File;
use std::path::{Path, PathBuf};

const CHECKPOINT_BYTES: u64 = 12 * 1024 * 1024;
const DATABASE_BYTES: u64 = 32 * 1024 * 1024;

/// The `(dev, ino)` pair on Unix; the volume and file ID on Windows.
#[cfg(unix)]
pub(crate) type Node = (u64, u64);
#[cfg(windows)]
pub(crate) type Node = guard_cigar_artifacts::host::FileId;

pub struct BrokerStorage {
    directory: PathBuf,
    pub(crate) cache_owner: Option<std::sync::Arc<dyn Send + Sync>>,
    opened: File,
    database: Option<File>,
    identity: Node,
}
impl BrokerStorage {
    pub fn inspect(directory: &Path) -> Result<Self, RuntimeError> {
        ancestry(directory)?;
        if !guard_cigar_artifacts::host::is_canonical(directory).map_err(unavailable)? {
            return Err(RuntimeError::ScopeDenied);
        }
        let metadata = std::fs::symlink_metadata(directory).map_err(unavailable)?;
        private_at(directory, &metadata, true)?;
        let opened = open_directory(directory)?;
        let identity = path_node(directory)?;
        if handle_node(&opened)? != identity {
            return Err(RuntimeError::ContextStale);
        }
        let mut result = Self {
            directory: directory.into(),
            cache_owner: None,
            opened,
            database: None,
            identity,
        };
        result.revalidate()?;
        if result.existed()? {
            result.seal()?;
        }
        Ok(result)
    }
    pub fn revalidate(&self) -> Result<(), RuntimeError> {
        ancestry(&self.directory)?;
        let metadata = std::fs::symlink_metadata(&self.directory).map_err(unavailable)?;
        private_at(&self.directory, &metadata, true)?;
        if path_node(&self.directory)? != self.identity
            || handle_node(&self.opened)? != self.identity
        {
            return Err(RuntimeError::ContextStale);
        }
        for entry in std::fs::read_dir(&self.directory).map_err(unavailable)? {
            let entry = entry.map_err(unavailable)?;
            let name = entry.file_name();
            let limit = if name == "broker.sqlite3" {
                DATABASE_BYTES
            } else if name == "broker.sqlite3-journal" {
                DATABASE_BYTES + 1024 * 1024
            } else {
                return Err(RuntimeError::ScopeDenied);
            };
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(unavailable)?;
            private_at(&entry.path(), &metadata, false)?;
            if metadata.len() > limit {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        if let Some(opened) = &self.database {
            let path = self.directory.join("broker.sqlite3");
            let after = std::fs::symlink_metadata(&path).map_err(unavailable)?;
            private_at(&path, &after, false)?;
            if handle_node(opened)? != path_node(&path)? {
                return Err(RuntimeError::ContextStale);
            }
        }
        Ok(())
    }
    pub(crate) fn matches_directory(&self, path: &Path) -> Result<bool, RuntimeError> {
        self.revalidate()?;
        Ok(self.directory == path)
    }
    pub(crate) fn seal(&mut self) -> Result<(), RuntimeError> {
        self.revalidate()?;
        if self.database.is_none() {
            let path = self.directory.join("broker.sqlite3");
            let file = open_unfollowed_file(&path)?;
            let metadata = file.metadata().map_err(unavailable)?;
            private_at(&path, &metadata, false)?;
            if metadata.len() == 0 {
                return Err(RuntimeError::ContextStale);
            }
            self.database = Some(file);
        }
        self.revalidate()
    }
    pub(crate) fn existed(&self) -> Result<bool, RuntimeError> {
        self.revalidate()?;
        match std::fs::symlink_metadata(self.directory.join("broker.sqlite3")) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(unavailable(e)),
        }
    }
    pub(crate) fn wire(&self) -> Value {
        json!({"directory":self.directory,"create_directory":false,"max_checkpoint_bytes":CHECKPOINT_BYTES,
            "max_database_bytes":DATABASE_BYTES,"max_journal_records":64})
    }
}
#[cfg(unix)]
pub(crate) fn private(metadata: &std::fs::Metadata, directory: bool) -> Result<(), RuntimeError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700
        } else {
            !metadata.is_file() || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1
        }
    {
        return Err(RuntimeError::ScopeDenied);
    }
    Ok(())
}
#[cfg(unix)]
pub(crate) fn ancestry(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.components().any(|p| {
            !matches!(
                p,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(RuntimeError::ScopeDenied);
    }
    let uid = nix::unistd::geteuid().as_raw();
    for parent in path.ancestors() {
        let m = std::fs::symlink_metadata(parent).map_err(unavailable)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != 0 && m.uid() != uid)
            || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
        {
            return Err(RuntimeError::ScopeDenied);
        }
    }
    Ok(())
}
/// Whether `path` is private to this user: a directory or a single-name
/// regular file the user owns, never a link. Unix also requires mode 0700
/// or 0600; Windows has no mode bits, and the Guard home's own access list
/// covers what is created below it.
pub(crate) fn private_at(
    path: &Path,
    metadata: &std::fs::Metadata,
    directory: bool,
) -> Result<(), RuntimeError> {
    #[cfg(unix)]
    {
        let _ = path;
        private(metadata, directory)
    }
    #[cfg(windows)]
    {
        use guard_cigar_artifacts::host;
        let private = if directory {
            host::private_directory(path, metadata)
        } else {
            host::private_file(path, metadata)
        };
        if private {
            Ok(())
        } else {
            Err(RuntimeError::ScopeDenied)
        }
    }
}
#[cfg(windows)]
pub(crate) fn ancestry(path: &Path) -> Result<(), RuntimeError> {
    use std::path::Component;
    // Windows protects an ancestry with access lists rather than owner and
    // mode bits, and a system drive root is owned by TrustedInstaller.
    // What can redirect a path is a link or junction, so refuse any.
    if !path.is_absolute()
        || path.components().any(|p| {
            !matches!(
                p,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
    {
        return Err(RuntimeError::ScopeDenied);
    }
    for parent in path.ancestors() {
        if parent.parent().is_none() {
            continue;
        }
        let m = std::fs::symlink_metadata(parent).map_err(unavailable)?;
        if !m.is_dir() || guard_cigar_artifacts::host::reparse(&m) {
            return Err(RuntimeError::ScopeDenied);
        }
    }
    Ok(())
}
/// The identity of `path` itself, never a link's target.
pub(crate) fn path_node(path: &Path) -> Result<Node, RuntimeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(path).map_err(unavailable)?;
        Ok((m.dev(), m.ino()))
    }
    #[cfg(windows)]
    {
        guard_cigar_artifacts::host::node_id(path).map_err(unavailable)
    }
}
/// The identity of an open handle.
pub(crate) fn handle_node(file: &File) -> Result<Node, RuntimeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(unavailable)?;
        Ok((m.dev(), m.ino()))
    }
    #[cfg(windows)]
    {
        guard_cigar_artifacts::host::handle_node_id(file).map_err(unavailable)
    }
}
fn open_directory(path: &Path) -> Result<File, RuntimeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags((nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits())
            .open(path)
            .map_err(unavailable)
    }
    #[cfg(windows)]
    {
        guard_cigar_artifacts::host::open_unfollowed(path).map_err(unavailable)
    }
}
fn open_unfollowed_file(path: &Path) -> Result<File, RuntimeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)
            .map_err(unavailable)
    }
    #[cfg(windows)]
    {
        guard_cigar_artifacts::host::open_unfollowed(path).map_err(unavailable)
    }
}
fn unavailable(_: std::io::Error) -> RuntimeError {
    RuntimeError::ArtifactUnreadable
}

#[cfg(all(test, unix))]
#[path = "broker_storage_tests.rs"]
mod tests;
