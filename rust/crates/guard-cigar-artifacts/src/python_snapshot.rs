//! In-process cache of a complete protected-byte verification. It cannot be
//! deserialized, persisted as authority, or rebound to another tree/build.
use crate::{paths, InstallError, PreparationControl};
use guard_cigar_release::InterpreterBinding;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct VerifiedPythonSnapshot {
    root: PathBuf,
    binding: InterpreterBinding,
    entries: BTreeMap<String, Stamp>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
pub(super) fn stamp(metadata: &fs::Metadata) -> Result<Stamp, InstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Stamp {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            size: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(InstallError::PlatformUnsupported)
    }
}
impl VerifiedPythonSnapshot {
    pub(super) fn new(
        root: &Path,
        binding: &InterpreterBinding,
        entries: BTreeMap<String, Stamp>,
    ) -> Self {
        Self {
            root: root.into(),
            binding: binding.clone(),
            entries,
        }
    }
    pub fn matches(&self, root: &Path, binding: &InterpreterBinding) -> bool {
        self.root == root && self.binding == *binding
    }
    /// Read metadata for every verified file and directory, including ctime,
    /// permissions, owner, inode, link count and namespace directory stamps.
    /// Restoring mtime or file length cannot revive changed code. A change
    /// requires complete verification again; it never refreshes this snapshot.
    pub fn recheck(&self, cancel: Option<&AtomicBool>) -> Result<(), InstallError> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let checkpoint = || {
            if cancel.is_some_and(|value| value.load(Ordering::Acquire)) {
                return Err(InstallError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(InstallError::DeadlineExceeded);
            }
            Ok(())
        };
        self.recheck_cached_with(&checkpoint)
    }
    pub fn recheck_controlled(&self, control: &PreparationControl) -> Result<(), InstallError> {
        self.recheck_cached_with(&|| control.checkpoint())
    }
    /// Nanosecond change times are essential to this optimization. Unknown
    /// or coarse-grained filesystems keep full-byte verification. Keep every
    /// entry on the same measured device, and recheck the filesystem each use.
    pub fn metadata_cache_supported(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            let Some(root) = self.entries.get("") else {
                return false;
            };
            nix::sys::statfs::statfs(&self.root)
                .is_ok_and(|info| info.filesystem_type_name() == "apfs")
                && self
                    .entries
                    .values()
                    .all(|entry| entry.dev == root.dev && entry.ctime.1 != 0)
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
    fn recheck_cached_with(
        &self,
        checkpoint: &dyn Fn() -> Result<(), InstallError>,
    ) -> Result<(), InstallError> {
        checkpoint()?;
        if self.metadata_cache_supported() {
            self.recheck_with(checkpoint)
        } else {
            crate::python_tree::check_python_controlled(&self.binding, &self.root, checkpoint)
        }
    }
    pub(super) fn recheck_with(
        &self,
        checkpoint: &dyn Fn() -> Result<(), InstallError>,
    ) -> Result<(), InstallError> {
        checkpoint()?;
        paths::private_directory(&self.root)?;
        for (name, expected) in &self.entries {
            checkpoint()?;
            let path = self.root.join(name);
            let actual =
                fs::symlink_metadata(path).map_err(|_| InstallError::ArtifactUnreadable)?;
            if stamp(&actual)? != *expected {
                return Err(InstallError::TreeMismatch);
            }
        }
        // Repeat the root check to catch ancestor/root replacement during the
        // scan. Directory entries below it are also bound individually.
        paths::private_directory(&self.root)?;
        let root =
            fs::symlink_metadata(&self.root).map_err(|_| InstallError::ArtifactUnreadable)?;
        if self.entries.get("") != Some(&stamp(&root)?) {
            return Err(InstallError::TreeMismatch);
        }
        checkpoint()
    }
}
