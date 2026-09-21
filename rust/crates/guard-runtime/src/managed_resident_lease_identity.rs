use std::fs::File;
#[cfg(not(windows))]
use std::fs::{self};
use std::path::Path;

pub(super) struct LeaseIdentity {
    #[cfg(unix)]
    file: File,
    #[cfg(windows)]
    file: File,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    nlink: u64,
}

impl LeaseIdentity {
    pub(super) fn from_file(file: &File) -> Result<Self, String> {
        let metadata = file
            .metadata()
            .map_err(|_| "native_resident_lease_write_failed".to_owned())?;
        if !metadata.is_file() {
            return Err("native_resident_lease_write_failed".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err("native_resident_lease_write_failed".to_owned());
            }
            Ok(Self {
                file: file
                    .try_clone()
                    .map_err(|_| "native_resident_lease_write_failed".to_owned())?,
                device: metadata.dev(),
                inode: metadata.ino(),
                nlink: metadata.nlink(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                file: file
                    .try_clone()
                    .map_err(|_| "native_resident_lease_write_failed".to_owned())?,
            })
        }
    }

    pub(super) fn remove_if_same(&self, path: &Path) -> bool {
        #[cfg(windows)]
        {
            guard_runtime_windows_process::remove_file_if_same(path, &self.file).unwrap_or(false)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Ok(metadata) = self.file.metadata() else {
                return false;
            };
            let Ok(path_metadata) = fs::symlink_metadata(path) else {
                return false;
            };
            if !metadata.is_file()
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.nlink() != self.nlink
                || path_metadata.file_type().is_symlink()
                || !path_metadata.is_file()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
                || path_metadata.nlink() != metadata.nlink()
            {
                return false;
            }
            fs::remove_file(path).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            fs::remove_file(path).is_ok()
        }
    }

    #[cfg(unix)]
    pub(super) fn matches_path(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Ok(path_metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        !path_metadata.file_type().is_symlink()
            && path_metadata.is_file()
            && path_metadata.dev() == self.device
            && path_metadata.ino() == self.inode
            && path_metadata.nlink() == self.nlink
    }
}

pub(super) fn remove_open_file_if_same(path: &Path, file: &File) -> bool {
    #[cfg(windows)]
    {
        guard_runtime_windows_process::remove_file_if_same(path, file).unwrap_or(false)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        let Ok(path_metadata) = fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_file()
            || metadata.nlink() != 1
            || path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || path_metadata.nlink() != metadata.nlink()
        {
            return false;
        }
        fs::remove_file(path).is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::remove_file(path).is_ok()
    }
}
