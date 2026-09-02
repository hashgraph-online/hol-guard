#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::path::Path;

pub(super) const MANAGED_OWNER_LOCK_FILE_NAME: &str = "managed-resident-owner.v1.lock";

pub(super) struct ManagedOwnerLock {
    pub(super) _file: File,
    pub(super) _legacy_files: Vec<File>,
    #[cfg(unix)]
    pub(super) _directory: File,
}

impl Drop for ManagedOwnerLock {
    fn drop(&mut self) {
        // Explicitly release every advisory lock before the descriptors close.
        // This matters on platforms where a lock on a renamed marker or a
        // directory is not made immediately available by descriptor teardown.
        for file in self._legacy_files.iter().rev() {
            let _ = fs2::FileExt::unlock(file);
        }
        let _ = fs2::FileExt::unlock(&self._file);
        #[cfg(unix)]
        {
            let _ = fs2::FileExt::unlock(&self._directory);
        }
    }
}

fn acquire_legacy_owner_locks(state_base: &Path) -> Result<Vec<File>, String> {
    let mut locks = Vec::new();
    let entries = std::fs::read_dir(state_base)
        .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
    for entry in entries {
        let entry = entry.map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("resident-v3-") {
            continue;
        }
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("native_resident_owner_lock_invalid".to_owned());
        }
        let lock_path = path.join(MANAGED_OWNER_LOCK_FILE_NAME);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_WRITE: u32 = 0x0000_0002;
            options
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let Ok(file) = options.open(&lock_path) else {
            continue;
        };
        let metadata = file
            .metadata()
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        if !metadata.is_file() {
            return Err("native_resident_owner_lock_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let path_metadata = std::fs::symlink_metadata(&lock_path)
                .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
            if path_metadata.file_type().is_symlink()
                || !path_metadata.is_file()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err("native_resident_owner_lock_not_private".to_owned());
            }
        }
        #[cfg(windows)]
        crate::resident_state::verify_windows_private_path(&lock_path, false)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                "native_resident_owner_busy".to_owned()
            } else {
                "native_resident_owner_lock_failed".to_owned()
            }
        })?;
        locks.push(file);
    }
    Ok(locks)
}

pub(super) fn acquire(scope: &Path) -> Result<ManagedOwnerLock, String> {
    #[cfg(unix)]
    let directory = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let mut directory_options = OpenOptions::new();
        directory_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = directory_options
            .open(scope)
            .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
        let metadata = directory
            .metadata()
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        let path_metadata = std::fs::symlink_metadata(scope)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        if !metadata.is_dir()
            || path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || metadata.dev() != path_metadata.dev()
            || metadata.ino() != path_metadata.ino()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_owner_lock_not_private".to_owned());
        }
        fs2::FileExt::try_lock_exclusive(&directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                "native_resident_owner_busy".to_owned()
            } else {
                "native_resident_owner_lock_failed".to_owned()
            }
        })?;
        directory
    };
    let path = scope.join(MANAGED_OWNER_LOCK_FILE_NAME);
    #[cfg(windows)]
    let (file, created) = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        let share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;

        let mut create_options = OpenOptions::new();
        create_options
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(share_mode)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        match create_options.open(&path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing_options = OpenOptions::new();
                existing_options
                    .read(true)
                    .write(true)
                    .share_mode(share_mode)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                let file = existing_options
                    .open(&path)
                    .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
                (file, false)
            }
            Err(_) => return Err("native_resident_owner_lock_failed".to_owned()),
        }
    };
    #[cfg(not(windows))]
    let (file, _created) = {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options
            .open(&path)
            .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
        (file, false)
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
    if !metadata.is_file() {
        return Err("native_resident_owner_lock_invalid".to_owned());
    }
    #[cfg(windows)]
    if created {
        crate::resident_state::protect_windows_private_path(&path, false)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path_metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        let parent_uid = path
            .parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .map(|parent| parent.uid());
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
            || parent_uid != Some(metadata.uid())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_owner_lock_not_private".to_owned());
        }
    }
    #[cfg(windows)]
    crate::resident_state::verify_windows_private_path(&path, false)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "native_resident_owner_busy".to_owned()
        } else {
            "native_resident_owner_lock_failed".to_owned()
        }
    })?;
    let legacy_files = acquire_legacy_owner_locks(scope)?;
    Ok(ManagedOwnerLock {
        _file: file,
        _legacy_files: legacy_files,
        #[cfg(unix)]
        _directory: directory,
    })
}
