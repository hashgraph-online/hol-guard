#![forbid(unsafe_code)]

use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::path::Path;

pub(super) const MANAGED_OWNER_LOCK_FILE_NAME: &str = "managed-resident-owner.v1.lock";

pub(super) struct ManagedOwnerLock {
    pub(super) _file: File,
    pub(super) _legacy_files: Vec<File>,
    #[cfg(unix)]
    pub(super) _directory: File,
}

struct LegacyOwnerLocks {
    files: Vec<File>,
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

fn acquire_legacy_owner_locks(state_base: &Path) -> Result<LegacyOwnerLocks, String> {
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    #[cfg(not(windows))]
    let _ = &private_root;
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
        #[cfg(windows)]
        {
            let binding =
                crate::resident_state::bind_windows_existing_directory(&path, &private_root)?;
            let lock_name = std::ffi::OsStr::new(MANAGED_OWNER_LOCK_FILE_NAME);
            let file = match binding.open_private_file(lock_name) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("native_resident_owner_lock_invalid".to_owned()),
            };
            crate::resident_state::verify_windows_private_file(&file)?;
            fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    "native_resident_owner_busy".to_owned()
                } else {
                    "native_resident_owner_lock_failed".to_owned()
                }
            })?;
            locks.push(file);
            continue;
        }
        #[cfg(not(windows))]
        {
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
            fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    "native_resident_owner_busy".to_owned()
                } else {
                    "native_resident_owner_lock_failed".to_owned()
                }
            })?;
            locks.push(file);
        }
    }
    Ok(LegacyOwnerLocks { files: locks })
}

pub(super) fn acquire(scope: &Path) -> Result<ManagedOwnerLock, String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    #[cfg(not(windows))]
    let _ = &private_root;
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
    // Keep the locked file, not a live directory barrier. Holding
    // `native-runtime` open without delete sharing stalls overlapping
    // client binds until the publisher ACK deadline expires.
    #[cfg(windows)]
    let (file, lock_directory_binding) =
        crate::resident_state::private_lock_file(&path, &private_root)
            .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(&path)
            .map_err(|_| "native_resident_owner_lock_failed".to_owned())?
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
    crate::resident_state::verify_windows_private_file(&file)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "native_resident_owner_busy".to_owned()
        } else {
            "native_resident_owner_lock_failed".to_owned()
        }
    })?;
    #[cfg(windows)]
    drop(lock_directory_binding);
    let legacy_locks = acquire_legacy_owner_locks(scope)?;
    Ok(ManagedOwnerLock {
        _file: file,
        _legacy_files: legacy_locks.files,
        #[cfg(unix)]
        _directory: directory,
    })
}
