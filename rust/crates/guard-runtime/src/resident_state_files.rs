use std::fs::File;
#[cfg(not(windows))]
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

#[cfg(windows)]
#[path = "resident_state_windows.rs"]
mod windows_security;

pub(crate) fn is_lock_contention(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const ERROR_LOCK_VIOLATION: i32 = 33;
        matches!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
        )
    }
    #[cfg(not(windows))]
    false
}

#[cfg(windows)]
fn windows_bind_target(path: &Path, directory: bool) -> &Path {
    if directory {
        path
    } else {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(path)
    }
}

#[cfg(windows)]
pub(crate) fn protect_windows_private_path(
    path: &Path,
    directory: bool,
    private_root: &Path,
) -> Result<(), String> {
    use windows_permissions::utilities::current_process_sid;

    let binding = windows_security::bind_windows_existing_directory(
        windows_bind_target(path, directory),
        private_root,
    )?;
    if directory {
        // Binding already repaired the private directory ACL through the held
        // handle. Re-protecting by path while that handle withholds delete
        // sharing fails with a sharing violation.
        let owner = current_process_sid()
            .map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
        return windows_security::verify_windows_handle(binding.handle(), owner.as_ref());
    }
    windows_security::protect_windows_path(path, directory)
}

#[cfg(windows)]
pub(crate) fn verify_windows_private_path(
    path: &Path,
    directory: bool,
    private_root: &Path,
) -> Result<(), String> {
    use windows_permissions::utilities::current_process_sid;

    let binding = windows_security::bind_windows_existing_directory(
        windows_bind_target(path, directory),
        private_root,
    )?;
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    if directory {
        return windows_security::verify_windows_handle(binding.handle(), owner.as_ref());
    }
    windows_security::verify_windows_path(path, owner.as_ref())
}

#[cfg(windows)]
pub(crate) fn replace_windows_private_file(
    temporary: &Path,
    path: &Path,
    private_root: &Path,
) -> Result<(), String> {
    windows_security::replace_private_file(temporary, path, private_root)
}

#[cfg(windows)]
pub(crate) fn remove_windows_private_file(
    path: &Path,
    private_root: &Path,
) -> Result<bool, String> {
    windows_security::remove_private_file(path, private_root)
}

#[cfg(all(windows, test))]
pub(crate) fn bind_windows_private_directory(
    path: &Path,
    private_root: &Path,
) -> Result<guard_runtime_windows_process::PrivateDirectoryBinding, String> {
    windows_security::bind_windows_private_directory(path, private_root)
}

#[cfg(windows)]
pub(crate) fn bind_windows_existing_directory(
    path: &Path,
    private_root: &Path,
) -> Result<guard_runtime_windows_process::PrivateDirectoryBinding, String> {
    windows_security::bind_windows_existing_directory(path, private_root)
}

#[cfg(windows)]
pub(crate) fn verify_windows_private_file(file: &File) -> Result<(), String> {
    windows_security::verify_private_file(file)
}

pub(crate) fn private_file(
    path: &Path,
    create_new: bool,
    private_root: &Path,
) -> Result<File, String> {
    #[cfg(not(windows))]
    let _ = private_root;
    #[cfg(windows)]
    {
        let file = match windows_security::create_private_file(path, private_root) {
            Ok(file) => file,
            Err(error) if create_new && error.kind() == std::io::ErrorKind::AlreadyExists => {
                // CREATE_NEW is intentionally non-mutating: do not open,
                // repair, or truncate an object that already exists.
                return Err("native_resident_state_write_failed".to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut file = windows_security::open_private_file(path, private_root)
                    .map_err(|_| "native_resident_state_write_failed".to_owned())?;
                windows_security::repair_private_file(&mut file)?;
                if !create_new {
                    file.set_len(0)
                        .map_err(|_| "native_resident_state_write_failed".to_owned())?;
                }
                file
            }
            Err(_) if create_new => {
                return Err("native_resident_state_write_failed".to_owned());
            }
            Err(_) => return Err("native_resident_state_write_failed".to_owned()),
        };
        // CREATE_NEW already created an empty file; the existing-object case
        // returned above before opening or mutating it.
        Ok(file)
    }

    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).create_new(create_new);
        if !create_new {
            options.truncate(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .map_err(|_| "native_resident_state_write_failed".to_owned())?;
        Ok(file)
    }
}

#[cfg(windows)]
pub(crate) fn private_lock_file(
    path: &Path,
    private_root: &Path,
) -> Result<(File, guard_runtime_windows_process::PrivateDirectoryBinding), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "native_resident_lock_open_failed".to_owned())?;
    let binding = windows_security::bind_windows_existing_directory(parent, private_root)?;
    let name = path
        .file_name()
        .ok_or_else(|| "native_resident_lock_open_failed".to_owned())?;
    let descriptor = windows_security::private_file_descriptor()?;
    let file = match binding.create_private_file(name, descriptor.as_ref()) {
        Ok(file) => {
            windows_security::verify_private_file(&file).map_err(|error| {
                let _ = guard_runtime_windows_process::delete_private_file_handle(&file);
                error
            })?;
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut file = binding
                .open_private_file(name)
                .map_err(|_| "native_resident_lock_open_failed".to_owned())?;
            windows_security::repair_private_file(&mut file)?;
            file
        }
        Err(_) => return Err("native_resident_lock_open_failed".to_owned()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_lock_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("native_resident_lock_invalid".to_owned());
    }
    Ok((file, binding))
}

#[cfg(not(windows))]
pub(crate) fn private_lock_file(path: &Path, private_root: &Path) -> Result<File, String> {
    let _ = private_root;
    #[cfg(not(windows))]
    {
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
            .open(path)
            .map_err(|_| "native_resident_lock_open_failed".to_owned())?;
        let metadata = file
            .metadata()
            .map_err(|_| "native_resident_lock_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("native_resident_lock_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let path_metadata = fs::symlink_metadata(path)
                .map_err(|_| "native_resident_lock_stat_failed".to_owned())?;
            if path_metadata.file_type().is_symlink()
                || !path_metadata.is_file()
                || path_metadata.dev() != metadata.dev()
                || path_metadata.ino() != metadata.ino()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err("native_resident_lock_not_private".to_owned());
            }
        }
        Ok(file)
    }
}

/// Open a private state file through one Windows handle, then validate the
/// opened object and its ACL before callers read from that same handle. The
/// reparse-point flag prevents the final path component from being followed;
/// no path metadata is trusted across a second open.
#[cfg(windows)]
pub(crate) fn open_private_read(
    path: &Path,
    maximum_bytes: u64,
    kind: &str,
    private_root: &Path,
) -> Result<Option<File>, String> {
    let file = match windows_security::open_private_file(path, private_root) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(format!("native_resident_{kind}_read_failed")),
    };
    let metadata = file
        .metadata()
        .map_err(|_| format!("native_resident_{kind}_invalid"))?;
    if !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(format!("native_resident_{kind}_invalid"));
    }
    let owner = windows_permissions::utilities::current_process_sid()
        .map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    windows_security::verify_windows_handle(&file, owner.as_ref())?;
    Ok(Some(file))
}

#[cfg(any(not(windows), test))]
pub(crate) fn ensure_private_directory(
    path: &Path,
    protect_windows: bool,
) -> Result<PathBuf, String> {
    let private_root = crate::resident_state::private_root_for_state_base(path)?;
    ensure_private_directory_under(path, &private_root, protect_windows)
}

pub(crate) fn ensure_private_directory_under(
    path: &Path,
    private_root: &Path,
    protect_windows: bool,
) -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        let resolved =
            windows_security::ensure_private_directory_path(path, private_root, protect_windows)?;
        let private_root = private_root
            .canonicalize()
            .map_err(|_| "native_resident_state_dir_outside_user_profile".to_owned())?;
        if !resolved.starts_with(&private_root) {
            return Err("native_resident_state_dir_outside_user_profile".to_owned());
        }
        Ok(resolved)
    }

    #[cfg(not(windows))]
    {
        let _ = (private_root, protect_windows);
        let created = match fs::create_dir(path) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(_) => return Err("native_resident_state_dir_create_failed".to_owned()),
        };
        let _ = created;
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| "native_resident_state_dir_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("native_resident_state_dir_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "native_resident_state_dir_permissions_failed".to_owned())?;
            }
            let updated = fs::symlink_metadata(path)
                .map_err(|_| "native_resident_state_dir_stat_failed".to_owned())?;
            if updated.permissions().mode() & 0o077 != 0 {
                return Err("native_resident_state_dir_not_private".to_owned());
            }
        }
        let resolved = path
            .canonicalize()
            .map_err(|_| "native_resident_state_dir_resolve_failed".to_owned())?;
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::is_lock_contention;

    #[test]
    fn would_block_is_lock_contention() {
        let error = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        assert!(is_lock_contention(&error));
    }

    #[cfg(windows)]
    #[test]
    fn windows_lock_violations_are_contention() {
        assert!(is_lock_contention(&std::io::Error::from_raw_os_error(32)));
        assert!(is_lock_contention(&std::io::Error::from_raw_os_error(33)));
        assert!(!is_lock_contention(&std::io::Error::from_raw_os_error(5)));
    }
}
