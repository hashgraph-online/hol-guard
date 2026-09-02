use std::fs::{self, File, OpenOptions};
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
        return matches!(
            error.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
        );
    }
    #[cfg(not(windows))]
    false
}

#[cfg(windows)]
pub(crate) fn protect_windows_private_path(path: &Path, directory: bool) -> Result<(), String> {
    windows_security::protect_windows_path(path, directory)
}

#[cfg(windows)]
pub(crate) fn verify_windows_private_path(path: &Path, _directory: bool) -> Result<(), String> {
    use windows_permissions::utilities::current_process_sid;

    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    windows_security::verify_windows_path(path, owner.as_ref())
}

pub(crate) fn private_file(path: &Path, create_new: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).create_new(create_new);
    if !create_new {
        options.truncate(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| "native_resident_state_write_failed".to_owned())?;
    #[cfg(windows)]
    if let Err(error) = windows_security::protect_windows_path(path, false) {
        if create_new {
            let _ = guard_runtime_windows_process::remove_file_if_same(path, &file);
        }
        return Err(error);
    }
    Ok(file)
}

pub(crate) fn private_lock_file(path: &Path) -> Result<File, String> {
    #[cfg(windows)]
    let (file, created) = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        let share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        let mut create_options = OpenOptions::new();
        create_options
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(share_mode)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        match create_options.open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing_options = OpenOptions::new();
                existing_options
                    .read(true)
                    .write(true)
                    .share_mode(share_mode)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
                let file = existing_options
                    .open(path)
                    .map_err(|_| "native_resident_lock_open_failed".to_owned())?;
                (file, false)
            }
            Err(_) => return Err("native_resident_lock_open_failed".to_owned()),
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
            .open(path)
            .map_err(|_| "native_resident_lock_open_failed".to_owned())?;
        (file, false)
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_lock_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("native_resident_lock_invalid".to_owned());
    }
    #[cfg(windows)]
    if created {
        protect_windows_private_path(path, false)?;
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
    #[cfg(windows)]
    verify_windows_private_path(path, false)?;
    Ok(file)
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
) -> Result<Option<File>, String> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_permissions::utilities::current_process_sid;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(format!("native_resident_{kind}_read_failed")),
    };
    let metadata = file
        .metadata()
        .map_err(|_| format!("native_resident_{kind}_invalid"))?;
    if !metadata.is_file()
        || metadata.len() > maximum_bytes
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(format!("native_resident_{kind}_invalid"));
    }
    let owner =
        current_process_sid().map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
    windows_security::verify_windows_handle(&file, owner.as_ref())?;
    Ok(Some(file))
}

pub(crate) fn ensure_private_directory(
    path: &Path,
    protect_windows: bool,
) -> Result<PathBuf, String> {
    #[cfg(not(windows))]
    let _ = protect_windows;
    let created = match fs::create_dir(path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => return Err("native_resident_state_dir_create_failed".to_owned()),
    };
    #[cfg(not(windows))]
    let _ = created;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "native_resident_state_dir_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("native_resident_state_dir_invalid".to_owned());
    }
    #[cfg(windows)]
    if protect_windows {
        if created {
            windows_security::protect_windows_path(path, true)?;
        } else {
            use windows_permissions::utilities::current_process_sid;
            let owner = current_process_sid()
                .map_err(|_| "native_resident_windows_owner_sid_failed".to_owned())?;
            windows_security::verify_windows_path(path, owner.as_ref())?;
        }
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
    #[cfg(windows)]
    {
        let profile = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .ok_or_else(|| "native_resident_user_profile_missing".to_owned())?
            .canonicalize()
            .map_err(|_| "native_resident_user_profile_invalid".to_owned())?;
        if !resolved.starts_with(profile) {
            return Err("native_resident_state_dir_outside_user_profile".to_owned());
        }
    }
    Ok(resolved)
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
