use super::*;
use std::fs;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

pub(super) fn validate_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "native_policy_snapshot_parent_invalid".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("native_policy_snapshot_parent_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("native_policy_snapshot_parent_not_private".to_owned());
        }
    }
    #[cfg(windows)]
    {
        let private_root = crate::resident_state::private_root_for_state_base(path)?;
        crate::resident_state::verify_windows_private_path(path, true, &private_root)?;
    }
    Ok(())
}

#[cfg(windows)]
fn map_verifier_read_error(error: String) -> String {
    if error.ends_with("_invalid") {
        "native_policy_verifier_key_invalid".to_owned()
    } else if error.ends_with("_not_private") {
        "native_policy_verifier_key_not_private".to_owned()
    } else {
        "native_policy_verifier_key_read_failed".to_owned()
    }
}

pub(super) fn read_verifier_key(state_base: &Path) -> Result<[u8; VERIFIER_KEY_BYTES], String> {
    let path = state_base.join(VERIFIER_KEY_FILE_NAME);
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    #[cfg(not(windows))]
    let _ = &private_root;
    #[cfg(windows)]
    let mut file = crate::resident_state::open_private_read(
        &path,
        MAX_KEY_FILE_BYTES,
        "policy_verifier_key",
        &private_root,
    )
    .map_err(map_verifier_read_error)?
    .ok_or_else(|| "native_policy_verifier_key_missing".to_owned())?;
    #[cfg(not(windows))]
    let mut file = {
        let path_metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "native_policy_verifier_key_missing".to_owned()
            } else {
                "native_policy_verifier_key_stat_failed".to_owned()
            }
        })?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.len() != MAX_KEY_FILE_BYTES
        {
            return Err("native_policy_verifier_key_invalid".to_owned());
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options
            .open(&path)
            .map_err(|_| "native_policy_verifier_key_read_failed".to_owned())?
    };
    let metadata = file
        .metadata()
        .map_err(|_| "native_policy_verifier_key_invalid".to_owned())?;
    if !metadata.is_file() || metadata.len() != MAX_KEY_FILE_BYTES {
        return Err("native_policy_verifier_key_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = fs::symlink_metadata(state_base)
            .map_err(|_| "native_policy_verifier_key_not_private".to_owned())?
            .uid();
        if metadata.uid() != owner || metadata.permissions().mode() & 0o077 != 0 {
            return Err("native_policy_verifier_key_not_private".to_owned());
        }
    }
    let mut key = [0u8; VERIFIER_KEY_BYTES];
    file.read_exact(&mut key)
        .map_err(|_| "native_policy_verifier_key_read_failed".to_owned())?;
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| "native_policy_verifier_key_read_failed".to_owned())?
        != 0
    {
        return Err("native_policy_verifier_key_invalid".to_owned());
    }
    Ok(key)
}
