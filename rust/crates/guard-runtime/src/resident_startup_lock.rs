#![forbid(unsafe_code)]

#[cfg(windows)]
use super::verify_windows_private_path;
use super::{
    private_lock_file, process_start_marker, runtime_digest, validate_package_process_identity,
    validate_runtime_process_identity, LOCK_STALE_AFTER, MAX_STARTUP_LOCK_BYTES,
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

pub(crate) struct StartupLock {
    file: File,
}

impl Drop for StartupLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub(crate) fn acquire_startup_lock(scope: &Path) -> Result<Option<StartupLock>, String> {
    let path = scope.join("startup.lock");
    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(|_| "native_client_random_failed".to_owned())?;
    let process_id = std::process::id();
    let start_marker = process_start_marker(process_id)?;
    let digest = runtime_digest()?;
    let nonce = format!(
        "{process_id}:{start_marker}:{digest}:{}",
        super::hex_bytes(&nonce_bytes)
    );
    let Ok(mut file) = private_lock_file(&path) else {
        return Ok(None);
    };
    if fs2::FileExt::try_lock_exclusive(&file).is_err() {
        return Ok(None);
    }
    if file
        .set_len(0)
        .and_then(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .and_then(|_| file.write_all(nonce.as_bytes()))
        .and_then(|()| file.sync_all())
        .is_err()
    {
        return Err("native_resident_lock_write_failed".to_owned());
    }
    Ok(Some(StartupLock { file }))
}

pub(crate) fn clear_stale_startup_lock(
    scope: &Path,
    expected_digest: &str,
) -> Result<bool, String> {
    let path = scope.join("startup.lock");
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
        options
            .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004)
            .custom_flags(0x0020_0000);
    }
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("native_resident_lock_stat_failed".to_owned()),
    };
    #[cfg(windows)]
    verify_windows_private_path(&path, false)?;
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_lock_stat_failed".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("native_resident_lock_invalid".to_owned());
    }
    let path_metadata =
        fs::symlink_metadata(&path).map_err(|_| "native_resident_lock_stat_failed".to_owned())?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err("native_resident_lock_not_private".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_lock_not_private".to_owned());
        }
    }
    #[cfg(not(unix))]
    if path_metadata.len() != metadata.len() {
        return Err("native_resident_lock_not_private".to_owned());
    }
    if fs2::FileExt::try_lock_exclusive(&file).is_err() {
        return Ok(false);
    }
    let age = metadata
        .modified()
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    if age.is_none_or(|age| age < LOCK_STALE_AFTER) {
        return Ok(false);
    }
    let mut contents = String::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| {
            Read::by_ref(&mut file)
                .take(MAX_STARTUP_LOCK_BYTES)
                .read_to_string(&mut contents)
        })
        .map_err(|_| "native_resident_lock_read_failed".to_owned())?;
    let owner_identity = contents.split_once(':').and_then(|(process_id, rest)| {
        let process_id = process_id.parse::<u32>().ok()?;
        let (start_and_digest, nonce) = rest.rsplit_once(':')?;
        if nonce.len() != 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        if let Some((start_marker, recorded_digest)) = start_and_digest.rsplit_once(':') {
            if recorded_digest.len() == 64
                && recorded_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                if start_marker.is_empty() || start_marker.len() > 256 {
                    return None;
                }
                Some((
                    process_id,
                    start_marker.to_owned(),
                    Some(recorded_digest.to_owned()),
                ))
            } else if !start_and_digest.is_empty() {
                Some((process_id, start_and_digest.to_owned(), None))
            } else {
                None
            }
        } else if !start_and_digest.is_empty() {
            Some((process_id, start_and_digest.to_owned(), None))
        } else {
            None
        }
    });
    if owner_identity.is_some_and(|(process_id, start_marker, recorded_digest)| {
        process_id > 0
            && if recorded_digest
                .is_some_and(|digest| !digest.eq_ignore_ascii_case(expected_digest))
            {
                validate_package_process_identity(process_id, &start_marker).is_ok()
            } else {
                validate_runtime_process_identity(process_id, &start_marker, expected_digest)
                    .is_ok()
                    || validate_package_process_identity(process_id, &start_marker).is_ok()
            }
    }) {
        return Ok(false);
    }
    Ok(true)
}
