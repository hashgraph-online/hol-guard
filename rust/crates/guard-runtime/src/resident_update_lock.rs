#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(crate) const RESIDENT_UPDATE_LOCK_FILE_NAME: &str = "resident-update.v1.lock";
const MAX_MARKER_BYTES: u64 = 128;

pub(crate) struct ResidentUpdateSharedLock {
    file: File,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl std::fmt::Debug for ResidentUpdateSharedLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResidentUpdateSharedLock")
            .finish_non_exhaustive()
    }
}

impl Drop for ResidentUpdateSharedLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub(crate) fn acquire_shared(
    state_base: &Path,
    runtime_digest: &str,
) -> Result<ResidentUpdateSharedLock, String> {
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    let path = state_base.join(RESIDENT_UPDATE_LOCK_FILE_NAME);
    #[cfg(windows)]
    let (file, directory_binding) = crate::resident_state::private_lock_file(&path, &private_root)
        .map_err(|_| "native_resident_update_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, &private_root)?;
    fs2::FileExt::try_lock_shared(&file).map_err(|error| {
        if crate::resident_state::is_lock_contention(&error) {
            "native_resident_update_in_progress".to_owned()
        } else {
            "native_resident_update_lock_failed".to_owned()
        }
    })?;
    let marker = read_marker(&file)?;
    if let Some(expected_digest) = marker {
        // The marker names the runtime the last updater published. Another
        // install sharing this guard home (for example a desktop-bundled core
        // next to a package-manager install) ships a different binary but is
        // still current; only a process whose own executable was replaced or
        // removed by an update is a superseded runtime.
        if expected_digest != runtime_digest
            && crate::resident_state::runtime_superseded(runtime_digest)
        {
            return Err("native_resident_runtime_identity_mismatch".to_owned());
        }
    }
    Ok(ResidentUpdateSharedLock {
        file,
        #[cfg(windows)]
        _directory_binding: directory_binding,
    })
}

fn read_marker(file: &File) -> Result<Option<String>, String> {
    let mut bytes = Vec::new();
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_resident_update_lock_read_failed".to_owned())?;
    if bytes.len() > MAX_MARKER_BYTES as usize {
        return Err("native_resident_update_lock_invalid".to_owned());
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err("native_resident_update_lock_invalid".to_owned());
    }
    Ok(Some(String::from_utf8(bytes).map_err(|_| {
        "native_resident_update_lock_invalid".to_owned()
    })?))
}

#[cfg(test)]
mod tests {
    use super::{acquire_shared, read_marker, RESIDENT_UPDATE_LOCK_FILE_NAME};
    use std::fs::{self, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hol-guard-resident-update-lock-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn empty_marker_allows_legacy_clients() {
        let root = temp_root();
        let state = root.join("native-runtime");
        fs::create_dir_all(&state).unwrap();
        let path = state.join(RESIDENT_UPDATE_LOCK_FILE_NAME);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .unwrap();
        file.set_len(0).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            state.join(RESIDENT_UPDATE_LOCK_FILE_NAME),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        #[cfg(windows)]
        {
            crate::resident_state::protect_windows_private_path(&root, true, &root).unwrap();
            crate::resident_state::protect_windows_private_path(&state, true, &root).unwrap();
            crate::resident_state::protect_windows_private_path(
                &state.join(RESIDENT_UPDATE_LOCK_FILE_NAME),
                false,
                &root,
            )
            .unwrap();
        }
        assert!(read_marker(&file).unwrap().is_none());
        drop(file);
        assert!(acquire_shared(&state, &"a".repeat(64)).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn marker_rejects_old_runtime_and_accepts_published_runtime() {
        let root = temp_root();
        let state = root.join("native-runtime");
        fs::create_dir_all(&state).unwrap();
        let path = state.join(RESIDENT_UPDATE_LOCK_FILE_NAME);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .unwrap();
        file.write_all(format!("{}\n", "b".repeat(64)).as_bytes())
            .unwrap();
        file.flush().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            state.join(RESIDENT_UPDATE_LOCK_FILE_NAME),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        #[cfg(windows)]
        {
            crate::resident_state::protect_windows_private_path(&root, true, &root).unwrap();
            crate::resident_state::protect_windows_private_path(&state, true, &root).unwrap();
            crate::resident_state::protect_windows_private_path(
                &state.join(RESIDENT_UPDATE_LOCK_FILE_NAME),
                false,
                &root,
            )
            .unwrap();
        }
        file.seek(SeekFrom::Start(0)).unwrap();
        drop(file);
        assert_eq!(
            acquire_shared(&state, &"a".repeat(64)).unwrap_err(),
            "native_resident_runtime_identity_mismatch"
        );
        assert!(acquire_shared(&state, &"b".repeat(64)).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn marker_from_another_install_allows_current_runtime() {
        let root = temp_root();
        let state = root.join("native-runtime");
        fs::create_dir_all(&state).unwrap();
        let path = state.join(RESIDENT_UPDATE_LOCK_FILE_NAME);
        fs::write(&path, format!("{}\n", "b".repeat(64))).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        #[cfg(windows)]
        {
            crate::resident_state::protect_windows_private_path(&root, true, &root).unwrap();
            crate::resident_state::protect_windows_private_path(&state, true, &root).unwrap();
            crate::resident_state::protect_windows_private_path(&path, false, &root).unwrap();
        }
        let current = crate::resident_state::runtime_digest().unwrap();
        assert!(acquire_shared(&state, &current).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
}
