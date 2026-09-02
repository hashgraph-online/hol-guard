use super::*;
use guard_policy_snapshot::{canonical_json_bytes, generation_floor_mac};
use serde_json::Value;
#[cfg(windows)]
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Recover the only intermediate states possible with a Windows replacement
/// sequence and discard fully written temporary candidates left by a crash.
/// POSIX rename is already a single atomic replacement; this cleanup remains
/// useful there for a process dying after temp fsync and before rename.
pub(super) fn recover_authority_replacement(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "native_policy_snapshot_authority_parent_missing".to_owned())?;
    #[cfg(windows)]
    {
        // Keep one handle-bound ancestry proof alive for the complete
        // recovery transaction. Every candidate is opened relative to this
        // binding, so a pathname replacement cannot switch parent identity
        // between enumeration, validation, and mutation.
        let private_root = crate::resident_state::private_root_for_state_base(parent)
            .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        let binding = crate::resident_state::bind_windows_existing_directory(parent, &private_root)
            .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy-snapshot-v3.json");
        let target_name = OsStr::new(file_name);
        let backup_name = format!(".{file_name}.previous");
        let open_candidate = |name: &OsStr| {
            let file = match binding.open_private_file(name) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err("native_policy_snapshot_authority_recovery_failed".to_owned()),
            };
            let metadata = file
                .metadata()
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
            if metadata.len() > AUTHORITY_RECORD_MAX_BYTES {
                return Err("native_policy_snapshot_authority_recovery_failed".to_owned());
            }
            Ok(Some(file))
        };
        let target_exists = open_candidate(target_name)?.is_some();
        let backup_exists = open_candidate(OsStr::new(&backup_name))?.is_some();
        if !target_exists && backup_exists {
            let source = open_candidate(OsStr::new(&backup_name))?
                .ok_or_else(|| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
            binding
                .replace_private_file(&source, target_name)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        } else if target_exists && backup_exists {
            let backup = open_candidate(OsStr::new(&backup_name))?
                .ok_or_else(|| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
            guard_runtime_windows_process::delete_private_file_handle(&backup)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        }
        let prefix = format!(".{file_name}.");
        for entry in fs::read_dir(parent)
            .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?
        {
            let entry =
                entry.map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
            let name = entry.file_name();
            let name_text = name.to_string_lossy();
            if !name_text.starts_with(&prefix) || !name_text.ends_with(".tmp") {
                continue;
            }
            let Some(file) = open_candidate(&name)? else {
                continue;
            };
            guard_runtime_windows_process::delete_private_file_handle(&file)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let prefix = format!(
            ".{}.",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("policy-snapshot-v3.json")
        );
        for entry in fs::read_dir(parent)
            .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?
        {
            let entry =
                entry.map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
            let candidate = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
                continue;
            }
            let metadata = fs::symlink_metadata(&candidate)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("native_policy_snapshot_authority_recovery_failed".to_owned());
            }
            fs::remove_file(candidate)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        }
        Ok(())
    }
}

pub(super) fn read_generation_floor(
    path: &Path,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<Option<GenerationFloorV1>, String> {
    let private_root = path
        .parent()
        .ok_or_else(|| "native_policy_snapshot_floor_parent_missing".to_owned())
        .and_then(crate::resident_state::private_root_for_state_base)?;
    let Some((value, bytes)) = read_private_json(path, MAX_FLOOR_BYTES, "floor", &private_root)?
    else {
        return Ok(None);
    };
    let floor: GenerationFloorV1 = serde_json::from_value(value.clone())
        .map_err(|_| "native_policy_snapshot_floor_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value).map_err(snapshot_error)?;
    if bytes != canonical
        || floor.schema != GENERATION_FLOOR_SCHEMA
        || floor.generation == 0
        || !is_lower_hex(&floor.policy_digest, 64)
        || !is_lower_hex(&floor.mac, 64)
        || !crate::constant_time_eq(
            generation_floor_mac(floor.generation, &floor.policy_digest, verifier_key).as_bytes(),
            floor.mac.as_bytes(),
        )
    {
        return Err("native_policy_snapshot_floor_invalid".to_owned());
    }
    Ok(Some(floor))
}

pub(super) fn persist_authority(
    path: &Path,
    generation_floor: u64,
    policy_digest: &str,
    snapshot: Option<&PolicySnapshotV3>,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<(), String> {
    let private_root = path
        .parent()
        .ok_or_else(|| "native_policy_snapshot_authority_parent_missing".to_owned())
        .and_then(crate::resident_state::private_root_for_state_base)?;
    if generation_floor == 0
        || !is_lower_hex(policy_digest, 64)
        || snapshot.is_some_and(|candidate| {
            candidate.generation != generation_floor || candidate.policy_digest != policy_digest
        })
    {
        return Err("native_policy_snapshot_authority_invalid".to_owned());
    }
    let record = PolicyAuthorityRecordV3 {
        schema: AUTHORITY_RECORD_SCHEMA.to_owned(),
        generation_floor,
        policy_digest: policy_digest.to_owned(),
        snapshot: snapshot.cloned(),
        floor_mac: generation_floor_mac(generation_floor, policy_digest, verifier_key),
    };
    let value = serde_json::to_value(record)
        .map_err(|_| "native_policy_snapshot_authority_encode_failed".to_owned())?;
    let bytes = canonical_json_bytes(&value).map_err(snapshot_error)?;
    persist_private_bytes(
        path,
        &bytes,
        AUTHORITY_RECORD_MAX_BYTES,
        "authority",
        &private_root,
    )
}

pub(super) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
pub(super) fn map_private_read_error(kind: &str, error: String) -> String {
    if error.ends_with("_invalid") {
        format!("native_policy_snapshot_{kind}_invalid")
    } else if error.ends_with("_not_private") {
        format!("native_policy_snapshot_{kind}_not_private")
    } else {
        format!("native_policy_snapshot_{kind}_read_failed")
    }
}

pub(super) fn read_private_json(
    path: &Path,
    maximum_bytes: u64,
    kind: &str,
    private_root: &Path,
) -> Result<Option<(Value, Vec<u8>)>, String> {
    #[cfg(not(windows))]
    let _ = private_root;
    #[cfg(windows)]
    let mut file =
        match crate::resident_state::open_private_read(path, maximum_bytes, kind, private_root)
            .map_err(|error| map_private_read_error(kind, error))?
        {
            Some(file) => file,
            None => return Ok(None),
        };
    #[cfg(not(windows))]
    let mut file = {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(format!("native_policy_snapshot_{kind}_stat_failed")),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > maximum_bytes
        {
            return Err(format!("native_policy_snapshot_{kind}_invalid"));
        }
        #[cfg(unix)]
        let mut options = {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            options
        };
        #[cfg(not(unix))]
        let mut options = OpenOptions::new();
        options.read(true);
        options
            .open(path)
            .map_err(|_| format!("native_policy_snapshot_{kind}_read_failed"))?
    };
    let opened_metadata = file
        .metadata()
        .map_err(|_| format!("native_policy_snapshot_{kind}_invalid"))?;
    if !opened_metadata.is_file() || opened_metadata.len() > maximum_bytes {
        return Err(format!("native_policy_snapshot_{kind}_invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner = path
            .parent()
            .and_then(|parent| fs::symlink_metadata(parent).ok())
            .map(|metadata| metadata.uid());
        if owner != Some(opened_metadata.uid()) || opened_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(format!("native_policy_snapshot_{kind}_not_private"));
        }
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("native_policy_snapshot_{kind}_read_failed"))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!("native_policy_snapshot_{kind}_invalid"));
    }
    let value = crate::strict_json_value(&bytes)
        .map_err(|_| format!("native_policy_snapshot_{kind}_invalid"))?;
    Ok(Some((value, bytes)))
}

pub(super) fn persist_private_bytes(
    path: &Path,
    bytes: &[u8],
    maximum_bytes: u64,
    kind: &str,
    private_root: &Path,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > maximum_bytes {
        return Err(format!("native_policy_snapshot_{kind}_too_large"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("native_policy_snapshot_{kind}_parent_missing"))?;
    validate_private_directory(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_nanos();
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy-state"),
        std::process::id(),
        stamp
    ));
    #[cfg(not(windows))]
    let mut options = OpenOptions::new();
    #[cfg(not(windows))]
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    let mut file = match persistence_fault(PersistBoundary::TemporaryCreate).and_then(|()| {
        crate::resident_state::private_file(&temporary, true, private_root)
            .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
    }) {
        Ok(file) => file,
        Err(error) => {
            return Err(error);
        }
    };
    #[cfg(not(windows))]
    let mut file = match persistence_fault(PersistBoundary::TemporaryCreate).and_then(|()| {
        options
            .open(&temporary)
            .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
    }) {
        Ok(file) => file,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    let write_result = persistence_fault(PersistBoundary::Write)
        .and_then(|()| {
            file.write_all(bytes)
                .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
        })
        .and_then(|()| persistence_fault(PersistBoundary::FileSync))
        .and_then(|()| {
            file.sync_all()
                .map_err(|_| format!("native_policy_snapshot_{kind}_write_failed"))
        });
    if let Err(error) = write_result {
        #[cfg(windows)]
        let _ = guard_runtime_windows_process::delete_private_file_handle(&file);
        #[cfg(not(windows))]
        {
            drop(file);
            let _ = fs::remove_file(&temporary);
        }
        return Err(error);
    }
    #[cfg(not(windows))]
    drop(file);
    if let Err(error) = persistence_fault(PersistBoundary::Rename) {
        #[cfg(windows)]
        let _ = guard_runtime_windows_process::delete_private_file_handle(&file);
        #[cfg(not(windows))]
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    let result = replace_temporary(&temporary, path, kind, private_root);
    #[cfg(windows)]
    drop(file);
    #[cfg(not(windows))]
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    // On Windows the replacement helper may have committed the rename before
    // a post-commit identity/ACL check failed. Leave the source candidate for
    // the bounded startup recovery pass instead of deleting through a
    // pathname that may now designate the target.
    #[cfg(windows)]
    result?;
    #[cfg(unix)]
    {
        persistence_fault(PersistBoundary::DirectorySync)?;
        let directory =
            File::open(parent).map_err(|_| format!("native_policy_snapshot_{kind}_sync_failed"))?;
        directory
            .sync_all()
            .map_err(|_| format!("native_policy_snapshot_{kind}_sync_failed"))?;
    }
    // Windows has no directory fsync primitive exposed by std. Keep a
    // separate fault boundary for the post-replacement durability point so
    // recovery tests still exercise the ACK/retry state transition.
    #[cfg(windows)]
    persistence_fault(PersistBoundary::DirectorySync)?;
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn replace_temporary(
    temporary: &Path,
    path: &Path,
    kind: &str,
    _private_root: &Path,
) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))
}

#[cfg(windows)]
pub(super) fn replace_temporary(
    temporary: &Path,
    path: &Path,
    kind: &str,
    private_root: &Path,
) -> Result<(), String> {
    crate::resident_state::replace_windows_private_file(temporary, path, private_root)
        .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))
}

#[cfg(all(test, windows))]
mod windows_recovery_tests {
    use super::*;
    use std::io::Write;

    fn test_root(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-policy-recovery-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::resident_state::ensure_private_directory(&root, true).unwrap();
        root
    }

    fn private_bytes(path: &Path, bytes: &[u8]) {
        let private_root = path.parent().unwrap_or(path);
        let mut file = crate::resident_state::private_file(path, true, private_root).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn authority_recovery_replaces_only_valid_private_backup() {
        let root = test_root("backup");
        let target = root.join("policy-snapshot-v3.json");
        let backup = root.join(".policy-snapshot-v3.json.previous");
        private_bytes(&backup, b"previous");

        recover_authority_replacement(&target).unwrap();

        assert!(crate::resident_state::open_private_read(
            &target,
            AUTHORITY_RECORD_MAX_BYTES,
            "authority",
            &root,
        )
        .unwrap()
        .is_some());
        assert!(crate::resident_state::open_private_read(
            &backup,
            AUTHORITY_RECORD_MAX_BYTES,
            "authority",
            &root,
        )
        .unwrap()
        .is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn authority_recovery_rejects_non_file_backup() {
        let root = test_root("reparse-or-directory");
        let target = root.join("policy-snapshot-v3.json");
        let backup = root.join(".policy-snapshot-v3.json.previous");
        crate::resident_state::ensure_private_directory(&backup, true).unwrap();

        assert_eq!(
            recover_authority_replacement(&target).unwrap_err(),
            "native_policy_snapshot_authority_recovery_failed"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
