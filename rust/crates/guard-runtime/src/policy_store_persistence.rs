use super::*;
use guard_policy_snapshot::{canonical_json_bytes, generation_floor_mac};
use serde_json::Value;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
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
    let target_exists = fs::symlink_metadata(path).is_ok();
    #[cfg(not(windows))]
    let _ = target_exists;
    #[cfg(windows)]
    {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("policy-snapshot-v3.json");
        let backup = parent.join(format!(".{file_name}.previous"));
        let backup_exists = fs::symlink_metadata(&backup).is_ok();
        if !target_exists && backup_exists {
            fs::rename(&backup, path)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        } else if target_exists && backup_exists {
            fs::remove_file(&backup)
                .map_err(|_| "native_policy_snapshot_authority_recovery_failed".to_owned())?;
        }
    }
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

pub(super) fn read_generation_floor(
    path: &Path,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<Option<GenerationFloorV1>, String> {
    let Some((value, bytes)) = read_private_json(path, MAX_FLOOR_BYTES, "floor")? else {
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
    persist_private_bytes(path, &bytes, AUTHORITY_RECORD_MAX_BYTES, "authority")
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

#[cfg(windows)]
pub(super) fn map_verifier_read_error(error: String) -> String {
    if error.ends_with("_invalid") {
        "native_policy_verifier_key_invalid".to_owned()
    } else if error.ends_with("_not_private") {
        "native_policy_verifier_key_not_private".to_owned()
    } else {
        "native_policy_verifier_key_read_failed".to_owned()
    }
}

pub(super) fn read_private_json(
    path: &Path,
    maximum_bytes: u64,
    kind: &str,
) -> Result<Option<(Value, Vec<u8>)>, String> {
    #[cfg(windows)]
    let mut file = match crate::resident_state::open_private_read(path, maximum_bytes, kind)
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
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
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
    #[cfg(windows)]
    if let Err(error) = crate::resident_state::protect_windows_private_path(&temporary, false) {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
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
    drop(file);
    let result = write_result.and_then(|()| {
        persistence_fault(PersistBoundary::Rename)?;
        replace_temporary(&temporary, path, kind)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return result;
    }
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
pub(super) fn replace_temporary(temporary: &Path, path: &Path, kind: &str) -> Result<(), String> {
    fs::rename(temporary, path).map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))
}

#[cfg(windows)]
pub(super) fn replace_temporary(temporary: &Path, path: &Path, kind: &str) -> Result<(), String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("policy-state");
    let backup = path.with_file_name(format!(".{file_name}.previous"));
    if fs::symlink_metadata(&backup).is_ok() {
        fs::remove_file(&backup)
            .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!("native_policy_snapshot_{kind}_replace_failed"));
        }
        fs::rename(path, &backup)
            .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))?;
    }
    if let Err(_) = fs::rename(temporary, path) {
        let _ = fs::rename(&backup, path);
        return Err(format!("native_policy_snapshot_{kind}_replace_failed"));
    }
    if fs::symlink_metadata(&backup).is_ok() {
        fs::remove_file(&backup)
            .map_err(|_| format!("native_policy_snapshot_{kind}_replace_failed"))?;
    }
    crate::resident_state::verify_windows_private_path(path, false)
}
