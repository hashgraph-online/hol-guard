//! The file facts a Codex publication record is built from: the five-part
//! identity `codex_hook_rollback.rollback_file_identity` reports, the bounded
//! private read `private_file_io.read_private_regular_bytes` performs, and the
//! private write and restore `codex_hook_integrity` publishes with.

use std::fs;
use std::io::Read;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

use super::inspect::{file_identity, path_identity, recovery, MAX_SNAPSHOT};
use super::output::{managed_write, restore_absent};
use super::{Fault, Step};

const PRIVATE_MODE: u32 = 0o600;

fn conflict() -> Fault {
    Fault::Integrity(
        "codex_hook_rollback_conflict".to_owned(),
        "codex_hook_rollback_conflict: Codex publication needs recovery; Guard preserved the \
         recovery record and current files."
            .to_owned(),
    )
}

fn number(value: i128) -> Step<Value> {
    if let Ok(value) = u64::try_from(value) {
        return Ok(Value::from(value));
    }
    i64::try_from(value)
        .map(Value::from)
        .map_err(|_| conflict())
}

fn identity_value(parts: [i128; 5]) -> Step<Option<Value>> {
    let parts = parts.into_iter().map(number).collect::<Step<Vec<_>>>()?;
    Ok(Some(Value::Array(parts)))
}

fn link_metadata(path: &Path) -> Step<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(metadata) => Ok(Some(metadata)),
    }
}

/// `rollback_file_identity`: `(st_dev, st_ino, st_size, st_mtime_ns,
/// st_ctime_ns)` of a single-link regular file, `None` when it is absent.
#[cfg(unix)]
pub(crate) fn rollback_identity(path: &Path) -> Step<Option<Value>> {
    use std::os::unix::fs::MetadataExt;
    let Some(meta) = link_metadata(path)? else {
        return Ok(None);
    };
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err(conflict());
    }
    let nanos = |seconds: i64, nanos: i64| i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    identity_value([
        i128::from(meta.dev()),
        i128::from(meta.ino()),
        i128::from(meta.size()),
        nanos(meta.mtime(), meta.mtime_nsec()),
        nanos(meta.ctime(), meta.ctime_nsec()),
    ])
}

/// On Windows `os.lstat` reports the volume serial, the file id, and the
/// write and creation times in nanoseconds since 1970.
#[cfg(windows)]
pub(crate) fn rollback_identity(path: &Path) -> Step<Option<Value>> {
    const EPOCH_TICKS: i128 = 116_444_736_000_000_000;
    let Some(meta) = link_metadata(path)? else {
        return Ok(None);
    };
    if !meta.file_type().is_file()
        || !guard_runtime_windows_process::is_single_link_file(path).unwrap_or(false)
    {
        return Err(conflict());
    }
    let stat = guard_runtime_windows_process::link_stat(path)?;
    let nanos = |ticks: u64| (i128::from(ticks) - EPOCH_TICKS) * 100;
    identity_value([
        i128::from(stat.volume_serial),
        i128::try_from(stat.file_index).map_err(|_| conflict())?,
        i128::from(stat.size),
        nanos(stat.last_write_time),
        nanos(stat.creation_time),
    ])
}

/// `_encode`: base64 of at most one snapshot's bytes.
pub(crate) fn encode(value: Option<&[u8]>) -> Step<Value> {
    match value {
        None => Ok(Value::Null),
        Some(bytes) if bytes.len() > MAX_SNAPSHOT => Err(recovery("snapshot_too_large")),
        Some(bytes) => Ok(Value::String(STANDARD.encode(bytes))),
    }
}

#[cfg(unix)]
pub(super) fn private_metadata(metadata: &fs::Metadata, directory: bool) -> bool {
    use std::os::unix::fs::MetadataExt;
    let kind = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    kind && metadata.uid() == nix::unistd::getuid().as_raw() && metadata.mode() & 0o077 == 0
}

#[cfg(not(unix))]
pub(super) fn private_metadata(metadata: &fs::Metadata, directory: bool) -> bool {
    if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    }
}

#[cfg(unix)]
fn stable(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.mode() == after.mode()
        && before.size() == after.size()
        && (before.mtime(), before.mtime_nsec()) == (after.mtime(), after.mtime_nsec())
        && (before.ctime(), before.ctime_nsec()) == (after.ctime(), after.ctime_nsec())
}

#[cfg(windows)]
fn stable(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    before.file_size() == after.file_size() && before.last_write_time() == after.last_write_time()
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
}

/// `read_private_regular_bytes`: `None` for anything that is not a private
/// regular file read whole and unchanged through one descriptor.
pub(crate) fn read_private(path: &Path, max_bytes: usize, private_parent: bool) -> Option<Vec<u8>> {
    let parent = path.parent()?;
    let parent_before = if private_parent {
        let metadata = fs::symlink_metadata(parent).ok()?;
        if !private_metadata(&metadata, true) {
            return None;
        }
        Some(path_identity(parent).ok()?)
    } else {
        None
    };
    let before = fs::symlink_metadata(path).ok()?;
    if !private_metadata(&before, false) {
        return None;
    }
    let identity = path_identity(path).ok()?;
    let file = open_no_follow(path).ok()?;
    let opened = file.metadata().ok()?;
    if !private_metadata(&opened, false)
        || file_identity(&file, &opened).ok()? != identity
        || opened.len() > max_bytes as u64
    {
        return None;
    }
    let mut value = Vec::new();
    (&file)
        .take(max_bytes as u64)
        .read_to_end(&mut value)
        .ok()?;
    if !stable(&opened, &file.metadata().ok()?) {
        return None;
    }
    if let Some(parent_before) = parent_before {
        let after = fs::symlink_metadata(parent).ok()?;
        if !private_metadata(&after, true) || path_identity(parent).ok()? != parent_before {
            return None;
        }
    }
    Some(value)
}

/// `_ensure_private_directory(path, repair_mode=True)`.
fn ensure_private_directory(path: &Path) -> Step<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(Fault::Integrity(
            "codex_hook_manifest_directory_unsafe".to_owned(),
            "The Codex managed-hook directory is not a private regular directory.".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(Fault::Integrity(
                "codex_hook_manifest_directory_owner_mismatch".to_owned(),
                "The Codex managed-hook directory has an unexpected owner.".to_owned(),
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// `atomic_write_bytes(path, payload, mode=0o600, private=True)`.
pub(crate) fn write_private(path: &Path, payload: &[u8], events: &mut Vec<Value>) -> Step<()> {
    let parent = path.parent().ok_or(Fault::Transition("files_invalid"))?;
    fs::create_dir_all(parent)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(Fault::Integrity(
                "codex_hook_transaction_target_not_regular".to_owned(),
                format!(
                    "Guard refused to replace a non-regular managed file at {}.",
                    path.display()
                ),
            ));
        }
        _ => {}
    }
    ensure_private_directory(parent)?;
    events.push(managed_write(path, payload, PRIVATE_MODE)?);
    Ok(())
}

/// `restore_private_file(path, payload)`.
pub(crate) fn restore_private(
    path: &Path,
    payload: Option<&[u8]>,
    events: &mut Vec<Value>,
) -> Step<()> {
    match payload {
        Some(payload) => write_private(path, payload, events),
        None => {
            events.push(restore_absent(path)?);
            Ok(())
        }
    }
}

/// `require_unchanged_config_for_rollback`: under the lifecycle lock, the
/// config is still the original or the written generation, byte for byte and
/// inode for inode. It does not fence writers that ignore the lock.
pub(crate) fn require_unchanged_for_rollback(
    path: &Path,
    original: Option<&[u8]>,
    written: &[u8],
    original_identity: &Value,
    written_identity: &Value,
) -> Step<()> {
    let present = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(conflict()),
        Ok(_) => true,
    };
    if !present {
        if original.is_none() && written_identity.is_null() {
            return Ok(());
        }
        return Err(conflict());
    }
    let before = rollback_identity(path)?.ok_or_else(conflict)?;
    let limit = original.map_or(0, <[u8]>::len).max(written.len());
    let size_of = |identity: &Value| identity.get(2).and_then(Value::as_u64);
    if size_of(&before).is_none_or(|size| size > limit as u64) {
        return Err(conflict());
    }
    let file = open_no_follow(path).map_err(|_| conflict())?;
    let mut current = Vec::new();
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut current)
        .map_err(|_| conflict())?;
    drop(file);
    let identity = rollback_identity(path)?.ok_or_else(conflict)?;
    if identity != before {
        return Err(conflict());
    }
    let is_original =
        original.is_some_and(|original| current == original) && &identity == original_identity;
    let is_written =
        !written_identity.is_null() && current == written && &identity == written_identity;
    if is_original || is_written {
        Ok(())
    } else {
        Err(conflict())
    }
}
