//! Reading a transition file without trusting it: the bounded snapshot from
//! `codex_hook_recovery._snapshot`, the pinned-dependency shape from
//! `_validate_digest_dependency`, and the artifact and invocation checks from
//! `_artifact_digest` and `_invocation_generation`.

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{Ask, Budget, Fault, Step};
use crate::codex_hook_file_identity_op::{permission_rules, FileFacts, IdentityAsk};

pub(crate) const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
const RECOVERY_MESSAGE: &str =
    "Codex publication needs recovery; Guard preserved the recovery record and current files.";
#[cfg(windows)]
const REPARSE_POINT: u32 = 0x400;

pub(crate) fn recovery(reason: &str) -> Fault {
    Fault::Integrity(
        format!("codex_hook_recovery_{reason}"),
        RECOVERY_MESSAGE.to_owned(),
    )
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// `codex_hook_recovery._decode`.
pub(crate) fn decode(value: Option<&Value>) -> Step<Option<Vec<u8>>> {
    let text = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(text)) => text,
        Some(_) => return Err(recovery("snapshot_invalid")),
    };
    if text.len() > 4 * MAX_SNAPSHOT.div_ceil(3) {
        return Err(recovery("snapshot_invalid"));
    }
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| recovery("snapshot_invalid"))?;
    if bytes.len() > MAX_SNAPSHOT {
        return Err(recovery("snapshot_too_large"));
    }
    Ok(Some(bytes))
}

/// The spelling `Path.resolve()` gives: the verbatim prefix Windows adds to a
/// canonical path is not part of it.
pub(crate) fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

/// `Path.resolve(strict=False)`: the existing prefix canonicalized, the rest
/// appended as written, with a `..` in the rest popping what precedes it.
pub(crate) fn resolve_lenient(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut current = path;
    loop {
        if let Ok(canonical) = fs::canonicalize(current) {
            let mut resolved = plain(canonical);
            for component in rest.iter().rev() {
                if *component == OsStr::new("..") {
                    resolved.pop();
                } else {
                    resolved.push(*component);
                }
            }
            return resolved;
        }
        // `file_name()` is `None` for a trailing `..`, so walk the components.
        let (Some(parent), Some(last)) = (current.parent(), current.components().next_back())
        else {
            return path.to_path_buf();
        };
        rest.push(last.as_os_str());
        current = parent;
    }
}

pub(crate) fn mode_of(path: &Path) -> Step<u32> {
    let metadata = fs::metadata(path)?;
    Ok(permission_bits(&metadata))
}

#[cfg(unix)]
fn permission_bits(metadata: &fs::Metadata) -> u32 {
    std::os::unix::fs::MetadataExt::mode(metadata) & 0o777
}

#[cfg(not(unix))]
fn permission_bits(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn open_no_follow(path: &Path, nonblocking: bool) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let extra = if nonblocking { libc::O_NONBLOCK } else { 0 };
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | extra)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path, _nonblocking: bool) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT: a link is opened as itself, then refused.
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x0020_0000)
        .open(path)
}

#[cfg(unix)]
fn opened_file_refused(file: &fs::File, metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let _ = file;
    metadata.nlink() != 1 || metadata.uid() != nix::unistd::geteuid().as_raw()
}

#[cfg(windows)]
fn opened_file_refused(file: &fs::File, metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & REPARSE_POINT != 0
        || !guard_runtime_windows_process::is_single_link_handle(file).unwrap_or(false)
}

/// The identity `(st_dev, st_ino)` both a path and an open file report.
#[cfg(unix)]
pub(super) fn path_identity(path: &Path) -> std::io::Result<(u64, u128)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path)?;
    Ok((metadata.dev(), u128::from(metadata.ino())))
}

#[cfg(unix)]
pub(super) fn file_identity(
    _file: &fs::File,
    metadata: &fs::Metadata,
) -> std::io::Result<(u64, u128)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev(), u128::from(metadata.ino())))
}

#[cfg(windows)]
pub(super) fn path_identity(path: &Path) -> std::io::Result<(u64, u128)> {
    let stat = guard_runtime_windows_process::link_stat(path)?;
    Ok((stat.volume_serial, stat.file_index))
}

#[cfg(windows)]
pub(super) fn file_identity(
    file: &fs::File,
    _metadata: &fs::Metadata,
) -> std::io::Result<(u64, u128)> {
    let hex = guard_runtime_windows_process::handle_file_id(file)?.to_hex();
    let (volume, id) = hex.split_once('-').unwrap_or_default();
    let volume = u64::from_str_radix(volume, 16).unwrap_or_default();
    let bytes: Vec<u8> = (0..id.len())
        .step_by(2)
        .filter_map(|at| u8::from_str_radix(id.get(at..at + 2)?, 16).ok())
        .collect();
    let bytes: [u8; 16] = bytes.try_into().unwrap_or_default();
    Ok((volume, u128::from_le_bytes(bytes)))
}

/// `codex_hook_recovery._snapshot`: a regular file this account owns, read
/// whole through one descriptor that still names the path afterwards.
pub(crate) fn snapshot(path: &Path, budget: &Budget) -> Step<Option<Vec<u8>>> {
    budget.hook()?;
    let file = match open_no_follow(path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            budget.hook()?;
            let linked = fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
            if linked {
                return Err(recovery("target_invalid"));
            }
            return Ok(None);
        }
        Err(_) => {
            budget.hook()?;
            return Err(recovery("target_invalid"));
        }
    };
    budget.hook()?;
    let opened = file.metadata()?;
    budget.hook()?;
    if !opened.is_file()
        || opened.len() > MAX_SNAPSHOT as u64
        || opened_file_refused(&file, &opened)
    {
        return Err(recovery("target_invalid"));
    }
    let identity = file_identity(&file, &opened)?;
    let mut value = Vec::new();
    (&file)
        .take(MAX_SNAPSHOT as u64 + 1)
        .read_to_end(&mut value)?;
    budget.hook()?;
    let current = path_identity(path)?;
    budget.hook()?;
    if value.len() > MAX_SNAPSHOT || identity != current {
        return Err(recovery("target_changed"));
    }
    Ok(Some(value))
}

fn whole(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

/// Owner ids an artifact may carry here: root or this account, off Windows.
fn owner_acceptable(owner: Option<&Value>) -> bool {
    match owner {
        Some(Value::Null) => cfg!(windows),
        Some(value) => match value.as_i64() {
            Some(owner) if owner >= 0 => !cfg!(unix) || owner == 0 || owner == effective_uid(),
            _ => false,
        },
        None => false,
    }
}

#[cfg(unix)]
fn effective_uid() -> i64 {
    i64::from(nix::unistd::geteuid().as_raw())
}

#[cfg(not(unix))]
fn effective_uid() -> i64 {
    -1
}

fn bounded_text(value: &Value, limit: usize) -> bool {
    value
        .as_str()
        .is_some_and(|text| (1..=limit).contains(&text.chars().count()) && !text.contains('\0'))
}

/// `_validate_digest_dependency`.
pub(crate) fn validate_digest_dependency(change: &Map<String, Value>) -> Step<()> {
    let digest_ok = change
        .get("expected_digest")
        .and_then(Value::as_str)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    let null = |key: &str| change.get(key).is_none_or(Value::is_null);
    if !digest_ok
        || !null("before")
        || !null("after")
        || change.get("before_mode") != change.get("after_mode")
        || change.get("kind").and_then(Value::as_str) != Some("binding")
        || change.get("no_follow").and_then(Value::as_bool) != Some(true)
    {
        return Err(Fault::Transition("authority_dependency_invalid"));
    }
    if let Some(identity) = change.get("artifact_identity") {
        let artifact_invalid = Fault::Transition("artifact_dependency_invalid");
        let Some(identity) = identity.as_object() else {
            return Err(artifact_invalid);
        };
        let keys: Vec<&str> = identity.keys().map(String::as_str).collect();
        let shaped = matches!(keys.len(), 2 | 3)
            && identity.contains_key("size")
            && identity.contains_key("owner_uid")
            && (keys.len() == 2 || identity.contains_key("role"));
        let role_ok = identity
            .get("role")
            .is_none_or(|role| bounded_text(role, 128));
        let size_ok = whole(identity.get("size")).is_some_and(|size| size >= 0);
        if !shaped || !role_ok || !size_ok || !owner_acceptable(identity.get("owner_uid")) {
            return Err(artifact_invalid);
        }
    }
    if let Some(invocation) = change.get("invocation_identity") {
        let invalid = Fault::Transition("invocation_dependency_invalid");
        let Some(invocation) = invocation.as_object() else {
            return Err(invalid);
        };
        let shaped = change.contains_key("artifact_identity")
            && invocation.len() == 4
            && ["path", "mode", "owner_uid", "link_target"]
                .iter()
                .all(|key| invocation.contains_key(*key));
        if !shaped {
            return Err(invalid);
        }
        let path = &invocation["path"];
        let path_ok =
            bounded_text(path, 4096) && path.as_str().is_some_and(|p| Path::new(p).is_absolute());
        let mode_ok = whole(invocation.get("mode")).is_some_and(|mode| (0..=0o777).contains(&mode));
        let link = &invocation["link_target"];
        let link_ok = link.is_null() || bounded_text(link, 4096);
        if !path_ok || !mode_ok || !link_ok || !owner_acceptable(invocation.get("owner_uid")) {
            return Err(invalid);
        }
    }
    Ok(())
}

#[path = "artifact.rs"]
mod artifact;
pub(crate) use artifact::{artifact_digest, invocation_generation};
