//! The daemon's lifecycle records under a Guard home: the signed state, the
//! signed pending-launch receipt and the discovery file, with the tombstone
//! and quarantine rules the retired Python `manager.py` applied to them.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::daemon_edge::standalone::{write_private_atomic, StateWriteLock};
use crate::daemon_policy_authority::{
    load_authenticated_daemon_state, load_daemon_discovery_key, read_private_regular_text,
    verify_daemon_state,
};

use super::host::{nt, resolve_lenient, same_text};

pub(super) const STATE_FILE: &str = "daemon-state.json";
const STATE_QUARANTINE_FILE: &str = "daemon-state.invalid.json";
const STATE_MAX_BYTES: u64 = 64 * 1024;
const PENDING_FILE: &str = "daemon-launch-pending.json";
const PENDING_QUARANTINE_FILE: &str = "daemon-launch-pending.invalid.json";
const PENDING_MAX_BYTES: u64 = 4096;
pub(super) const LOCATOR_FILE: &str = "approval-center-locator.json";
pub(super) const DISCOVERY_FILE: &str = "daemon-discovery-key";
const TOMBSTONE: &[u8] = b"{}";

pub(super) fn state_path(home: &Path) -> PathBuf {
    home.join(STATE_FILE)
}

pub(super) fn pending_path(home: &Path) -> PathBuf {
    home.join(PENDING_FILE)
}

/// `_launch_nonce_is_valid`: 64 lowercase hexadecimal characters.
pub(super) fn nonce_is_valid(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|nonce| {
        nonce.len() == 64
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(super) fn int(map: &Map<String, Value>, key: &str) -> Option<i64> {
    map.get(key)
        .filter(|value| value.is_i64() || value.is_u64())
        .and_then(Value::as_i64)
}

pub(super) fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

pub(super) fn owner(map: &Map<String, Value>) -> Option<&Value> {
    map.get("owner").or_else(|| map.get("user"))
}

/// `_load_state`: any JSON object in the state file, signed or not.
pub(super) fn load_state_unverified(home: &Path) -> Option<Map<String, Value>> {
    let path = state_path(home);
    if !path.is_file() {
        return None;
    }
    let raw = fs::read_to_string(path).ok()?;
    match serde_json::from_str(&raw).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// `load_authenticated_guard_daemon_pending_launch`.
pub(super) fn load_pending(home: &Path) -> Option<Map<String, Value>> {
    let raw = read_private_regular_text(&pending_path(home), PENDING_MAX_BYTES, true)?;
    let Value::Object(payload) = serde_json::from_str(&raw).ok()? else {
        return None;
    };
    let discovery = load_daemon_discovery_key(home)?;
    if !verify_daemon_state(&payload, &discovery)
        || text(&payload, "state_kind") != Some("daemon_launch_pending")
    {
        return None;
    }
    int(&payload, "pid").filter(|pid| *pid > 0)?;
    int(&payload, "port").filter(|port| (1..=65535).contains(port))?;
    let guard_home = text(&payload, "guard_home")?;
    if nt()
        && int(&payload, "process_creation_time")
            .filter(|time| *time > 0)
            .is_none()
    {
        return None;
    }
    if !nt() {
        let nonce = payload.get("launch_nonce");
        let filled = |key: &str| text(&payload, key).is_some_and(|value| !value.is_empty());
        if !nonce_is_valid(nonce)
            || payload.get("launch_generation") != nonce
            || payload.get("generation") != nonce
            || !filled("process_start_marker")
            || owner(&payload)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || !filled("runtime_fingerprint")
        {
            return None;
        }
    }
    if resolve_lenient(Path::new(guard_home)) != resolve_lenient(home) {
        return None;
    }
    Some(payload)
}

/// `_guard_daemon_pending_launch_is_generation_bound`.
pub(super) fn is_generation_bound(pending: Option<&Map<String, Value>>) -> bool {
    pending.is_some_and(|pending| {
        let nonce = pending.get("launch_nonce");
        nonce_is_valid(nonce)
            && pending.get("launch_generation") == nonce
            && pending.get("generation") == nonce
    })
}

/// `_guard_daemon_pending_launch_state_is_resolved`.
pub(super) fn pending_is_resolved(home: &Path) -> bool {
    let path = pending_path(home);
    !path.is_file() || is_exact_tombstone(&path)
}

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified_ns: i128,
}

fn identity(metadata: &fs::Metadata) -> Identity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
        }
    }
    #[cfg(not(unix))]
    {
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_nanos() as i128);
        Identity {
            device: 0,
            inode: 0,
            size: metadata.len(),
            modified_ns,
        }
    }
}

/// Reads up to `limit` bytes, proving the file did not change underneath.
fn stable_read(path: &Path, limit: u64) -> Option<(Vec<u8>, u64)> {
    let before = fs::symlink_metadata(path).ok()?;
    let mut file = File::open(path).ok()?;
    let mut raw = Vec::new();
    (&mut file).take(limit).read_to_end(&mut raw).ok()?;
    let opened = file.metadata().ok()?;
    let after = fs::symlink_metadata(path).ok()?;
    let first = identity(&before);
    if first != identity(&opened) || first != identity(&after) {
        return None;
    }
    Some((raw, before.len()))
}

/// `_daemon_lifecycle_artifact_is_quarantinable`.
fn is_quarantinable(path: &Path) -> bool {
    let (Some(parent), Ok(metadata)) = (path.parent(), fs::symlink_metadata(path)) else {
        return false;
    };
    let Ok(parent_metadata) = fs::symlink_metadata(parent) else {
        return false;
    };
    if !parent_metadata.is_dir() || !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = nix::unistd::getuid().as_raw();
        parent_metadata.uid() == uid && metadata.uid() == uid && parent_metadata.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `_daemon_lifecycle_artifact_is_exact_tombstone`.
pub(super) fn is_exact_tombstone(path: &Path) -> bool {
    if !is_quarantinable(path) {
        return false;
    }
    if fs::symlink_metadata(path).map(|m| m.len()).ok() != Some(2) {
        return false;
    }
    stable_read(path, 3).is_some_and(|(raw, _)| raw == TOMBSTONE)
}

fn write_tombstone(path: &Path) -> bool {
    write_private_atomic(path, TOMBSTONE).is_ok()
}

/// `_quarantine_daemon_lifecycle_artifact`.
fn quarantine(path: &Path, quarantine_path: &Path, max_preserved: u64) -> bool {
    if !is_quarantinable(path) {
        return false;
    }
    let Some((raw, size)) = stable_read(path, max_preserved + 1) else {
        return false;
    };
    if raw == TOMBSTONE && size == 2 && is_exact_tombstone(path) {
        return true;
    }
    if fs::rename(path, quarantine_path).is_err() {
        return false;
    }
    if raw.len() as u64 > max_preserved {
        let marker = json!({
            "original_size": size,
            "quarantined": true,
            "reason": "oversized_invalid_daemon_lifecycle_artifact",
        });
        if write_private_atomic(quarantine_path, marker.to_string().as_bytes()).is_err() {
            return false;
        }
    }
    write_tombstone(path)
}

/// `_reconcile_invalid_daemon_lifecycle_artifacts`: only after the caller
/// proved the process inventory empty.
pub(super) fn reconcile_invalid(home: &Path) -> bool {
    let Ok(_lock) = StateWriteLock::acquire(home) else {
        return false;
    };
    let state = state_path(home);
    if state.is_file() && load_authenticated_daemon_state(home).is_none() {
        if !quarantine(&state, &home.join(STATE_QUARANTINE_FILE), STATE_MAX_BYTES) {
            return false;
        }
        remove_invalid_discovery(home);
    }
    let pending = pending_path(home);
    !(nt()
        && pending.is_file()
        && load_pending(home).is_none()
        && !quarantine(
            &pending,
            &home.join(PENDING_QUARANTINE_FILE),
            PENDING_MAX_BYTES,
        ))
}

/// `_remove_invalid_daemon_discovery_key`.
pub(super) fn remove_invalid_discovery(home: &Path) -> bool {
    if load_daemon_discovery_key(home).is_some() {
        return false;
    }
    fs::remove_file(home.join(DISCOVERY_FILE)).is_ok()
}

/// `_clear_guard_daemon_pending_launch_if_current`.
pub(super) fn clear_pending_if_current(
    home: &Path,
    pid: i64,
    creation_time: Option<i64>,
    launch_nonce: Option<&str>,
    start_marker: Option<&str>,
) -> bool {
    let Ok(_lock) = StateWriteLock::acquire(home) else {
        return false;
    };
    let Some(pending) = load_pending(home) else {
        return !pending_path(home).is_file();
    };
    if int(&pending, "pid") != Some(pid) {
        return false;
    }
    if nt() && int(&pending, "process_creation_time") != creation_time {
        return false;
    }
    let field = |key: &str| text(&pending, key).unwrap_or_default().to_owned();
    if launch_nonce.is_some_and(|nonce| !same_text(&field("launch_nonce"), nonce)) {
        return false;
    }
    if start_marker.is_some_and(|marker| !same_text(&field("process_start_marker"), marker)) {
        return false;
    }
    write_tombstone(&pending_path(home))
}

/// `_clear_authenticated_guard_daemon_state_if_current`: tombstones only the
/// exact signed snapshot that was classified.
pub(super) fn clear_state_if_current(home: &Path, expected: &Map<String, Value>) -> bool {
    let Ok(_lock) = StateWriteLock::acquire(home) else {
        return false;
    };
    if load_authenticated_daemon_state(home).as_ref() != Some(expected) {
        return false;
    }
    write_tombstone(&state_path(home))
}

/// `clear_guard_daemon_state`.
pub(super) fn clear_state(home: &Path) -> std::io::Result<()> {
    ensure_private_directory(home)?;
    let _lock = StateWriteLock::acquire(home)?;
    write_private_atomic(&state_path(home), TOMBSTONE)
}

fn ensure_private_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
