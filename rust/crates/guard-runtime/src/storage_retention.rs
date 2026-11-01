//! `storage-retention --stdin`: the Guard home sweeps that keep store
//! quarantine snapshots and updater staging from growing for the life of an
//! install (`guard/sqlite_recovery.py` and `guard/update_staging.py` before
//! they moved here).
//!
//! - `quarantine-prune` deletes quarantined store snapshots past the
//!   retention policy and answers how many files it removed.
//! - `quarantine-summary` answers the snapshot counts the daemon diagnostics
//!   report.
//! - `staging-prune` deletes updater staging older than `age_seconds`.
//!
//! A quarantine event is every `guard.db.corrupt-<id>` file sharing one id:
//! the snapshot, its `-wal` and `-shm` sidecars and its `.forensics.json`
//! record. Events are ordered newest first by the stamp encoded in the id
//! (`Path.replace` keeps the source database's mtime, so the file time is not
//! the quarantine time); ids without a stamp sort oldest, by mtime. The newest
//! `min_keep` events stay, and an older event stays only while it is within
//! `max_age_seconds` and the running byte budget. A forensic record is never
//! deleted. Symlinks are never followed, counted or deleted. The id prefix is
//! matched case-sensitively on every platform.
//!
//! The staging sweep is skipped while `update-runtime/active.json` is less
//! than seven days old, and when any component of the staging path is a link.
//! A stale directory is removed with `remove_dir_all`, which never follows a
//! link inside the tree and stops at the first entry it cannot remove.

use std::fs::{self, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::policy_bundle_time::{micros_to_utc_isoformat, strict_utc_micros};
use crate::skill_identity_platform::unsupported_reparse;

const SCHEMA: &str = "storage-retention.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const SNAPSHOT_PREFIX: &str = "guard.db.corrupt-";
const FORENSICS_SUFFIX: &str = ".forensics.json";
const UPDATE_RUNTIME_DIR_NAME: &str = "update-runtime";
const ACTIVITY_MARKER_NAME: &str = "active.json";
const ACTIVITY_WINDOW_SECONDS: f64 = 7.0 * 24.0 * 60.0 * 60.0;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: String,
    #[serde(default)]
    now: Option<f64>,
    #[serde(default)]
    min_keep: Option<u64>,
    #[serde(default)]
    max_age_seconds: Option<f64>,
    #[serde(default)]
    max_total_bytes: Option<i64>,
    #[serde(default)]
    age_seconds: Option<f64>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "storage-retention"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "storage_retention_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("storage_retention_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request, epoch_seconds(SystemTime::now()))?;
    serde_json::to_vec(&answer).map_err(|_| "storage_retention_response_unencodable".to_owned())
}

fn answer(request: &Request, now: f64) -> Result<Value, String> {
    let guard_home = PathBuf::from(&request.guard_home);
    if request.schema != SCHEMA || !guard_home.is_absolute() {
        return Err(invalid());
    }
    let finite = |value: Option<f64>| value.is_none_or(f64::is_finite);
    if !finite(request.now) || !finite(request.max_age_seconds) || !finite(request.age_seconds) {
        return Err(invalid());
    }
    match (
        request.op.as_str(),
        request.min_keep,
        request.max_age_seconds,
        request.max_total_bytes,
        request.age_seconds,
    ) {
        ("quarantine-prune", Some(min_keep), Some(max_age), Some(max_bytes), None) => {
            let policy = Retention {
                now: request.now.unwrap_or(now),
                min_keep,
                max_age_seconds: max_age,
                max_total_bytes: max_bytes,
            };
            Ok(json!({ "removed": prune_quarantine(&guard_home, &policy) }))
        }
        ("quarantine-summary", None, None, None, None) if request.now.is_none() => {
            Ok(quarantine_summary(&guard_home))
        }
        ("staging-prune", None, None, None, Some(age)) if request.now.is_none() => {
            prune_staging(&guard_home, age, now);
            Ok(json!({}))
        }
        _ => Err(invalid()),
    }
}

struct Retention {
    now: f64,
    min_keep: u64,
    max_age_seconds: f64,
    max_total_bytes: i64,
}

/// One quarantine event: its newest sort key, snapshot bytes (not counting
/// the forensic record) and newest file time.
struct Event {
    base: String,
    key: SortKey,
    bytes: u64,
    mtime: f64,
    has_snapshot: bool,
}

/// `(stamped, stamp, mtime)`: a stamped id outranks every unstamped one.
#[derive(Clone, PartialEq, PartialOrd)]
struct SortKey(bool, String, f64);

/// Every regular `guard.db.corrupt-*` file in `guard_home` with its
/// metadata. A listing failure ends the listing with what was read.
fn snapshot_files(guard_home: &Path) -> Vec<(String, Metadata)> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(guard_home) else {
        return files;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            break;
        };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !name.starts_with(SNAPSHOT_PREFIX) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            continue;
        }
        files.push((name, metadata));
    }
    files
}

/// The event id a quarantine file belongs to.
fn event_base(name: &str) -> &str {
    ["-wal", "-shm", FORENSICS_SUFFIX]
        .into_iter()
        .find_map(|ending| name.strip_suffix(ending))
        .unwrap_or(name)
}

/// The `%Y%m%dT%H%M%S%fZ` stamp after the prefix, when the id has that
/// exact shape (ASCII digits only); a digit-led but malformed id is not one.
fn event_stamp(base: &str) -> Option<&str> {
    let stamp = base.strip_prefix(SNAPSHOT_PREFIX)?;
    let bytes = stamp.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    let shaped = bytes.len() >= 22
        && digits(0..8)
        && bytes[8] == b'T'
        && digits(9..15)
        && digits(15..21)
        && bytes[21] == b'Z';
    shaped.then_some(stamp)
}

fn sort_key(base: &str, mtime: f64) -> SortKey {
    match event_stamp(base) {
        Some(stamp) => SortKey(true, stamp.to_owned(), mtime),
        None => SortKey(false, String::new(), mtime),
    }
}

/// The quarantine time the stamp encodes, or `mtime` for an id without a
/// valid one.
fn event_epoch_seconds(base: &str, mtime: f64) -> f64 {
    let Some(stamp) = event_stamp(base) else {
        return mtime;
    };
    let iso = format!(
        "{}-{}-{}T{}:{}:{}.{}Z",
        &stamp[0..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[9..11],
        &stamp[11..13],
        &stamp[13..15],
        &stamp[15..21],
    );
    match strict_utc_micros(&iso) {
        Some(micros) => micros as f64 / 1_000_000.0,
        None => mtime,
    }
}

fn prune_quarantine(guard_home: &Path, policy: &Retention) -> u64 {
    let mut events: Vec<Event> = Vec::new();
    for (name, metadata) in snapshot_files(guard_home) {
        let base = event_base(&name);
        let mtime = modified_seconds(&metadata);
        let key = sort_key(base, mtime);
        let index = match events.iter().position(|event| event.base == base) {
            Some(index) => index,
            None => {
                events.push(Event {
                    base: base.to_owned(),
                    key: key.clone(),
                    bytes: 0,
                    mtime: 0.0,
                    has_snapshot: false,
                });
                events.len() - 1
            }
        };
        let event = &mut events[index];
        if key > event.key {
            event.key = key;
        }
        if !name.ends_with(FORENSICS_SUFFIX) {
            event.bytes = event.bytes.saturating_add(metadata.len());
            event.has_snapshot = true;
        }
        event.mtime = event.mtime.max(mtime);
    }
    events.retain(|event| event.has_snapshot);
    // Stable, so events with equal keys keep listing order, as Python's
    // `sorted(..., reverse=True)` does.
    events.sort_by(|left, right| {
        right
            .key
            .partial_cmp(&left.key)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut removed = 0;
    let mut kept_bytes: i128 = 0;
    for (index, event) in events.iter().enumerate() {
        let keep = (index as u64) < policy.min_keep || {
            let age = policy.now - event_epoch_seconds(&event.base, event.mtime);
            age <= policy.max_age_seconds
                && kept_bytes + i128::from(event.bytes) <= i128::from(policy.max_total_bytes)
        };
        if keep {
            kept_bytes += i128::from(event.bytes);
            continue;
        }
        for ending in ["", "-wal", "-shm"] {
            let candidate = guard_home.join(format!("{}{ending}", event.base));
            // Recheck before unlinking: a sidecar may have been swapped for a
            // link since the listing, and a link is never followed or counted.
            let Ok(metadata) = fs::symlink_metadata(&candidate) else {
                continue;
            };
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                continue;
            }
            if fs::remove_file(&candidate).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

fn quarantine_summary(guard_home: &Path) -> Value {
    let mut total_bytes: u64 = 0;
    let mut forensic_record_count: u64 = 0;
    let mut events: Vec<(String, f64)> = Vec::new();
    for (name, metadata) in snapshot_files(guard_home) {
        total_bytes = total_bytes.saturating_add(metadata.len());
        if name.ends_with(FORENSICS_SUFFIX) {
            forensic_record_count += 1;
            continue;
        }
        let base = event_base(&name);
        let epoch = event_epoch_seconds(base, modified_seconds(&metadata));
        match events.iter_mut().find(|(known, _)| known == base) {
            Some((_, newest)) => *newest = newest.max(epoch),
            None => events.push((base.to_owned(), epoch)),
        }
    }
    let newest = events
        .iter()
        .map(|(_, epoch)| *epoch)
        .reduce(f64::max)
        .and_then(utc_isoformat);
    json!({
        "count": events.len(),
        "total_bytes": total_bytes,
        "newest_quarantined_at": newest,
        "forensic_record_count": forensic_record_count,
    })
}

/// `datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()`: the
/// fraction rounds half to even to whole microseconds. `None` out of range.
fn utc_isoformat(seconds: f64) -> Option<String> {
    let mut whole = seconds.trunc();
    let mut micros = ((seconds - whole) * 1_000_000.0).round_ties_even();
    if micros >= 1_000_000.0 {
        whole += 1.0;
        micros -= 1_000_000.0;
    } else if micros < 0.0 {
        whole -= 1.0;
        micros += 1_000_000.0;
    }
    let total = (whole as i64)
        .checked_mul(1_000_000)?
        .checked_add(micros as i64)?;
    micros_to_utc_isoformat(total, "+00:00")
}

fn prune_staging(guard_home: &Path, age_seconds: f64, now: f64) {
    let runtime = guard_home.join(UPDATE_RUNTIME_DIR_NAME);
    // Never traverse through a linked component: removing a tree below a
    // linked runtime directory would delete whatever the link points at.
    if !components_unlinked(&runtime) {
        return;
    }
    if let Ok(marker) = fs::metadata(runtime.join(ACTIVITY_MARKER_NAME)) {
        if now - modified_seconds(&marker) < ACTIVITY_WINDOW_SECONDS {
            return;
        }
    }
    let cutoff = now - age_seconds;
    let Ok(children) = fs::read_dir(&runtime) else {
        return;
    };
    for child in children {
        let Ok(child) = child else {
            return;
        };
        if child.file_name() == ACTIVITY_MARKER_NAME {
            continue;
        }
        let path = child.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if modified_seconds(&metadata) > cutoff {
            continue;
        }
        let file_type = metadata.file_type();
        if file_type.is_dir() && !file_type.is_symlink() {
            let _ = fs::remove_dir_all(&path);
        } else if fs::remove_file(&path).is_err() && file_type.is_symlink() {
            // A Windows directory link is removed as a directory.
            let _ = fs::remove_dir(&path);
        }
    }
}

/// Whether no existing component of `path` is a symlink, junction or other
/// reparse point. The walk stops at the first missing component; any other
/// failure to read a component answers `false`.
fn components_unlinked(path: &Path) -> bool {
    let mut current = PathBuf::new();
    let mut anchored = false;
    for component in path.components() {
        current.push(component.as_os_str());
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                anchored = true;
                continue;
            }
            _ if !anchored => return false,
            _ => {}
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || unsupported_reparse(&metadata) {
                    return false;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => return false,
        }
    }
    true
}

/// `st_mtime` as Python reads it: seconds since the epoch, negative before
/// it. An unreadable time reads as the epoch.
fn modified_seconds(metadata: &Metadata) -> f64 {
    metadata.modified().map(epoch_seconds).unwrap_or(0.0)
}

fn epoch_seconds(time: SystemTime) -> f64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_secs() as f64 + f64::from(after.subsec_nanos()) * 1e-9,
        Err(before) => {
            let before = before.duration();
            -(before.as_secs() as f64 + f64::from(before.subsec_nanos()) * 1e-9)
        }
    }
}

fn invalid() -> String {
    "storage_retention_request_invalid".to_owned()
}

#[cfg(test)]
#[path = "storage_retention_tests.rs"]
mod tests;
