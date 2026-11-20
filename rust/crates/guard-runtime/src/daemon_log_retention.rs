//! Daily rotation and seven-day retention for `logs/daemon.log`.
//!
//! The daemon owns both, as the Python daemon's midnight `TimedRotatingFileHandler`
//! did: a log last written before today (UTC) moves to `daemon.log.YYYY-MM-DD`,
//! named for the day it was written, and rotated logs older than seven days or
//! beyond the seven newest are deleted. One-shot writers only ever append, so
//! a hook never renames the live log out from under the daemon.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::policy_bundle_time::micros_to_utc_isoformat;

const LOG_DIRECTORY: &str = "logs";
const LOG_NAME: &str = "daemon.log";
const BACKUP_COUNT: usize = 7;
const RETENTION_MICROS: i64 = 7 * 86_400_000_000;

/// Rotates and prunes the daemon log for the instant `now` (UTC microseconds).
/// Every failure leaves the files as they were; diagnostics never fail a pass.
pub(crate) fn rotate(guard_home: &Path, now: i64) {
    let directory = guard_home.join(LOG_DIRECTORY);
    if fs::symlink_metadata(&directory).map_or(true, |metadata| !metadata.is_dir()) {
        return;
    }
    if let Some(today) = utc_date(now) {
        roll_over(&directory, &today);
    }
    prune(&directory, now);
}

fn utc_date(micros: i64) -> Option<String> {
    micros_to_utc_isoformat(micros, "+00:00").and_then(|text| text.get(..10).map(str::to_owned))
}

fn modified_micros(metadata: &fs::Metadata) -> Option<i64> {
    let elapsed = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(elapsed.as_micros()).ok()
}

/// Moves a log last written on an earlier day to that day's backup name.
fn roll_over(directory: &Path, today: &str) {
    let live = directory.join(LOG_NAME);
    let Ok(metadata) = fs::symlink_metadata(&live) else {
        return;
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return;
    }
    let Some(written) = modified_micros(&metadata).and_then(utc_date) else {
        return;
    };
    if written.as_str() >= today {
        return;
    }
    let backup = directory.join(format!("{LOG_NAME}.{written}"));
    // As the rotating handler did, a backup already holding that day's name
    // is replaced rather than appended to.
    if fs::symlink_metadata(&backup).is_ok_and(|existing| existing.is_file()) {
        let _ = fs::remove_file(&backup);
    }
    if fs::symlink_metadata(&backup).is_err() {
        let _ = fs::rename(&live, &backup);
    }
}

/// Deletes rotated logs older than the retention window, then all but the
/// newest `BACKUP_COUNT` that remain.
fn prune(directory: &Path, now: i64) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let prefix = format!("{LOG_NAME}.");
    let mut kept = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let expired =
            modified_micros(&metadata).is_some_and(|written| written < now - RETENTION_MICROS);
        if expired {
            let _ = fs::remove_file(entry.path());
        } else if is_dated_backup(&name[prefix.len()..]) {
            kept.push(name.to_owned());
        }
    }
    kept.sort();
    let excess = kept.len().saturating_sub(BACKUP_COUNT);
    for name in kept.into_iter().take(excess) {
        let _ = fs::remove_file(directory.join(name));
    }
}

/// `YYYY-MM-DD`, the only suffix the rotation writes.
fn is_dated_backup(suffix: &str) -> bool {
    let bytes = suffix.as_bytes();
    bytes.len() == 10
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

#[cfg(all(test, unix))]
#[path = "daemon_log_retention_tests.rs"]
mod tests;
