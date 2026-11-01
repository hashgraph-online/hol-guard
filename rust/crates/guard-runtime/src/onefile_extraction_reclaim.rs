//! `onefile-extraction-reclaim --stdin`: delete the PyInstaller `_MEI*`
//! extraction directories that leaked from hard-killed Guard launches
//! (`guard/onefile_extraction.py` and `guard/onefile_unmarked.py` before
//! they moved here).
//!
//! A onefile launch extracts to `<tempdir>/_MEIxxxxxx` and its bootloader
//! parent removes that directory on a normal exit. Each launch stamps an owner
//! marker with its pid and the bootloader parent pid, so a marked directory is
//! deleted once both are provably dead. An unmarked directory has no pid to
//! check: it is deleted only when the caller asks for the open-files scan, the
//! directory is provably a Guard extraction, this user owns it, it is older
//! than the unmarked floor, and the one system-wide scan
//! (`onefile_open_paths`) shows no process using it. Otherwise it is only
//! counted. Every liveness check fails closed: a pid that cannot be proven dead
//! is alive, and a failed scan skips every unmarked directory.

use std::collections::BTreeSet;
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::onefile_open_paths;

const SCHEMA: &str = "onefile-extraction-reclaim.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const OWNER_MARKER_NAME: &str = ".hol-guard-extraction-owner.json";
const OWNER_MARKER_SCHEMA: &str = "guard.onefile-extraction-owner.v1";
const OWNER_MARKER_MAX_BYTES: u64 = 4096;
const EXTRACTION_PREFIX: &str = "_MEI";
const MIN_EXTRACTION_SUFFIX: usize = 4;
/// Extracted late, so its presence means the extraction finished.
const BUNDLE_SENTINEL: [&str; 5] = [
    "codex_plugin_scanner",
    "guard",
    "daemon",
    "static",
    "index.html",
];
const PACKAGE_DIR_NAME: &str = "codex_plugin_scanner";
const MAX_RECORDED_ERRORS: usize = 8;
const UNMARKED_BYTES_SAMPLE_LIMIT: u64 = 10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    temp_root: String,
    current_meipass: Option<String>,
    now: f64,
    min_age_seconds: f64,
    unmarked_min_age_seconds: f64,
    max_unmarked_reclaims: u64,
    unmarked_time_budget_seconds: Option<f64>,
    scan_open_paths: bool,
    dry_run: bool,
}

/// What one sweep did, in the shape `ExtractionReclaimResult` reads.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct ReclaimResult {
    reclaimed_count: u64,
    reclaimed_bytes: u64,
    killed_launches: u64,
    unmarked_count: u64,
    unmarked_bytes_estimate: u64,
    unmarked_reclaimed_count: u64,
    unmarked_reclaimed_bytes: u64,
    partial_reclaimed_count: u64,
    /// `disabled` (no scan asked for), `not_needed`, `ok`, or `unavailable`
    /// (the scan failed, so every unmarked directory was skipped).
    unmarked_scan: &'static str,
    unmarked_budget_exhausted: bool,
    errors: Vec<String>,
}

impl ReclaimResult {
    fn new() -> Self {
        Self {
            unmarked_scan: "disabled",
            ..Self::default()
        }
    }

    fn remember_error(&mut self, detail: String) {
        if self.errors.len() < MAX_RECORDED_ERRORS {
            self.errors.push(detail);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unmarked {
    /// The dashboard sentinel exists: a finished Guard extraction.
    Bundle,
    /// No sentinel, but a real top-level package directory: a Guard
    /// extraction that was cut short.
    Partial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Owner {
    pid: i64,
    parent_pid: i64,
}

struct Settings {
    current_meipass: Option<PathBuf>,
    now: f64,
    min_age_seconds: f64,
    unmarked_min_age_seconds: f64,
    max_unmarked_reclaims: u64,
    unmarked_time_budget: Option<Duration>,
    scan_open_paths: bool,
    dry_run: bool,
}

/// The operating-system facts one sweep reads, so tests can stand in for them.
trait Host {
    fn pid_alive(&mut self, pid: i64) -> bool;
    fn open_paths(&mut self, temp_root: &Path) -> Option<BTreeSet<String>>;
    fn elapsed(&mut self) -> Duration;
    fn remove_dir_all(&mut self, path: &Path) -> io::Result<()>;
    fn owned_by_current_user(&mut self, metadata: &Metadata) -> bool;
}

struct SystemHost {
    started: Instant,
}

impl Host for SystemHost {
    fn pid_alive(&mut self, pid: i64) -> bool {
        pid_alive(pid)
    }

    fn open_paths(&mut self, temp_root: &Path) -> Option<BTreeSet<String>> {
        onefile_open_paths::scan_system(temp_root)
    }

    fn elapsed(&mut self) -> Duration {
        self.started.elapsed()
    }

    fn remove_dir_all(&mut self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }

    fn owned_by_current_user(&mut self, metadata: &Metadata) -> bool {
        let owner = onefile_open_paths::metadata_uid(metadata);
        owner.is_some() && owner == onefile_open_paths::current_uid()
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "onefile-extraction-reclaim"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "onefile_extraction_reclaim_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("onefile_extraction_reclaim_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let (temp_root, settings) = settings(request)?;
    let mut host = SystemHost {
        started: Instant::now(),
    };
    let result = reclaim(&temp_root, &settings, &mut host);
    serde_json::to_vec(&result)
        .map_err(|_| "onefile_extraction_reclaim_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "onefile_extraction_reclaim_request_invalid".to_owned()
}

fn settings(request: Request) -> Result<(PathBuf, Settings), String> {
    let temp_root = PathBuf::from(&request.temp_root);
    let seconds_valid = |seconds: f64| seconds.is_finite() && seconds >= 0.0;
    if request.schema != SCHEMA
        || !temp_root.is_absolute()
        || !request.now.is_finite()
        || !seconds_valid(request.min_age_seconds)
        || !seconds_valid(request.unmarked_min_age_seconds)
        || request
            .unmarked_time_budget_seconds
            .is_some_and(|seconds| !seconds_valid(seconds))
    {
        return Err(invalid());
    }
    let current_meipass = request
        .current_meipass
        .filter(|path| !path.is_empty())
        .and_then(|path| fs::canonicalize(path).ok());
    Ok((
        temp_root,
        Settings {
            current_meipass,
            now: request.now,
            min_age_seconds: request.min_age_seconds,
            unmarked_min_age_seconds: request.unmarked_min_age_seconds,
            max_unmarked_reclaims: request.max_unmarked_reclaims,
            unmarked_time_budget: request
                .unmarked_time_budget_seconds
                .map(Duration::from_secs_f64),
            scan_open_paths: request.scan_open_paths,
            dry_run: request.dry_run,
        },
    ))
}

/// One sweep over `temp_root`. Work on unmarked directories is bounded by
/// the reclaim count and the time budget; the rest are only counted. A dry
/// run still runs every proof and counts what it would delete.
fn reclaim(temp_root: &Path, settings: &Settings, host: &mut impl Host) -> ReclaimResult {
    let mut result = ReclaimResult::new();
    let Ok(resolved_root) = fs::canonicalize(temp_root) else {
        result.remember_error("temp_root_unavailable".to_owned());
        return result;
    };
    let Some(children) = sorted_children(temp_root) else {
        result.remember_error("temp_root_listing_failed".to_owned());
        return result;
    };
    let mut sampled_count = 0_u64;
    let mut sampled_bytes = 0_u64;
    let mut in_use: Option<BTreeSet<String>> = None;
    let mut scan_attempted = false;
    for child in children {
        let Some(name) = child.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !is_extraction_name(name) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(&child) else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }
        let Ok(resolved_child) = fs::canonicalize(&child) else {
            continue;
        };
        if resolved_child.parent() != Some(resolved_root.as_path())
            || settings.current_meipass.as_ref() == Some(&resolved_child)
        {
            continue;
        }
        let Some(mtime) = mtime_seconds(&metadata) else {
            continue;
        };
        let age_seconds = settings.now - mtime;
        if age_seconds < settings.min_age_seconds {
            continue;
        }
        let marker = child.join(OWNER_MARKER_NAME);
        if let Some(owner) = read_owner_marker(&marker) {
            if host.pid_alive(owner.pid) || host.pid_alive(owner.parent_pid) {
                continue;
            }
            // Re-read the marker right before deleting, so a live launch
            // that rewrote it is not swept out from under itself.
            if read_owner_marker(&marker) != Some(owner) {
                continue;
            }
            let Some(size) = remove_dir(&child, settings.dry_run, host, &mut result) else {
                continue;
            };
            result.reclaimed_count += 1;
            result.reclaimed_bytes += size;
            result.killed_launches += 1;
            continue;
        }
        let Some(kind) = classify_unmarked(&child) else {
            continue;
        };
        let reclaimable = settings.scan_open_paths
            && age_seconds >= settings.unmarked_min_age_seconds
            && host.owned_by_current_user(&metadata);
        if reclaimable && !scan_attempted {
            scan_attempted = true;
            in_use = host.open_paths(&resolved_root);
            result.unmarked_scan = if in_use.is_some() {
                "ok"
            } else {
                "unavailable"
            };
            if in_use.is_none() {
                result.remember_error("open_path_scan_unavailable".to_owned());
            }
        }
        if let Some(in_use) = in_use.as_ref().filter(|_| reclaimable) {
            let exhausted = result.unmarked_reclaimed_count >= settings.max_unmarked_reclaims
                || settings
                    .unmarked_time_budget
                    .is_some_and(|budget| host.elapsed() >= budget);
            if exhausted {
                result.unmarked_budget_exhausted = true;
            } else if !in_use.contains(name)
                && reclaim_unmarked(&child, &metadata, kind, settings.dry_run, host, &mut result)
            {
                continue;
            }
        }
        result.unmarked_count += 1;
        // Walking every legacy directory on the hourly sweep is too costly
        // on hosts with hundreds of leaks; sample a bounded set and estimate.
        if sampled_count < UNMARKED_BYTES_SAMPLE_LIMIT {
            sampled_count += 1;
            sampled_bytes += dir_bytes(&child);
        }
    }
    if settings.scan_open_paths && !scan_attempted {
        result.unmarked_scan = "not_needed";
    }
    if sampled_count > 0 {
        let estimate = sampled_bytes as f64 / sampled_count as f64 * result.unmarked_count as f64;
        result.unmarked_bytes_estimate = estimate.round_ties_even() as u64;
    }
    result
}

/// Delete one proven-dead unmarked directory; true when it was removed.
fn reclaim_unmarked(
    child: &Path,
    listed: &Metadata,
    kind: Unmarked,
    dry_run: bool,
    host: &mut impl Host,
    result: &mut ReclaimResult,
) -> bool {
    let Ok(recheck) = fs::symlink_metadata(child) else {
        return false;
    };
    // A launch that touched the directory since it was listed is alive.
    if mtime_seconds(&recheck) != mtime_seconds(listed) || !same_inode(&recheck, listed) {
        return false;
    }
    // Any marker file, even a corrupt one, means a launch claimed it.
    if fs::symlink_metadata(child.join(OWNER_MARKER_NAME)).is_ok() {
        return false;
    }
    let Some(size) = remove_dir(child, dry_run, host, result) else {
        return false;
    };
    result.reclaimed_count += 1;
    result.reclaimed_bytes += size;
    result.unmarked_reclaimed_count += 1;
    result.unmarked_reclaimed_bytes += size;
    if kind == Unmarked::Partial {
        result.partial_reclaimed_count += 1;
    }
    true
}

/// The directory's size, once it is deleted (or would be, in a dry run).
fn remove_dir(
    path: &Path,
    dry_run: bool,
    host: &mut impl Host,
    result: &mut ReclaimResult,
) -> Option<u64> {
    let size = dir_bytes(path);
    if dry_run {
        return Some(size);
    }
    match host.remove_dir_all(path) {
        Ok(()) => Some(size),
        Err(error) => {
            result.remember_error(format!("rmtree:{}", error_class(&error)));
            None
        }
    }
}

/// The Python exception class name the error used to surface as.
fn error_class(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::PermissionDenied => "PermissionError",
        io::ErrorKind::NotFound => "FileNotFoundError",
        _ => "OSError",
    }
}

fn sorted_children(temp_root: &Path) -> Option<Vec<PathBuf>> {
    let mut children = fs::read_dir(temp_root)
        .ok()?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<Vec<_>>>()
        .ok()?;
    children.sort();
    Some(children)
}

/// `_MEI` followed by at least four ASCII letters or digits.
fn is_extraction_name(name: &str) -> bool {
    name.strip_prefix(EXTRACTION_PREFIX).is_some_and(|suffix| {
        suffix.len() >= MIN_EXTRACTION_SUFFIX
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}

/// Whether an unmarked directory is provably a Guard extraction. Empty
/// directories, other PyInstaller apps, and launches killed before any Guard
/// file landed are not identified. A mypyc runtime next to a bundled
/// `libpython` is deliberately not a signature: any onefile app built with
/// mypyc-compiled dependencies has the same layout.
fn classify_unmarked(directory: &Path) -> Option<Unmarked> {
    let sentinel = BUNDLE_SENTINEL
        .iter()
        .fold(directory.to_path_buf(), |path, part| path.join(part));
    if fs::metadata(sentinel).is_ok_and(|metadata| metadata.is_file()) {
        return Some(Unmarked::Bundle);
    }
    fs::symlink_metadata(directory.join(PACKAGE_DIR_NAME))
        .is_ok_and(|metadata| metadata.is_dir())
        .then_some(Unmarked::Partial)
}

/// The marker's pids, only when it is a small regular file with the owner
/// schema and integer pids.
fn read_owner_marker(marker: &Path) -> Option<Owner> {
    let metadata = fs::symlink_metadata(marker).ok()?;
    if !metadata.is_file() || metadata.len() > OWNER_MARKER_MAX_BYTES {
        return None;
    }
    let bytes = fs::read(marker).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let payload = payload.as_object()?;
    if payload.get("schema")?.as_str()? != OWNER_MARKER_SCHEMA {
        return None;
    }
    let pid = |key: &str| payload.get(key).and_then(serde_json::Value::as_i64);
    Some(Owner {
        pid: pid("pid")?,
        parent_pid: pid("parent_pid")?,
    })
}

/// Total size of the files below `root`, without following links. Entries
/// that vanish or cannot be read are skipped.
fn dir_bytes(root: &Path) -> u64 {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(path);
            } else if !(metadata.file_type().is_symlink() && path.is_dir()) {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

fn mtime_seconds(metadata: &Metadata) -> Option<f64> {
    let modified = metadata.modified().ok()?;
    Some(match modified.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_secs_f64(),
        Err(before) => -before.duration().as_secs_f64(),
    })
}

#[cfg(unix)]
fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_inode(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

/// Fail closed: a pid that cannot be proven dead counts as alive.
#[cfg(unix)]
fn pid_alive(pid: i64) -> bool {
    let Some(pid) = i32::try_from(pid).ok().filter(|pid| *pid > 0) else {
        return true;
    };
    !matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    )
}

/// Fail closed: a pid that cannot be proven dead counts as alive.
#[cfg(not(unix))]
fn pid_alive(pid: i64) -> bool {
    u32::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .is_none_or(|pid| guard_runtime_windows_process::process_liveness(pid) != Some(false))
}

#[cfg(test)]
#[path = "onefile_extraction_reclaim_tests.rs"]
mod tests;
