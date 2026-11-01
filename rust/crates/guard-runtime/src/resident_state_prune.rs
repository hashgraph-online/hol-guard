//! `resident-state-prune --stdin`: remove dead native-resident state, the
//! stale `resident-v3-*` directories under `<guard_home>/native-runtime` and
//! the dead resident sockets (`resident_state_prune.py` before it moved here).
//!
//! Everything here is fail-closed. An entry is removed only when it is
//! provably unowned; any doubt (unreadable state, live or unverifiable pid,
//! held owner lock, socket that still answers, wrong uid, symlink, too
//! recent) keeps it.
//!
//! A `resident-v3-<digest>` directory is stale when:
//!
//! * it is a real directory (not a symlink) owned by the current user;
//! * neither it nor anything directly inside it changed within the minimum
//!   age;
//! * every `generation-*.json` parses, and both the resident `process_id` and
//!   `owner_process_id` it names are gone (a pid that cannot be proven dead
//!   counts as alive, so a recycled pid only delays pruning);
//! * the `managed-resident-owner.v1.lock` flock is free, and it is held
//!   exclusively while the directory is renamed to a tombstone, so no live
//!   resident can own it at that moment.
//!
//! A resident socket (`hook-v2-*.sock` from older builds, `h3-*.sock` from
//! current ones) is dead when it is a socket owned by this user, older than
//! the socket minimum age, and `connect()` is refused. POSIX only; Windows
//! answers `unsupported`.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::onefile_extraction_reclaim::pid_alive;
use crate::onefile_open_paths::{current_uid, metadata_uid};

use sockets::{
    default_socket_roots, probe_socket, prune_socket, socket_candidates, SYSTEM_TMP_BASES,
};

const COMMAND: &str = "resident-state-prune";
const SCHEMA: &str = "resident-state-prune.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const STATE_DIR_NAME: &str = "native-runtime";
const RESIDENT_DIR_PREFIX: &str = "resident-v3-";
const OWNER_LOCK_NAME: &str = "managed-resident-owner.v1.lock";
const GENERATION_PREFIX: &str = "generation-";
const GENERATION_SUFFIX: &str = ".json";
const STALE_DIR_MIN_AGE_SECONDS: f64 = 3600.0;
const STALE_SOCKET_MIN_AGE_SECONDS: f64 = 600.0;
const UNPARSEABLE_STATE_MIN_AGE_SECONDS: f64 = 24.0 * 3600.0;
const MAX_ENTRIES: usize = 2000;
const TIME_BUDGET: Duration = Duration::from_secs(30);
const MAX_STATE_BYTES: u64 = 64 * 1024;
const MAX_LISTED: usize = 50;
/// The listed paths together stay well inside the caller's 64 KiB answer.
const MAX_LISTED_BYTES: usize = 24 * 1024;
const SOCKET_SETTLE: Duration = Duration::from_millis(100);
const MAX_ERRORS: usize = 10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    guard_home: String,
    dry_run: bool,
    /// Whether to walk the `<tmp>/hgr-*` socket directories, which every
    /// Guard home on the account shares.
    include_system_sockets: bool,
}

/// What one prune did, in the shape the repair report shows.
#[derive(Debug, Default, Serialize)]
struct Report {
    outcome: &'static str,
    dry_run: bool,
    stale_dirs: usize,
    dead_sockets: usize,
    removed_dirs: Vec<String>,
    removed_sockets: Vec<String>,
    kept: BTreeMap<&'static str, u64>,
    budget_exhausted: bool,
    errors: Vec<&'static str>,
    #[serde(skip)]
    listed_bytes: usize,
}

impl Report {
    fn new(dry_run: bool) -> Self {
        Self {
            outcome: "ok",
            dry_run,
            ..Self::default()
        }
    }

    fn keep(&mut self, reason: &'static str) {
        *self.kept.entry(reason).or_default() += 1;
    }

    fn unavailable(mut self, error: &'static str) -> Self {
        self.outcome = "unavailable";
        self.errors.push(error);
        self
    }

    fn removed_dir(&mut self, directory: &Path) {
        self.stale_dirs += 1;
        if let Some(text) = self.listable(self.removed_dirs.len(), directory) {
            self.removed_dirs.push(text);
        }
    }

    fn removed_socket(&mut self, socket: &Path) {
        self.dead_sockets += 1;
        if let Some(text) = self.listable(self.removed_sockets.len(), socket) {
            self.removed_sockets.push(text);
        }
    }

    /// The path to list, while its list and the shared byte budget have
    /// room. The counts always cover every removal.
    fn listable(&mut self, listed: usize, item: &Path) -> Option<String> {
        let text = item.to_string_lossy().into_owned();
        // JSON escaping can at most double a path's bytes.
        let cost = text.len() * 2 + 4;
        if listed >= MAX_LISTED || self.listed_bytes + cost > MAX_LISTED_BYTES {
            return None;
        }
        self.listed_bytes += cost;
        Some(text)
    }

    fn error(&mut self, error: &'static str) {
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(error);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketState {
    Dead,
    Gone,
    Live,
    Unknown,
}

struct Settings {
    now: f64,
    min_age: f64,
    socket_min_age: f64,
    max_entries: usize,
    dry_run: bool,
    /// `None` walks the system socket directories; tests name their own.
    socket_roots: Option<Vec<PathBuf>>,
}

/// The operating-system facts one prune reads, so tests can stand in for
/// them.
trait Host {
    fn pid_alive(&mut self, pid: i64) -> bool;
    fn owner_lock_free(&mut self, directory: &Path) -> Option<bool>;
    fn probe_socket(&mut self, socket: &Path) -> SocketState;
    fn elapsed(&mut self) -> Duration;
    /// The pause between the two probes of a refused socket.
    fn settle(&mut self);
}

struct SystemHost {
    started: Instant,
}

impl Host for SystemHost {
    fn pid_alive(&mut self, pid: i64) -> bool {
        pid_alive(pid)
    }

    fn owner_lock_free(&mut self, directory: &Path) -> Option<bool> {
        owner_lock_free(directory)
    }

    fn probe_socket(&mut self, socket: &Path) -> SocketState {
        probe_socket(socket)
    }

    fn elapsed(&mut self) -> Duration {
        self.started.elapsed()
    }

    fn settle(&mut self) {
        std::thread::sleep(SOCKET_SETTLE);
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "resident_state_prune_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("resident_state_prune_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .ok()
        .filter(|request: &Request| {
            request.schema == SCHEMA && Path::new(&request.guard_home).is_absolute()
        })
        .ok_or_else(|| "resident_state_prune_request_invalid".to_owned())?;
    let report = if cfg!(unix) {
        let settings = Settings {
            now: unix_seconds(SystemTime::now()),
            min_age: STALE_DIR_MIN_AGE_SECONDS,
            socket_min_age: STALE_SOCKET_MIN_AGE_SECONDS,
            max_entries: MAX_ENTRIES,
            dry_run: request.dry_run,
            socket_roots: (!request.include_system_sockets).then(Vec::new),
        };
        let mut host = SystemHost {
            started: Instant::now(),
        };
        prune(Path::new(&request.guard_home), &settings, &mut host)
    } else {
        Report {
            outcome: "unsupported",
            ..Report::new(request.dry_run)
        }
    };
    serde_json::to_vec(&report).map_err(|_| "resident_state_prune_response_unencodable".to_owned())
}

fn prune(guard_home: &Path, settings: &Settings, host: &mut impl Host) -> Report {
    let mut report = Report::new(settings.dry_run);
    let state_dir = guard_home.join(STATE_DIR_NAME);
    let state_present = match fs::symlink_metadata(&state_dir) {
        Ok(metadata) if metadata.is_dir() && owned(&metadata) => true,
        Ok(_) => return report.unavailable("state_dir_untrusted"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return report.unavailable("state_dir_unreadable"),
    };
    let mut resident_dirs = Vec::new();
    if state_present {
        let Ok(entries) = fs::read_dir(&state_dir) else {
            return report.unavailable("state_dir_unreadable");
        };
        let mut children = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return report.unavailable("state_dir_unreadable");
            };
            children.push(entry.path());
        }
        children.sort();
        resident_dirs = children
            .into_iter()
            .filter(|child| name_of(child).starts_with(RESIDENT_DIR_PREFIX))
            .collect();
    }
    let mut handled = 0usize;
    let mut over_budget = |report: &mut Report, elapsed: Duration| {
        handled += 1;
        let exhausted = handled > settings.max_entries || elapsed > TIME_BUDGET;
        report.budget_exhausted |= exhausted;
        exhausted
    };
    for directory in &resident_dirs {
        if over_budget(&mut report, host.elapsed()) {
            return report;
        }
        match stale_dir_verdict(directory, settings, host) {
            "stale" => prune_resident_dir(directory, &mut report, settings.dry_run),
            reason => report.keep(reason),
        }
    }
    // Sockets: the state directory, each surviving resident directory, and
    // the tmp socket directories. A symlinked resident directory is never
    // walked.
    let mut roots: Vec<PathBuf> = state_present
        .then(|| state_dir.clone())
        .into_iter()
        .collect();
    roots.extend(
        resident_dirs
            .into_iter()
            .filter(|directory| fs::symlink_metadata(directory).is_ok_and(|item| item.is_dir())),
    );
    match &settings.socket_roots {
        Some(extra) => roots.extend(extra.iter().cloned()),
        None => roots.extend(default_socket_roots(&SYSTEM_TMP_BASES.map(Path::new))),
    }
    let (sockets, truncated) = socket_candidates(&roots, settings.max_entries + 1);
    for socket in sockets {
        if over_budget(&mut report, host.elapsed()) {
            return report;
        }
        prune_socket(&socket, &mut report, settings, host);
    }
    report.budget_exhausted |= truncated;
    report
}

/// `stale`, or the reason the directory must be kept.
fn stale_dir_verdict(directory: &Path, settings: &Settings, host: &mut impl Host) -> &'static str {
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return "unreadable";
    };
    if !metadata.is_dir() {
        return "not_directory";
    }
    if !owned(&metadata) {
        return "foreign_owner";
    }
    let Some(newest) = newest_mtime(directory, &metadata) else {
        return "unreadable";
    };
    let age = settings.now - newest;
    if age < settings.min_age {
        return "recent";
    }
    let (pids, clean) = generation_pids(directory);
    if !clean && age < UNPARSEABLE_STATE_MIN_AGE_SECONDS {
        return "unverifiable_state";
    }
    if pids.into_iter().any(|pid| host.pid_alive(pid)) {
        return "owner_alive";
    }
    if host.owner_lock_free(directory) != Some(true) {
        return "owner_lock_unverified";
    }
    "stale"
}

fn newest_mtime(directory: &Path, metadata: &Metadata) -> Option<f64> {
    let mut newest = mtime_seconds(metadata)?;
    for entry in fs::read_dir(directory).ok()? {
        // `DirEntry::metadata` never follows a symlink.
        newest = newest.max(mtime_seconds(&entry.ok()?.metadata().ok()?)?);
    }
    Some(newest)
}

/// The pids the generation files name; `false` when any one is unreadable or
/// names none.
fn generation_pids(directory: &Path) -> (Vec<i64>, bool) {
    let Ok(entries) = fs::read_dir(directory) else {
        return (Vec::new(), false);
    };
    let mut pids = Vec::new();
    let mut clean = true;
    for entry in entries {
        let Ok(entry) = entry else {
            clean = false;
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.len() < GENERATION_PREFIX.len() + GENERATION_SUFFIX.len()
            || !name.starts_with(GENERATION_PREFIX)
            || !name.ends_with(GENERATION_SUFFIX)
        {
            continue;
        }
        let named = read_generation(&entry.path());
        clean &= !named.is_empty();
        pids.extend(named);
    }
    (pids, clean)
}

fn read_generation(state: &Path) -> Vec<i64> {
    let Ok(metadata) = fs::symlink_metadata(state) else {
        return Vec::new();
    };
    if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
        return Vec::new();
    }
    let Ok(serde_json::Value::Object(payload)) = fs::read(state)
        .map_err(drop)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(drop))
    else {
        return Vec::new();
    };
    ["process_id", "owner_process_id"]
        .iter()
        .filter_map(|key| payload.get(*key)?.as_u64())
        .filter(|pid| *pid > 0)
        // A pid too large to name a process can never be proven dead.
        .map(|pid| i64::try_from(pid).unwrap_or(i64::MAX))
        .collect()
}

fn prune_resident_dir(directory: &Path, report: &mut Report, dry_run: bool) {
    if dry_run {
        report.removed_dir(directory);
        return;
    }
    let lock = match open_owner_lock(directory) {
        Ok(lock) => Some(lock),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            report.keep("owner_lock_unverified");
            return;
        }
    };
    if lock
        .as_ref()
        .is_some_and(|lock| fs2::FileExt::try_lock_exclusive(lock).is_err())
    {
        report.keep("owner_lock_unverified");
        return;
    }
    let tombstone = directory.with_file_name(format!(
        ".pruned-{}-{}",
        name_of(directory),
        std::process::id()
    ));
    let renamed = fs::rename(directory, &tombstone);
    drop(lock);
    if renamed.is_err() {
        report.keep("rename_failed");
        return;
    }
    // `remove_dir_all` never follows a symlink out of the tombstone.
    let _ = fs::remove_dir_all(&tombstone);
    if fs::symlink_metadata(&tombstone).is_ok() {
        report.error("tombstone_not_removed");
    }
    report.removed_dir(directory);
}

/// Whether the owner flock is free: `Some(true)` when free or never created,
/// `Some(false)` when held, `None` when it cannot tell.
fn owner_lock_free(directory: &Path) -> Option<bool> {
    let lock = match open_owner_lock(directory) {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Some(true),
        Err(_) => return None,
    };
    match fs2::FileExt::try_lock_shared(&lock) {
        Ok(()) => Some(true),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            Some(false)
        }
        Err(_) => None,
    }
}

#[cfg(unix)]
fn open_owner_lock(directory: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join(OWNER_LOCK_NAME))
}

#[cfg(not(unix))]
fn open_owner_lock(directory: &Path) -> io::Result<File> {
    File::open(directory.join(OWNER_LOCK_NAME))
}

/// Owned by the current user; everything is when the platform has no uids.
fn owned(metadata: &Metadata) -> bool {
    current_uid().is_none_or(|uid| metadata_uid(metadata) == Some(uid))
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn mtime_seconds(metadata: &Metadata) -> Option<f64> {
    metadata.modified().ok().map(unix_seconds)
}

fn unix_seconds(moment: SystemTime) -> f64 {
    match moment.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_secs_f64(),
        Err(before) => -before.duration().as_secs_f64(),
    }
}

#[path = "resident_state_prune_sockets.rs"]
mod sockets;

#[cfg(all(test, unix))]
#[path = "resident_state_prune_tests.rs"]
mod tests;
