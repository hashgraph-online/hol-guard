//! The daemon lifecycle journal (`<guard home>/daemon-lifecycle/`): one small
//! private JSON file per event, read back by `load_events` without opening
//! Guard SQLite. Writing is best effort, as it was for the daemon.
//!
//! Every hook that cannot reach the daemon asks for recovery, so recovery
//! events keep their own short ring (`*.recovery.json`). They no longer push
//! the daemon's own start, exit and retirement history out of the journal.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub(crate) const DIRECTORY: &str = "daemon-lifecycle";
const RECOVERY_PREFIX: &str = "recovery_";
const RECOVERY_SUFFIX: &str = ".recovery.json";
/// Daemon starts, exits and retirements: weeks of history, not days.
const MAX_LIFECYCLE_ENTRIES: usize = 2048;
const MAX_RECOVERY_ENTRIES: usize = 128;
const MAX_LOADED_ENTRIES: usize = 128;
const MAX_EVENT_BYTES: u64 = 2048;
const MAX_INCIDENT_SCAN: usize = MAX_LIFECYCLE_ENTRIES + MAX_RECOVERY_ENTRIES + 256;
const MAX_INCIDENT_ENTRIES: usize = 20;
/// How many recent lifecycle records a starting daemon reads to find the
/// daemons before it that stopped without saying why.
const MAX_PREDECESSOR_SCAN: usize = 256;
const MAX_LOCATION_BYTES: usize = 96;

/// Records that give a daemon's run a known end. `death_observed` is
/// written when a launcher finds the published daemon gone; it names no
/// cause, but the exit is already on record.
pub(crate) const TERMINAL_EVENTS: [&str; 6] = [
    "death_observed",
    "exiting",
    "retirement_requested",
    "shutdown_requested",
    "start_failed",
    "unclean_exit_detected",
];
/// Records only a daemon that published its state writes.
const STARTED_EVENTS: [&str; 6] = [
    "published",
    "workers_started",
    "hook_worker_warming",
    "ready",
    "reconciled",
    "reconcile_deferred",
];
/// Records also written to `logs/daemon.log`, where people look first.
const LOGGED_EVENTS: [&str; 10] = [
    "published",
    "ready",
    "reconcile_deferred",
    "exiting",
    "start_failed",
    "retirement_requested",
    "shutdown_requested",
    "unclean_exit_detected",
    "repair_requested",
    "leftover_left_alone",
];

/// The optional fields of one record.
#[derive(Clone, Copy, Default)]
pub(crate) struct Details<'a> {
    pub(crate) reason: Option<&'a str>,
    pub(crate) session_id: Option<&'a str>,
    pub(crate) port: Option<u16>,
    /// The process that wrote a record about another one, such as the
    /// caller that retired a daemon, and that caller's parent.
    pub(crate) by_pid: Option<u32>,
    pub(crate) by_parent_pid: Option<u32>,
    /// `file.rs:line` of the panic that ended a daemon.
    pub(crate) location: Option<&'a str>,
}

/// Records `event` for this process; failures are ignored.
pub(super) fn record(
    guard_home: &Path,
    event: &str,
    reason: Option<&str>,
    session_id: Option<&str>,
    port: Option<u16>,
) {
    let details = Details {
        reason,
        session_id,
        port,
        ..Details::default()
    };
    let _ = write(guard_home, std::process::id(), event, &details);
}

/// Records `event` on behalf of another process, such as a daemon being
/// retired; failures are ignored.
pub(crate) fn record_for_pid(
    guard_home: &Path,
    pid: u32,
    event: &str,
    reason: Option<&str>,
    session_id: Option<&str>,
) {
    let details = Details {
        reason,
        session_id,
        ..Details::default()
    };
    record_details(guard_home, pid, event, &details);
}

/// Records `event` for `pid` with every field in `details`; failures are
/// ignored.
pub(crate) fn record_details(guard_home: &Path, pid: u32, event: &str, details: &Details<'_>) {
    if pid > 0 {
        let _ = write(guard_home, pid, event, details);
    }
}

/// Before a daemon reports ready, gives each earlier daemon of this home that
/// started, never recorded why it stopped, and is now proven gone an
/// `unclean_exit_detected` record. A SIGKILL, a crash or a power loss leaves
/// no record of its own, so this is the only trace those exits leave.
pub(super) fn record_unclean_exits(guard_home: &Path) {
    let own_pid = std::process::id();
    for pid in unexplained_predecessors(guard_home, own_pid) {
        if crate::onefile_extraction_reclaim::pid_alive(i64::from(pid)) {
            continue;
        }
        let details = Details {
            reason: Some("no_exit_record"),
            by_pid: Some(own_pid),
            ..Details::default()
        };
        record_details(guard_home, pid, "unclean_exit_detected", &details);
    }
}

/// The pids, other than `own_pid`, whose latest start in the recent journal
/// has no terminal record after it.
fn unexplained_predecessors(guard_home: &Path, own_pid: u32) -> Vec<u32> {
    let directory = guard_home.join(DIRECTORY);
    if is_symlink(&directory) {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            !name.starts_with('.') && name.ends_with(".json") && !name.ends_with(RECOVERY_SUFFIX)
        })
        .collect();
    names.sort_unstable_by(|left, right| right.cmp(left));
    names.truncate(MAX_PREDECESSOR_SCAN);
    // Newest first, back to the pid's `published`: a terminal record anywhere
    // in that run ends it. A daemon stopped while it starts can journal its
    // exit before a later start step (`ready` is written after the ready
    // line), so the newest record alone does not say whether the run ended.
    let mut runs: HashMap<u32, (bool, bool)> = HashMap::new();
    let mut published: HashSet<u32> = HashSet::new();
    let mut order = Vec::new();
    for name in &names {
        let Some(event) = read_event(&directory.join(name)) else {
            continue;
        };
        let (Some(pid), Some(kind)) = (
            event
                .get("pid")
                .and_then(Value::as_u64)
                .and_then(|pid| u32::try_from(pid).ok()),
            event.get("event").and_then(Value::as_str),
        ) else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        let (started, ended) = runs.entry(pid).or_insert_with(|| {
            order.push(pid);
            (false, false)
        });
        if published.contains(&pid) {
            continue;
        }
        if TERMINAL_EVENTS.contains(&kind) {
            *ended = true;
        } else if STARTED_EVENTS.contains(&kind) {
            *started = true;
            if kind == "published" {
                published.insert(pid);
            }
        }
    }
    order
        .into_iter()
        .filter(|pid| {
            runs.get(pid)
                .is_some_and(|(started, ended)| *started && !*ended)
        })
        .collect()
}

fn write(guard_home: &Path, pid: u32, event: &str, details: &Details<'_>) -> Option<()> {
    if !safe_label(event) || details.reason.is_some_and(|reason| !safe_label(reason)) {
        return None;
    }
    if details.session_id.is_some_and(|id| !safe_session_id(id))
        || details.port == Some(0)
        || details.by_pid == Some(0)
        || details.by_parent_pid == Some(0)
        || details
            .location
            .is_some_and(|location| !safe_location(location))
    {
        return None;
    }
    let directory = guard_home.join(DIRECTORY);
    if is_symlink(guard_home) || is_symlink(&directory) {
        return None;
    }
    fs::create_dir_all(&directory).ok()?;
    if !directory.is_dir() {
        return None;
    }
    private_mode(&directory, 0o700);
    let recorded_at_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    // Keys sorted, as `json.dumps(..., sort_keys=True)` wrote them.
    let mut payload = Map::new();
    if let Some(by_parent_pid) = details.by_parent_pid {
        payload.insert("by_parent_pid".into(), by_parent_pid.into());
    }
    if let Some(by_pid) = details.by_pid {
        payload.insert("by_pid".into(), by_pid.into());
    }
    payload.insert("event".into(), event.into());
    if let Some(location) = details.location {
        payload.insert("location".into(), location.into());
    }
    payload.insert("pid".into(), pid.into());
    if let Some(port) = details.port {
        payload.insert("port".into(), port.into());
    }
    if let Some(reason) = details.reason {
        payload.insert("reason".into(), reason.into());
    }
    payload.insert(
        "recorded_at_ns".into(),
        Value::from(u64::try_from(recorded_at_ns).ok()?),
    );
    if let Some(session_id) = details.session_id {
        payload.insert("session_id".into(), session_id.into());
    }
    payload.insert("version".into(), 1.into());
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    let identifier = hex::encode(nonce);
    let suffix = if event.starts_with(RECOVERY_PREFIX) {
        RECOVERY_SUFFIX
    } else {
        ".json"
    };
    let target = directory.join(format!(
        "{recorded_at_ns:020}-{pid:010}-{identifier}{suffix}"
    ));
    let temporary = directory.join(format!(".{identifier}.tmp"));
    let written = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).ok()?;
        file.write_all(Value::Object(payload).to_string().as_bytes())
            .ok()?;
        file.sync_all().ok()?;
        drop(file);
        fs::rename(&temporary, &target).ok()
    })();
    let _ = fs::remove_file(&temporary);
    written?;
    private_mode(&target, 0o600);
    prune(&directory);
    if LOGGED_EVENTS.contains(&event) {
        log_line(guard_home, pid, event, details);
    }
    Some(())
}

/// One `daemon_lifecycle` line in `logs/daemon.log`: labels and numbers only.
fn log_line(guard_home: &Path, pid: u32, event: &str, details: &Details<'_>) {
    let mut detail = format!("{event} pid={pid}");
    if let Some(reason) = details.reason {
        detail.push_str(&format!(" reason={reason}"));
    }
    if let Some(port) = details.port {
        detail.push_str(&format!(" port={port}"));
    }
    if let Some(by_pid) = details.by_pid {
        detail.push_str(&format!(" by_pid={by_pid}"));
    }
    if let Some(location) = details.location {
        detail.push_str(&format!(" location={location}"));
    }
    let _ = super::reads::record_diagnostic(guard_home, "daemon_lifecycle", Some(&detail));
}

/// Keeps the newest records of each ring. Records written before the rings
/// were split count toward the lifecycle ring and age out of it.
fn prune(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut lifecycle = Vec::new();
    let mut recovery = Vec::new();
    for name in entries.filter_map(|entry| entry.ok().map(|entry| entry.file_name())) {
        let text = name.to_string_lossy();
        if text.starts_with('.') || !text.ends_with(".json") {
            continue;
        }
        if text.ends_with(RECOVERY_SUFFIX) {
            recovery.push(name);
        } else {
            lifecycle.push(name);
        }
    }
    for (mut names, keep) in [
        (lifecycle, MAX_LIFECYCLE_ENTRIES),
        (recovery, MAX_RECOVERY_ENTRIES),
    ] {
        names.sort();
        let excess = names.len().saturating_sub(keep);
        for name in &names[..excess] {
            let _ = fs::remove_file(directory.join(name));
        }
    }
}

/// The newest `limit` valid events, oldest first. `incident` caps the
/// directory scan and the timeline, and reports why entries are missing:
/// `ok`, `invalid_entries_omitted`, `journal_unavailable`,
/// `journal_path_unsafe` or `journal_scan_limit`.
pub(crate) fn load_events(
    guard_home: &Path,
    limit: usize,
    incident: bool,
) -> (Vec<Value>, &'static str) {
    let directory = guard_home.join(DIRECTORY);
    if is_symlink(&directory) {
        return (Vec::new(), "journal_path_unsafe");
    }
    let Ok(entries) = fs::read_dir(&directory) else {
        return (Vec::new(), "journal_unavailable");
    };
    let mut names = Vec::new();
    for (index, entry) in entries.enumerate() {
        if incident && index >= MAX_INCIDENT_SCAN {
            return (Vec::new(), "journal_scan_limit");
        }
        let Ok(entry) = entry else {
            return (Vec::new(), "journal_unavailable");
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") && (incident || !name.starts_with('.')) {
            names.push(name);
        }
    }
    let cap = if incident {
        MAX_INCIDENT_ENTRIES
    } else {
        MAX_LOADED_ENTRIES
    };
    names.sort_unstable_by(|left, right| right.cmp(left));
    names.truncate(limit.min(cap));
    let mut invalid = false;
    let mut events = Vec::new();
    for name in &names {
        match read_event(&directory.join(name)) {
            Some(event) => events.push(event),
            None => invalid = true,
        }
    }
    events.reverse();
    (
        events,
        if invalid {
            "invalid_entries_omitted"
        } else {
            "ok"
        },
    )
}

pub(crate) fn read_event(path: &Path) -> Option<Value> {
    let raw =
        crate::daemon_policy_authority::read_private_regular_text(path, MAX_EVENT_BYTES, false)?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let event = value.as_object()?;
    let optional_text = |key: &str, check: fn(&str) -> bool| {
        event
            .get(key)
            .is_none_or(|item| item.as_str().is_some_and(check))
    };
    let pid_ok = |key: &str| {
        event.get(key).is_none_or(|pid| {
            pid.as_u64()
                .is_some_and(|pid| pid > 0 && u32::try_from(pid).is_ok())
        })
    };
    let port_ok = event.get("port").is_none_or(|port| {
        port.as_u64()
            .is_some_and(|port| (1..=65_535).contains(&port))
    });
    let valid = event.get("version").and_then(Value::as_i64) == Some(1)
        && event
            .get("event")
            .and_then(Value::as_str)
            .is_some_and(safe_label)
        && event
            .get("recorded_at_ns")
            .and_then(Value::as_u64)
            .is_some_and(|at| at > 0)
        && event
            .get("pid")
            .and_then(Value::as_u64)
            .is_some_and(|pid| pid > 0)
        && optional_text("session_id", safe_session_id)
        && optional_text("reason", safe_label)
        && optional_text("location", safe_location)
        && pid_ok("by_pid")
        && pid_ok("by_parent_pid")
        && port_ok;
    valid.then_some(value)
}

/// `^[a-z][a-z0-9_-]{0,63}$`.
fn safe_label(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && value.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

/// `file.rs:line`: `^[A-Za-z0-9_.:-]{1,96}$`, with no path separators.
fn safe_location(value: &str) -> bool {
    (1..=MAX_LOCATION_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

/// `^[A-Za-z0-9_-]{1,128}$`.
fn safe_session_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

#[cfg(unix)]
fn private_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn private_mode(_path: &Path, _mode: u32) {}

#[cfg(test)]
#[path = "daemon_edge_lifecycle_tests.rs"]
mod tests;
