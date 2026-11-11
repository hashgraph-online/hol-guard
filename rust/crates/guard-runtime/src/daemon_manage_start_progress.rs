//! A spawned daemon that missed its start deadline but is still starting
//! (`classify_spawned_daemon` and `_record_guard_daemon_start_progress`).
//!
//! A cold frozen Core on a loaded machine can spend most of the start window
//! unpacking and importing before it hands over to the native daemon, and the
//! native daemon reconciles Guard's hooks before it answers health checks.
//! Killing such a child turns a slow start into a failed one. Instead the
//! launcher records a signed progress marker, leaves the child and its pending
//! receipt in place, and answers that the daemon is still starting, so the
//! caller waits for the handoff.
//!
//! Only evidence the spawned child alone can produce counts, so a foreign
//! process can never keep a stuck launch alive:
//! - signed daemon state that binds this launch's nonce, which only the
//!   spawned child was given, or
//! - the early heartbeat the frozen entry point writes before importing Guard,
//!   recorded after the spawn and naming a pid in the child's process tree.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Map;

use crate::daemon_edge::standalone::write_signed_record;
use crate::daemon_policy_authority::read_private_regular_text;

use super::host::{self, Caller};
use super::retire;

pub(super) const PROGRESS_FILE: &str = "daemon-start-progress.json";
/// Read by `scripts/mdm/hol-guard-entry.py`, which writes `<pid> <time_ns>`.
pub(super) const HEARTBEAT_ENV: &str = "HOL_GUARD_DAEMON_START_HEARTBEAT";
const HEARTBEAT_FILE: &str = "daemon-start-heartbeat";
const HEARTBEAT_MAX_BYTES: u64 = 256;
/// How long after the spawn a child that has only written its heartbeat
/// still counts as starting; past it the child is treated as silent.
const SLOW_START_MAX: Duration = Duration::from_secs(180);
const PPID_WALK_LIMIT: usize = 16;

pub(super) fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_nanos()).unwrap_or(i64::MAX)
        })
}

pub(super) fn heartbeat_path(home: &Path) -> PathBuf {
    home.join(HEARTBEAT_FILE)
}

/// Removes a heartbeat an earlier launch left, so only this child's counts.
pub(super) fn clear_heartbeat(home: &Path) {
    let _ = fs::remove_file(heartbeat_path(home));
}

/// Whether the child that missed its deadline, still running, has shown it
/// is starting rather than stuck.
pub(super) fn child_is_progressing(
    caller: &Caller,
    nonce: &str,
    root_pid: i64,
    spawned_at_ns: i64,
) -> bool {
    retire::handoff_matches_launch(caller, nonce, root_pid)
        || heartbeat_names_child(caller, root_pid, spawned_at_ns, now_ns())
}

/// Records the signed marker a later starter reads to wait for this child
/// instead of retiring it. `marker` is the child's process start marker.
pub(super) fn record(home: &Path, pid: i64, port: i64, marker: &str, spawned_at_ns: i64) -> bool {
    let mut progress = Map::new();
    progress.insert("state_kind".into(), "daemon_start_progress".into());
    progress.insert(
        "guard_home".into(),
        host::resolve_lenient(home)
            .to_string_lossy()
            .into_owned()
            .into(),
    );
    progress.insert("pid".into(), pid.into());
    progress.insert("port".into(), port.into());
    progress.insert(format!("process_start_{}", "token"), marker.into());
    progress.insert("recorded_at_ns".into(), now_ns().into());
    progress.insert("spawned_at_ns".into(), spawned_at_ns.into());
    write_signed_record(home, PROGRESS_FILE, progress).is_ok()
}

fn heartbeat_names_child(caller: &Caller, root_pid: i64, spawned_at_ns: i64, now: i64) -> bool {
    let Some((pid, recorded_at_ns)) = load_heartbeat(&caller.guard_home) else {
        return false;
    };
    let window = i64::try_from(SLOW_START_MAX.as_nanos()).unwrap_or(i64::MAX);
    recorded_at_ns > spawned_at_ns
        && recorded_at_ns <= now
        && now.saturating_sub(spawned_at_ns) < window
        && in_spawned_tree(caller, pid, root_pid)
}

fn load_heartbeat(home: &Path) -> Option<(i64, i64)> {
    let raw = read_private_regular_text(&heartbeat_path(home), HEARTBEAT_MAX_BYTES, true)?;
    let mut fields = raw.split_ascii_whitespace();
    let (pid, recorded_at_ns) = (fields.next()?, fields.next()?);
    if fields.next().is_some()
        || ![pid, recorded_at_ns]
            .iter()
            .all(|field| field.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let pid: i64 = pid.parse().ok().filter(|pid| *pid > 0)?;
    let recorded_at_ns: i64 = recorded_at_ns.parse().ok().filter(|at| *at > 0)?;
    Some((pid, recorded_at_ns))
}

/// The spawned process itself or one of its descendants (a onefile
/// bootloader runs Guard in a child process).
fn in_spawned_tree(caller: &Caller, pid: i64, root_pid: i64) -> bool {
    if pid <= 0 || root_pid <= 0 {
        return false;
    }
    if retire::is_spawned_launch(caller, pid, root_pid) {
        return true;
    }
    if host::nt() {
        return false;
    }
    let mut current = pid;
    for _ in 0..PPID_WALK_LIMIT {
        match host::parent_pid(current) {
            Some(parent) if parent == root_pid => return true,
            Some(parent) if parent > 1 => current = parent,
            _ => return false,
        }
    }
    false
}
