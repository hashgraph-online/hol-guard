//! `orphaned-worker-reap --stdin`: stop Guard hook workers left behind when
//! their daemon is stopped (`guard/daemon/orphaned_daemon_workers.py` before
//! it moved here).
//!
//! Hook workers call `setsid()` so a crash stays inside the worker. That also
//! means killing the daemon process does not kill them. The survivors keep the
//! local store open, and the replacement daemon blocks on that store before it
//! can publish daemon state.
//!
//! A worker is orphaned when its parent chain has no live daemon and no other
//! live hol-guard process that is not itself a hook worker. Workers of a live
//! daemon, including a daemon for another home, are left alone.
//!
//! The request names the caller's pid, which is never signalled, and an
//! optional `budget_ms` that bounds the process listing and the grace period.
//! Each signal is sent only while the pid still has the listed command and
//! the start token captured for that worker, so a reused pid is skipped. The
//! answer lists the selected, signalled and forced pids. Off Unix the command
//! answers `orphaned_worker_reap_unsupported`.

// The selection and stop loop only run on Unix; their tests run everywhere.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "orphaned-worker-reap.v1";
const MAX_REQUEST_BYTES: u64 = 4096;
const MAX_BUDGET_MS: u64 = 60_000;
const LISTING_TIMEOUT: Duration = Duration::from_secs(5);
const GRACE: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(50);
const MAX_PARENT_HOPS: usize = 8;
const HOOK_WORKER_COMMAND_MARKER: &str = "--hol-guard-hook-worker";
const FORK_MARKER: &str = "--multiprocessing-fork";
const TRACKER_MARKER: &str = "from multiprocessing.resource_tracker import main";
const HOL_GUARD_EXECUTABLES: [&str; 4] = [
    "hol-guard",
    "hol-guard.exe",
    "plugin-guard",
    "plugin-guard.exe",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    self_pid: u32,
    #[serde(default)]
    budget_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProcessSnapshot {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) state: String,
    pub(crate) command: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Terminate,
    Kill,
}

/// The process table and signals the reaper acts on.
pub(crate) trait Host {
    /// `ps -axww -o pid=,ppid=,state=,command=` output, or `None`.
    fn listing(&self, timeout: Duration) -> Option<String>;
    /// The pid's current command line, or `None` when it cannot be read.
    fn command(&self, pid: u32) -> Option<String>;
    /// The pid's start token, or `None` when it cannot be read.
    fn start_token(&self, pid: u32) -> Option<String>;
    /// Signal the pid's own process group, else the pid.
    fn signal(&self, pid: u32, stop: Stop);
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "orphaned-worker-reap"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "orphaned_worker_reap_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("orphaned_worker_reap_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA
        || request.self_pid == 0
        || request
            .budget_ms
            .is_some_and(|budget| budget > MAX_BUDGET_MS)
    {
        return Err(invalid());
    }
    let answer = answer(&request);
    serde_json::to_vec(&answer)
        .map_err(|_| "orphaned_worker_reap_response_encode_failed".to_owned())
}

fn invalid() -> String {
    "orphaned_worker_reap_request_invalid".to_owned()
}

#[cfg(unix)]
fn answer(request: &Request) -> Value {
    let excluded = [request.self_pid, std::process::id()];
    let budget = request.budget_ms.map(Duration::from_millis);
    reap(&system::SystemHost, &excluded, budget)
}

#[cfg(not(unix))]
fn answer(_request: &Request) -> Value {
    json!({ "error": "orphaned_worker_reap_unsupported" })
}

/// List, select and stop the orphaned workers within `budget`.
pub(crate) fn reap<H: Host>(host: &H, excluded: &[u32], budget: Option<Duration>) -> Value {
    let started = host.now();
    let remaining = |host: &H| budget.map(|budget| budget.saturating_sub(host.now() - started));
    let listing_timeout = remaining(host).map_or(LISTING_TIMEOUT, |left| left.min(LISTING_TIMEOUT));
    if listing_timeout.is_zero() {
        return json!({ "listed": false, "selected": [], "signalled": [], "forced": [] });
    }
    let Some(output) = host.listing(listing_timeout) else {
        return json!({ "listed": false, "selected": [], "signalled": [], "forced": [] });
    };
    let workers = orphaned_daemon_workers(&parse_process_snapshot(&output), excluded);
    let grace = remaining(host).map_or(GRACE, |left| left.min(GRACE));
    let (signalled, forced) = terminate(host, &workers, excluded, grace);
    json!({
        "listed": true,
        "selected": workers.iter().map(|worker| worker.pid).collect::<Vec<_>>(),
        "signalled": signalled,
        "forced": forced,
    })
}

/// CPython's `str.isspace` for the characters `ps` output can carry.
fn is_py_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

fn py_split(text: &str) -> impl Iterator<Item = &str> {
    text.split(is_py_space).filter(|field| !field.is_empty())
}

/// `str.splitlines()`.
fn py_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split("\r\n").flat_map(|line| {
        line.split([
            '\n', '\r', '\u{0b}', '\u{0c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ])
    })
}

fn ascii_number(text: &str) -> Option<u32> {
    (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// Parse `ps -axww -o pid=,ppid=,state=,command=` output.
pub(crate) fn parse_process_snapshot(output: &str) -> Vec<ProcessSnapshot> {
    py_lines(output)
        .filter_map(|line| {
            let (pid, rest) = py_strip(line).split_once(' ')?;
            let pid = ascii_number(pid)?;
            let (ppid, rest) = py_strip(rest).split_once(' ')?;
            let ppid = ascii_number(ppid)?;
            let (state, command) = py_strip(rest).split_once(' ')?;
            if state.is_empty() || state.chars().any(is_py_space) {
                return None;
            }
            Some(ProcessSnapshot {
                pid,
                ppid,
                state: state.to_owned(),
                command: py_strip(command).to_owned(),
            })
        })
        .collect()
}

/// Detached Guard hook workers whose daemon is no longer live, by pid.
pub(crate) fn orphaned_daemon_workers(
    processes: &[ProcessSnapshot],
    excluded: &[u32],
) -> Vec<ProcessSnapshot> {
    let by_pid: HashMap<u32, &ProcessSnapshot> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut selected: Vec<ProcessSnapshot> = processes
        .iter()
        .filter(|process| {
            process.pid > 1
                && !excluded.contains(&process.pid)
                && is_hol_guard_hook_worker(&process.command)
                && !has_live_guard_ancestor(process, &by_pid)
        })
        .cloned()
        .collect();
    selected.sort_by_key(|process| process.pid);
    selected
}

/// Stop the workers, then force any that ignore the first signal; the pids
/// signalled and forced.
pub(crate) fn terminate<H: Host>(
    host: &H,
    workers: &[ProcessSnapshot],
    excluded: &[u32],
    grace: Duration,
) -> (Vec<u32>, Vec<u32>) {
    let mut armed: Vec<(&ProcessSnapshot, String)> = Vec::new();
    for worker in workers {
        if worker.pid <= 1 || excluded.contains(&worker.pid) {
            continue;
        }
        if let Some(token) = signal_matching_worker(host, worker, Stop::Terminate, None) {
            armed.push((worker, token));
        }
    }
    let signalled = armed.iter().map(|(worker, _)| worker.pid).collect();
    let deadline = host.now() + grace;
    let mut pending = armed;
    while !pending.is_empty() && host.now() < deadline {
        host.sleep(POLL.min(deadline.saturating_duration_since(host.now())));
        pending.retain(|(worker, token)| {
            worker_identity_matches(host, worker, Some(token.as_str())).is_some()
        });
    }
    let mut forced = Vec::new();
    for (worker, token) in &pending {
        if signal_matching_worker(host, worker, Stop::Kill, Some(token.as_str())).is_some() {
            forced.push(worker.pid);
        }
    }
    (signalled, forced)
}

fn signal_matching_worker<H: Host>(
    host: &H,
    worker: &ProcessSnapshot,
    stop: Stop,
    expected_token: Option<&str>,
) -> Option<String> {
    let token = worker_identity_matches(host, worker, expected_token)?;
    let command = host.command(worker.pid)?;
    if py_strip(&command) != worker.command {
        return None;
    }
    host.signal(worker.pid, stop);
    Some(token)
}

fn worker_identity_matches<H: Host>(
    host: &H,
    worker: &ProcessSnapshot,
    expected_token: Option<&str>,
) -> Option<String> {
    let command = host.command(worker.pid)?;
    if py_strip(&command) != worker.command {
        return None;
    }
    let token = host
        .start_token(worker.pid)
        .filter(|token| !token.is_empty())?;
    if expected_token.is_some_and(|expected| expected != token) {
        return None;
    }
    Some(token)
}

fn has_live_guard_ancestor(
    process: &ProcessSnapshot,
    by_pid: &HashMap<u32, &ProcessSnapshot>,
) -> bool {
    let mut seen = HashSet::from([process.pid]);
    let mut current = by_pid.get(&process.ppid);
    for _ in 0..MAX_PARENT_HOPS {
        let Some(ancestor) = current else {
            return false;
        };
        if ancestor.pid <= 1 || seen.contains(&ancestor.pid) {
            return false;
        }
        if !ancestor.state.starts_with('Z') && is_protecting_guard_ancestor(&ancestor.command) {
            return true;
        }
        seen.insert(ancestor.pid);
        current = by_pid.get(&ancestor.ppid);
    }
    false
}

/// Keep workers of a live daemon or another live non-worker hol-guard
/// process. A hook worker is not an anchor: after the daemon exits, a nested
/// worker whose parent is another worker must still be reaped.
fn is_protecting_guard_ancestor(command: &str) -> bool {
    if is_hol_guard_daemon_serve(command) {
        return true;
    }
    if is_hol_guard_hook_worker(command) {
        return false;
    }
    leading_executable_is_hol_guard(&format!("{command} "))
}

fn is_hol_guard_hook_worker(command: &str) -> bool {
    if let Some(fork_at) = command.find(" --multiprocessing-fork") {
        if fork_at > 0 && is_absolute_hol_guard_executable(&command[..fork_at]) {
            return true;
        }
    }
    if command.contains(TRACKER_MARKER) && leading_executable_is_hol_guard(command) {
        return true;
    }
    is_marked_python_hook_worker(command)
}

fn is_hol_guard_daemon_serve(command: &str) -> bool {
    if let Some(frozen_at) = command.find(" --_hol-guard-daemon-serve") {
        if frozen_at > 0 && is_absolute_hol_guard_executable(&command[..frozen_at]) {
            return true;
        }
    }
    [" daemon --serve", " guard daemon --serve"]
        .iter()
        .any(|marker| match command.find(marker) {
            Some(marker_at) if marker_at > 0 => {
                let prefix = &command[..marker_at];
                is_absolute_hol_guard_executable(prefix)
                    || (prefix.contains("codex_plugin_scanner.cli")
                        && (prefix.ends_with(" guard")
                            || prefix.ends_with("codex_plugin_scanner.cli")))
            }
            _ => false,
        })
}

fn is_absolute_path(value: &str) -> bool {
    if value.starts_with('/') {
        return true;
    }
    let mut characters = value.chars();
    let (_, colon, separator) = (characters.next(), characters.next(), characters.next());
    colon == Some(':') && matches!(separator, Some('\\' | '/'))
}

fn basename(executable: &str) -> String {
    let normalized = executable.replace('\\', "/");
    normalized
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

fn is_absolute_hol_guard_executable(prefix: &str) -> bool {
    let executable = py_strip(prefix).trim_matches('"');
    is_absolute_path(executable) && HOL_GUARD_EXECUTABLES.contains(&basename(executable).as_str())
}

fn leading_executable_is_hol_guard(command: &str) -> bool {
    let stripped = py_strip(command).trim_matches('"');
    if !is_absolute_path(stripped) {
        return false;
    }
    // ps omits a trailing space when the executable has no arguments. Keep a
    // separator so the basename match does not also accept hol-guard-desktop.
    let padded = if stripped.ends_with(' ') {
        stripped.to_lowercase()
    } else {
        format!("{stripped} ").to_lowercase()
    };
    [
        "/hol-guard ",
        "/hol-guard.exe ",
        "/plugin-guard ",
        "/plugin-guard.exe ",
    ]
    .iter()
    .any(|name| {
        padded
            .find(name)
            .is_some_and(|marker_at| marker_at > 0 && !padded[..marker_at].contains(" -"))
    })
}

fn is_marked_python_hook_worker(command: &str) -> bool {
    let words: Vec<&str> = py_split(command).collect();
    if !words.contains(&HOOK_WORKER_COMMAND_MARKER) {
        return false;
    }
    if !words.contains(&FORK_MARKER) && !command.contains(TRACKER_MARKER) {
        return false;
    }
    let stripped = py_strip(command).trim_matches('"');
    if !is_absolute_path(stripped) {
        return false;
    }
    py_split(stripped)
        .next()
        .is_some_and(|executable| basename(executable).starts_with("python"))
}

/// Signal the worker's own process group, else the pid alone. A pid whose
/// group cannot be read has already exited and is left alone.
pub(crate) fn deliver(
    leads_own_group: impl FnOnce() -> Option<bool>,
    signal_group: impl FnOnce() -> bool,
    signal_pid: impl FnOnce(),
) {
    let Some(leads) = leads_own_group() else {
        return;
    };
    if leads && signal_group() {
        return;
    }
    signal_pid();
}

#[cfg(unix)]
#[path = "orphaned_worker_reap_system.rs"]
mod system;

#[cfg(test)]
#[path = "orphaned_worker_reap_tests.rs"]
mod tests;
