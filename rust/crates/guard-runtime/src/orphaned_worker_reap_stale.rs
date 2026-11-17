//! Guard processes that outlived what they serve, which the reaper retires
//! beside orphaned hook workers:
//!
//! - a daemon whose Guard home no longer exists, such as one started for a
//!   scratch home that was deleted while it ran. Nothing can reach its state
//!   again, so it only holds its port and memory;
//! - an `mcp-relay` whose host has exited (parent pid 1) and whose runtime
//!   executable has been removed by an update. A relay with a live host is
//!   left alone even after an update, because the host is still talking to
//!   it.
//!
//! The executable must be an absolute `hol-guard`, `plugin-guard` or
//! `hol-guard-runtime` path, the process must belong to the user the reaper
//! runs as, and a path counts as gone only when reading it answers "not
//! found". Every signal is then sent through the same command and start-token
//! check as a hook worker's, so a reused pid or a look-alike process is
//! skipped.

use super::Host;
use super::{
    is_absolute_hol_guard_executable, is_absolute_path, is_hol_guard_daemon_serve, py_strip,
    ProcessSnapshot,
};

const RUNTIME_EXECUTABLES: [&str; 2] = ["hol-guard-runtime", "hol-guard-runtime.exe"];
const NATIVE_DAEMON_MARKER: &str = " daemon-serve";
const RELAY_MARKER: &str = " mcp-relay";
const GUARD_HOME_FLAG: &str = " --guard-home ";

/// The processes in `processes` that serve nothing any more, by pid.
pub(super) fn stale_guard_processes<H: Host>(
    host: &H,
    processes: &[ProcessSnapshot],
    excluded: &[u32],
) -> Vec<ProcessSnapshot> {
    let mut selected: Vec<ProcessSnapshot> = processes
        .iter()
        .filter(|process| {
            process.pid > 1
                && !excluded.contains(&process.pid)
                && !process.state.starts_with('Z')
                && is_stale(host, process)
                && host.owned_by_caller(process.pid)
        })
        .cloned()
        .collect();
    selected.sort_by_key(|process| process.pid);
    selected
}

fn is_stale<H: Host>(host: &H, process: &ProcessSnapshot) -> bool {
    if let Some(home) = daemon_guard_home(&process.command) {
        return host.path_absent(home);
    }
    match relay_executable(&process.command) {
        Some(executable) => process.ppid == 1 && host.path_absent(executable),
        None => false,
    }
}

/// The `--guard-home` of a Guard daemon command line, when it is absolute.
fn daemon_guard_home(command: &str) -> Option<&str> {
    let daemon_at = if is_hol_guard_daemon_serve(command) {
        0
    } else {
        let marker_at = marker_after_runtime(command, NATIVE_DAEMON_MARKER)?;
        marker_at + NATIVE_DAEMON_MARKER.len()
    };
    let rest = &command[daemon_at..];
    let value_at = rest.find(GUARD_HOME_FLAG)? + GUARD_HOME_FLAG.len();
    let value = &rest[value_at..];
    // The value runs to the next flag. A path is not split on its own spaces.
    let home = value.find(" --").map_or(value, |end| &value[..end]);
    let home = py_strip(home);
    (is_absolute_path(home) && !home.contains(" --")).then_some(home)
}

/// The executable of a Guard `mcp-relay` command line.
fn relay_executable(command: &str) -> Option<&str> {
    let marker_at = marker_after_runtime(command, RELAY_MARKER)?;
    Some(py_strip(&command[..marker_at]))
}

/// Where `marker` follows a leading absolute Guard executable and ends a word.
fn marker_after_runtime(command: &str, marker: &str) -> Option<usize> {
    let marker_at = command.find(marker)?;
    let after = &command[marker_at + marker.len()..];
    if !(after.is_empty() || after.starts_with(' ')) || marker_at == 0 {
        return None;
    }
    let executable = py_strip(&command[..marker_at]);
    let runtime = is_absolute_path(executable)
        && RUNTIME_EXECUTABLES.contains(&super::basename(executable).as_str());
    (runtime || is_absolute_hol_guard_executable(executable)).then_some(marker_at)
}

#[cfg(test)]
#[path = "orphaned_worker_reap_stale_tests.rs"]
mod tests;
