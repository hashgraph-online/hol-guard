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
//! found". `ps` joins arguments with spaces, so a home that contains ` --`
//! can be read more than one way; the home counts as gone only when every
//! reading names a missing path. Every signal is then sent through the same command and start-token
//! check as a hook worker's, so a reused pid or a look-alike process is
//! skipped.

use std::time::Instant;

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
///
/// Each owner check runs `ps`, so the scan stops selecting once `deadline`
/// passes and gives each check only the time left; a process not checked in
/// time is left for the next pass.
pub(super) fn stale_guard_processes<H: Host>(
    host: &H,
    processes: &[ProcessSnapshot],
    excluded: &[u32],
    deadline: Option<Instant>,
) -> Vec<ProcessSnapshot> {
    let mut selected = Vec::new();
    for process in processes {
        if process.pid <= 1
            || excluded.contains(&process.pid)
            || process.state.starts_with('Z')
            || !is_stale(host, process)
        {
            continue;
        }
        let left = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(host.now());
                if left.is_zero() {
                    break;
                }
                left.min(OWNER_CHECK_TIMEOUT)
            }
            None => OWNER_CHECK_TIMEOUT,
        };
        if host.owned_by_caller(process.pid, left) {
            selected.push(process.clone());
        }
    }
    selected.sort_by_key(|process| process.pid);
    selected
}

/// The longest one owner check may take.
const OWNER_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

fn is_stale<H: Host>(host: &H, process: &ProcessSnapshot) -> bool {
    if let Some(homes) = daemon_guard_homes(&process.command) {
        return !homes.is_empty() && homes.iter().all(|home| host.path_absent(home));
    }
    match relay_executable(&process.command) {
        Some(executable) => process.ppid == 1 && host.path_absent(executable),
        None => false,
    }
}

/// Every way the `--guard-home` of a Guard daemon command line can be read,
/// or `None` for a command line that is not a Guard daemon's.
///
/// The value runs to the next flag, but `ps` joins arguments with spaces, so
/// a home that itself contains ` --` cannot be told apart from a flag after
/// it. Each place the value could end is one reading; a reading that is not
/// an absolute path is dropped, and a daemon with no absolute reading is
/// never stale.
fn daemon_guard_homes(command: &str) -> Option<Vec<&str>> {
    let daemon_at = if is_hol_guard_daemon_serve(command) {
        0
    } else {
        let marker_at = marker_after_runtime(command, NATIVE_DAEMON_MARKER)?;
        marker_at + NATIVE_DAEMON_MARKER.len()
    };
    let rest = &command[daemon_at..];
    let Some(flag_at) = rest.find(GUARD_HOME_FLAG) else {
        return Some(Vec::new());
    };
    let value = &rest[flag_at + GUARD_HOME_FLAG.len()..];
    let ends = value
        .match_indices(" --")
        .map(|(end, _)| end)
        .chain(std::iter::once(value.len()));
    Some(
        ends.map(|end| py_strip(&value[..end]))
            .filter(|home| is_absolute_path(home))
            .collect(),
    )
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
