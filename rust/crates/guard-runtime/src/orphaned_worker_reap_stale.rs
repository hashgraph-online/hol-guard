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
    is_absolute_hol_guard_executable, is_absolute_path, py_split, py_strip, ProcessSnapshot,
};

const RUNTIME_EXECUTABLES: [&str; 2] = ["hol-guard-runtime", "hol-guard-runtime.exe"];
const NATIVE_DAEMON_MARKER: &str = " daemon-serve";
const RELAY_MARKER: &str = " mcp-relay";
const GUARD_HOME_FLAG: &str = " --guard-home ";
const FROZEN_DAEMON_MARKER: &str = " --_hol-guard-daemon-serve";
const PYTHON_DAEMON_MARKERS: [&str; 2] = [" guard daemon --serve", " daemon --serve"];
const PACKAGED_MODULE: &str = "codex_plugin_scanner.cli";
/// Python options that take no value, so none can hide a `-c` script or
/// another module in front of `-m`.
const BARE_PYTHON_OPTIONS: &str = "bBdEiIOPqRsSuv";

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
    let daemon_at = match python_daemon_at(command) {
        Some(daemon_at) => daemon_at,
        None => {
            let marker_at = marker_after_runtime(command, NATIVE_DAEMON_MARKER)?;
            marker_at + NATIVE_DAEMON_MARKER.len()
        }
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

/// Where the daemon flag of a Python Guard daemon command line starts.
///
/// Only an absolute Guard executable or a Python interpreter running
/// `-m codex_plugin_scanner.cli` counts. The hook-worker matcher accepts any
/// command that mentions the module, which is right for keeping workers, but
/// a process chosen for retirement must not be a `-c` script that only
/// names the module.
fn python_daemon_at(command: &str) -> Option<usize> {
    if let Some(marker_at) = command.find(FROZEN_DAEMON_MARKER) {
        if marker_at > 0 && is_absolute_hol_guard_executable(&command[..marker_at]) {
            return Some(marker_at);
        }
    }
    PYTHON_DAEMON_MARKERS.iter().find_map(|marker| {
        let marker_at = command.find(marker)?;
        let prefix = &command[..marker_at];
        (marker_at > 0
            && (is_absolute_hol_guard_executable(prefix) || runs_packaged_module(prefix)))
        .then_some(marker_at)
    })
}

/// `python [bare options] -m codex_plugin_scanner.cli`, and nothing else.
///
/// `ps` joins arguments with spaces, so an interpreter under a directory
/// whose name has a space arrives as several words. Those words are taken as
/// one path only when it is absolute, no later word starts a new path or an
/// option, the first word is not itself a program (an existing file or a
/// shell or launcher name), and the file name is a Python interpreter:
/// `sh /x/python`, `/bin/sh tools/python` and `python3 -c pass` are refused.
fn runs_packaged_module(prefix: &str) -> bool {
    let words: Vec<&str> = py_split(prefix).collect();
    let [head @ .., flag, module] = words.as_slice() else {
        return false;
    };
    if *flag != "-m" || *module != PACKAGED_MODULE {
        return false;
    }
    let options = head
        .iter()
        .rev()
        .take_while(|word| is_bare_python_option(word))
        .count();
    let interpreter = &head[..head.len() - options];
    let [first, rest @ ..] = interpreter else {
        return false;
    };
    if !rest.is_empty()
        && (!is_absolute_path(first)
            || names_a_program(first)
            || rest
                .iter()
                .any(|word| word.starts_with(['/', '-']) || word.contains(':')))
    {
        return false;
    }
    let last = rest.last().unwrap_or(first);
    let name = last.rsplit(['/', '\\']).next().unwrap_or_default();
    name.to_ascii_lowercase().starts_with("python")
}

/// Launchers that take a program as their next word. A spaced interpreter
/// path never starts with one of these.
const LAUNCHER_NAMES: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "env",
    "nohup",
    "nice",
    "exec",
    "sudo",
    "xargs",
    "timeout",
    "caffeinate",
    "arch",
];

/// Whether the first word of a multi-word interpreter is a program in its own
/// right rather than the start of a directory name with a space in it.
fn names_a_program(first: &str) -> bool {
    let name = first.rsplit(['/', '\\']).next().unwrap_or_default();
    LAUNCHER_NAMES.contains(&name.to_ascii_lowercase().as_str())
        || std::path::Path::new(first).is_file()
}

fn is_bare_python_option(word: &str) -> bool {
    word.strip_prefix('-').is_some_and(|letters| {
        !letters.is_empty()
            && letters
                .chars()
                .all(|letter| BARE_PYTHON_OPTIONS.contains(letter))
    })
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
