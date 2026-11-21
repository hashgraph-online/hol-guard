//! `windows-process-command-lines --stdin`: the bounded Windows process
//! command lines the daemon ownership checks compare
//! (`guard/windows_processes.py` before it moved here).
//!
//! - `read` answers the command line of each listed process, or `null` for
//!   one that cannot be read.
//! - `inventory` answers every live process whose image is one of the
//!   candidate executable names, with its command line, sorted by process
//!   id. A process that might still run but whose command line cannot be
//!   read, a process table larger than `max_processes`, or command lines
//!   whose UTF-8 total passes `max_command_line_bytes` make the whole
//!   inventory `null`: an incomplete list could hide a running daemon.
//!
//! Command lines are stripped of surrounding whitespace, and an empty one
//! reads as unreadable. Off Windows nothing can be read.

use std::io::Read;

use guard_runtime_windows_process::ProcessQuery;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_request_text::py_strip;

const SCHEMA: &str = "windows-process-command-lines.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_READ_PIDS: usize = 64;
const PROCESS_ENUMERATION_LIMIT: i64 = 65_536;
const COMMAND_LINE_TOTAL_LIMIT_BYTES: i64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    pids: Vec<i64>,
    #[serde(default)]
    candidate_executable_names: Vec<String>,
    #[serde(default)]
    max_processes: Option<i64>,
    max_command_line_bytes: i64,
}

/// The process table as the checks see it.
trait ProcessTable {
    type Process;
    /// Every process id, or `None` when the table cannot be read.
    fn process_ids(&self) -> Option<Vec<u32>>;
    fn open(&self, process_id: u32) -> Option<Self::Process>;
    fn image_path(&self, process: &Self::Process) -> Option<String>;
    /// The raw command line, bounded for `max_command_line_bytes`.
    fn command_line(
        &self,
        process: &Self::Process,
        max_command_line_bytes: usize,
    ) -> Option<String>;
    /// `Some(false)` only when the process is proven gone.
    fn liveness(&self, process_id: u32) -> Option<bool>;
}

struct SystemTable;

impl ProcessTable for SystemTable {
    type Process = ProcessQuery;

    fn process_ids(&self) -> Option<Vec<u32>> {
        guard_runtime_windows_process::process_ids().ok()
    }

    fn open(&self, process_id: u32) -> Option<ProcessQuery> {
        ProcessQuery::open(process_id).ok()
    }

    fn image_path(&self, process: &ProcessQuery) -> Option<String> {
        process.image_path()
    }

    fn command_line(
        &self,
        process: &ProcessQuery,
        max_command_line_bytes: usize,
    ) -> Option<String> {
        process.command_line(max_command_line_bytes)
    }

    fn liveness(&self, process_id: u32) -> Option<bool> {
        guard_runtime_windows_process::process_liveness(process_id)
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "windows-process-command-lines"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "windows_process_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("windows_process_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "windows_process_request_invalid".to_owned())?;
    let answer = answer(&request, &SystemTable)?;
    serde_json::to_vec(&answer).map_err(|_| "windows_process_response_encode_failed".to_owned())
}

fn answer<T: ProcessTable>(request: &Request, table: &T) -> Result<Value, String> {
    let invalid = || "windows_process_request_invalid".to_owned();
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let max_bytes = bounded(
        request.max_command_line_bytes,
        COMMAND_LINE_TOTAL_LIMIT_BYTES,
    );
    match request.op.as_str() {
        "read" => {
            if request.pids.len() > MAX_READ_PIDS {
                return Err(invalid());
            }
            let command_lines: Vec<Option<String>> = request
                .pids
                .iter()
                .map(|pid| {
                    let pid = u32::try_from(*pid).ok().filter(|pid| *pid > 0)?;
                    read_command_line(table, pid, max_bytes?)
                })
                .collect();
            Ok(json!({ "command_lines": command_lines }))
        }
        "inventory" => {
            let max_processes = request
                .max_processes
                .and_then(|limit| bounded(limit, PROCESS_ENUMERATION_LIMIT));
            let entries = match (max_processes, max_bytes) {
                (Some(max_processes), Some(max_bytes)) => inventory(
                    table,
                    &request.candidate_executable_names,
                    max_processes,
                    max_bytes,
                ),
                _ => None,
            };
            Ok(json!({ "entries": entries }))
        }
        _ => Err(invalid()),
    }
}

/// `value` when it lies in `1..=limit`.
fn bounded(value: i64, limit: i64) -> Option<usize> {
    if (1..=limit).contains(&value) {
        usize::try_from(value).ok()
    } else {
        None
    }
}

fn read_command_line<T: ProcessTable>(table: &T, pid: u32, max_bytes: usize) -> Option<String> {
    let process = table.open(pid)?;
    stripped_command_line(table, &process, max_bytes)
}

/// The stripped command line when it is non-empty and its UTF-8 fits
/// `max_bytes`.
fn stripped_command_line<T: ProcessTable>(
    table: &T,
    process: &T::Process,
    max_bytes: usize,
) -> Option<String> {
    let raw = table.command_line(process, max_bytes)?;
    let command_line = py_strip(&raw);
    if command_line.is_empty() || command_line.len() > max_bytes {
        return None;
    }
    Some(command_line.to_owned())
}

fn inventory<T: ProcessTable>(
    table: &T,
    candidate_executable_names: &[String],
    max_processes: usize,
    max_bytes: usize,
) -> Option<Vec<(u32, String)>> {
    let candidates: Vec<String> = candidate_executable_names
        .iter()
        .map(|name| executable_name(py_strip(name)))
        .filter(|name| !name.is_empty())
        .collect();
    if candidates.is_empty() {
        return Some(Vec::new());
    }
    let mut process_ids = table.process_ids()?;
    if process_ids.is_empty() || process_ids.len() >= max_processes {
        return None;
    }
    process_ids.retain(|pid| *pid > 0);
    process_ids.sort_unstable();
    process_ids.dedup();

    let mut entries = Vec::new();
    let mut consumed = 0usize;
    for pid in process_ids {
        let Some(process) = table.open(pid) else {
            continue;
        };
        let Some(image) = table.image_path(&process) else {
            continue;
        };
        let image = py_strip(&image);
        if image.is_empty() || !candidates.contains(&executable_name(image)) {
            continue;
        }
        let remaining = max_bytes - consumed;
        if remaining == 0 {
            return None;
        }
        let Some(command_line) = stripped_command_line(table, &process, remaining) else {
            if table.liveness(pid) == Some(false) {
                continue;
            }
            return None;
        };
        if table.liveness(pid) == Some(false) {
            continue;
        }
        consumed += command_line.len();
        entries.push((pid, command_line));
    }
    Some(entries)
}

/// `ntpath.basename(path).lower()`: the last component after any drive or
/// UNC share, lowercased.
fn executable_name(path: &str) -> String {
    let tail = match path.as_bytes() {
        [first, second, ..] if is_separator(*first) && is_separator(*second) => {
            // `\\server\share` is all drive; only what follows it names a file.
            path[2..].splitn(3, ['\\', '/']).nth(2).unwrap_or("")
        }
        [_, b':', ..] => &path[2..],
        _ => path,
    };
    tail.rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_lowercase()
}

fn is_separator(byte: u8) -> bool {
    byte == b'\\' || byte == b'/'
}

#[cfg(test)]
#[path = "windows_process_command_lines_tests.rs"]
mod tests;
