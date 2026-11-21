//! `windows-process-lifecycle --stdin`: the Windows process facts the daemon
//! lifecycle checks and the one action it takes on a process
//! (`guard/windows_paths.py` before they moved here).
//!
//! - `liveness` answers, for each listed process, `false` only when Windows
//!   proves it gone, `true` while it runs and `null` when neither is proven.
//! - `creation_time` answers each process's kernel creation time, or `null`.
//! - `owner_sid` answers `sid:` and the SID each process's token runs as,
//!   or `null`.
//! - `current_owner_sid` answers `sid:` and the SID the runtime's own token
//!   runs as, or `null`. The runtime inherits its caller's primary token, so
//!   this is the caller's user without opening the caller by id.
//! - `terminate_if_creation_time` terminates one process only while its
//!   creation time still matches, and answers whether that generation
//!   exited.
//! - `command_line_to_argv` answers the arguments Windows splits one
//!   command line into, or `null`.
//!
//! Off Windows no process can be read.

use std::io::Read;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

const SCHEMA: &str = "windows-process-lifecycle.v1";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_PIDS: usize = 64;
/// The longest timeout a termination request may carry.
const MAX_TIMEOUT_MS: i64 = 600_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    pids: Vec<i64>,
    #[serde(default)]
    pid: Option<i64>,
    #[serde(default)]
    expected_creation_time: Option<i64>,
    #[serde(default)]
    timeout_ms: Option<i64>,
    #[serde(default)]
    command: Option<String>,
}

/// The process facts and actions as the checks see them.
trait Processes {
    fn liveness(&self, process_id: u32) -> Option<bool>;
    fn creation_time(&self, process_id: u32) -> Option<u64>;
    fn owner_sid(&self, process_id: u32) -> Option<String>;
    fn current_owner_sid(&self) -> Option<String>;
    fn terminate_if_creation_time(
        &self,
        process_id: u32,
        expected_creation_time: u64,
        timeout: Option<Duration>,
    ) -> bool;
    fn command_line_to_argv(&self, command: &str) -> Option<Vec<String>>;
}

struct SystemProcesses;

impl Processes for SystemProcesses {
    fn liveness(&self, process_id: u32) -> Option<bool> {
        guard_runtime_windows_process::process_liveness(process_id)
    }

    fn creation_time(&self, process_id: u32) -> Option<u64> {
        guard_runtime_windows_process::process_creation_time(process_id)
    }

    fn owner_sid(&self, process_id: u32) -> Option<String> {
        guard_runtime_windows_process::process_owner_sid(process_id)
    }

    fn current_owner_sid(&self) -> Option<String> {
        current_owner_sid()
    }

    fn terminate_if_creation_time(
        &self,
        process_id: u32,
        expected_creation_time: u64,
        timeout: Option<Duration>,
    ) -> bool {
        guard_runtime_windows_process::terminate_if_creation_time(
            process_id,
            expected_creation_time,
            timeout,
        )
    }

    fn command_line_to_argv(&self, command: &str) -> Option<Vec<String>> {
        guard_runtime_windows_process::command_line_to_argv(command)
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "windows-process-lifecycle"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "windows_process_lifecycle_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("windows_process_lifecycle_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "windows_process_lifecycle_request_invalid".to_owned())?;
    let answer = answer(&request, &SystemProcesses)?;
    serde_json::to_vec(&answer)
        .map_err(|_| "windows_process_lifecycle_response_encode_failed".to_owned())
}

fn answer<P: Processes>(request: &Request, processes: &P) -> Result<Value, String> {
    let invalid = || "windows_process_lifecycle_request_invalid".to_owned();
    if request.schema != SCHEMA || request.pids.len() > MAX_PIDS {
        return Err(invalid());
    }
    match request.op.as_str() {
        "liveness" => {
            let liveness: Vec<Option<bool>> = request
                .pids
                .iter()
                .map(|pid| {
                    if *pid <= 0 {
                        return Some(false);
                    }
                    processes.liveness(u32::try_from(*pid).ok()?)
                })
                .collect();
            Ok(json!({ "liveness": liveness }))
        }
        "creation_time" => {
            let creation_times: Vec<Option<u64>> = request
                .pids
                .iter()
                .map(|pid| processes.creation_time(process_id(*pid)?))
                .collect();
            Ok(json!({ "creation_times": creation_times }))
        }
        "owner_sid" => {
            let owner_sids: Vec<Option<String>> = request
                .pids
                .iter()
                .map(|pid| processes.owner_sid(process_id(*pid)?))
                .collect();
            Ok(json!({ "owner_sids": owner_sids }))
        }
        "current_owner_sid" => {
            if !request.pids.is_empty() || request.pid.is_some() {
                return Err(invalid());
            }
            Ok(json!({ "owner_sid": processes.current_owner_sid() }))
        }
        "terminate_if_creation_time" => {
            let timeout = match request.timeout_ms {
                None => None,
                Some(millis) if (0..=MAX_TIMEOUT_MS).contains(&millis) => {
                    Some(Duration::from_millis(millis.unsigned_abs()))
                }
                Some(_) => return Err(invalid()),
            };
            let target = request.pid.and_then(process_id).zip(
                request
                    .expected_creation_time
                    .and_then(|value| u64::try_from(value).ok())
                    .filter(|value| *value > 0),
            );
            let terminated = target.is_some_and(|(pid, creation_time)| {
                processes.terminate_if_creation_time(pid, creation_time, timeout)
            });
            Ok(json!({ "terminated": terminated }))
        }
        "command_line_to_argv" => {
            let argv = request
                .command
                .as_deref()
                .filter(|command| !command.is_empty())
                .and_then(|command| processes.command_line_to_argv(command))
                .filter(|argv| !argv.is_empty());
            Ok(json!({ "argv": argv }))
        }
        _ => Err(invalid()),
    }
}

/// The SID this process's token runs as, read through the current-process
/// pseudo-handle, which a restricted token can always query.
#[cfg(windows)]
fn current_owner_sid() -> Option<String> {
    let sid = windows_permissions::utilities::current_process_sid()
        .ok()?
        .to_string();
    sid.starts_with("S-").then(|| format!("sid:{sid}"))
}

#[cfg(not(windows))]
fn current_owner_sid() -> Option<String> {
    None
}

/// A process id Windows can name: positive and within `u32`.
fn process_id(pid: i64) -> Option<u32> {
    u32::try_from(pid).ok().filter(|pid| *pid > 0)
}

#[cfg(test)]
#[path = "windows_process_lifecycle_tests.rs"]
mod tests;
