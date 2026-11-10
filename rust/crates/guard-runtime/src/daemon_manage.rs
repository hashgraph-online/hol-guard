//! `daemon-manage --stdin`: retiring a Guard home's daemons and repairing its
//! approval-center locator, in place of `guard/daemon/manager.py`.
//!
//! Ops (schema `daemon-manage.v1`):
//! - `retire`: stop every daemon of the home except one on `keep_port`;
//!   answers `{"retired": [pid, ...]}`.
//! - `retirement_complete`: whether no signed, pending or enumerable daemon
//!   remains; answers `{"complete": bool}`.
//! - `repair_locator`: remove the locator and any untrusted daemon state;
//!   answers `{"repaired": true, "cleared": [...]}` or `{"error": code}`.

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::daemon_policy_authority::load_authenticated_daemon_identity;

#[path = "daemon_manage_host.rs"]
mod host;
#[path = "daemon_manage_records.rs"]
mod records;
#[path = "daemon_manage_retire.rs"]
mod retire;
#[cfg(all(test, unix))]
#[path = "daemon_manage_tests.rs"]
mod tests;

const SCHEMA: &str = "daemon-manage.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const MAX_BUDGET_MS: u64 = 600_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    guard_home: PathBuf,
    implicit_home: String,
    #[serde(default)]
    keep_port: Option<i64>,
    #[serde(default)]
    budget_ms: Option<u64>,
    #[serde(default)]
    caller_pid: Option<i64>,
    #[serde(default)]
    caller_parent_pid: Option<i64>,
    #[serde(default)]
    frozen_runtime: bool,
    #[serde(default)]
    frozen_parent_trusted: bool,
    #[serde(default)]
    executable_name: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "daemon-manage"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "daemon_manage_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("daemon_manage_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let answer = answer(&request)?;
    serde_json::to_vec(&answer).map_err(|_| "daemon_manage_response_unencodable".to_owned())
}

fn invalid() -> String {
    "daemon_manage_request_invalid".to_owned()
}

fn answer(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA
        || !request.guard_home.is_absolute()
        || request
            .keep_port
            .is_some_and(|port| !(1..=65535).contains(&port))
        || request
            .budget_ms
            .is_some_and(|budget| budget > MAX_BUDGET_MS)
    {
        return Err(invalid());
    }
    let own_pid = i64::from(std::process::id());
    let caller = host::Caller {
        guard_home: request.guard_home.clone(),
        implicit_home: request.implicit_home.clone(),
        own_pid: request.caller_pid.filter(|pid| *pid > 0).unwrap_or(own_pid),
        parent_pid: request
            .caller_parent_pid
            .filter(|pid| *pid > 0)
            .unwrap_or(0),
        frozen_runtime: request.frozen_runtime,
        frozen_parent_trusted: request.frozen_parent_trusted,
        executable_name: request.executable_name.clone(),
    };
    let deadline = retire::Deadline(
        request
            .budget_ms
            .map(|budget| Instant::now() + Duration::from_millis(budget)),
    );
    match request.op.as_str() {
        "retire" => {
            Ok(json!({"retired": retire::retire_all(&caller, request.keep_port, deadline)}))
        }
        "retirement_complete" => Ok(json!({"complete": retire::retirement_is_complete(&caller)})),
        "repair_locator" => Ok(repair_locator(&caller, deadline)),
        _ => Err(invalid()),
    }
}

/// `POST /v1/daemon/repair`, answered by the daemon edge: the edge is the
/// caller, so it never retires itself or its parent. `None` when the repair
/// stopped safely, which the daemon answered by closing the connection.
pub(crate) fn repair_from_daemon(guard_home: &std::path::Path, user_home: &str) -> Option<Value> {
    if !guard_home.is_absolute() || user_home.is_empty() {
        return None;
    }
    let executable_name = std::env::current_exe().ok().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().trim().to_lowercase())
            .filter(|name| !name.is_empty())
    });
    #[cfg(unix)]
    let parent_pid = i64::from(nix::unistd::getppid().as_raw());
    #[cfg(not(unix))]
    let parent_pid = 0;
    let caller = host::Caller {
        guard_home: guard_home.to_path_buf(),
        implicit_home: std::path::Path::new(user_home)
            .join(".hol-guard")
            .to_string_lossy()
            .into_owned(),
        own_pid: i64::from(std::process::id()),
        parent_pid,
        frozen_runtime: false,
        frozen_parent_trusted: false,
        executable_name,
    };
    let deadline = retire::Deadline(Some(Instant::now() + Duration::from_secs(30)));
    let answer = repair_locator(&caller, deadline);
    if answer.get("repaired") != Some(&Value::Bool(true)) {
        return None;
    }
    let cleared = answer.get("cleared").cloned().unwrap_or_else(|| json!([]));
    Some(json!({"repaired": true, "cleared": cleared}))
}

/// `repair_approval_center_locator`: a healthy live daemon is kept; a live
/// daemon whose identity is untrusted is retired before its state is cleared.
fn repair_locator(caller: &host::Caller, deadline: retire::Deadline) -> Value {
    let home = caller.guard_home.as_path();
    let mut cleared: Vec<&str> = Vec::new();
    let locator = home.join(records::LOCATOR_FILE);
    if locator.is_file() {
        if fs::remove_file(&locator).is_err() {
            return json!({"error": "locator_unremovable"});
        }
        cleared.push("locator");
    }
    let state_path = records::state_path(home);
    let identity_is_invalid = load_authenticated_daemon_identity(home).is_none();
    let discovery_path = home.join(records::DISCOVERY_FILE);
    let invalid_discovery_existed = discovery_path.is_file()
        && crate::daemon_policy_authority::load_daemon_discovery_key(home).is_none();
    if state_path.is_file() {
        let pid = records::load_state_unverified(home)
            .and_then(|state| records::int(&state, "pid"))
            .filter(|pid| *pid > 0);
        let pid_is_live = pid.is_some_and(host::pid_is_running);
        let identity = match pid {
            Some(pid) if pid_is_live => retire::live_identity(caller, pid),
            _ => Some(false),
        };
        if pid_is_live && identity.is_none() {
            return json!({"error": "daemon_identity_unresolved"});
        }
        let mut daemon_is_live = pid_is_live && identity == Some(true);
        if identity_is_invalid {
            retire::retire_all(caller, None, deadline);
            if !records::is_exact_tombstone(&state_path) {
                return json!({"error": "untrusted_state_not_retired"});
            }
            if daemon_is_live {
                cleared.push("daemon_process");
            }
            daemon_is_live = false;
        }
        if !daemon_is_live {
            if records::clear_state(home).is_err() {
                return json!({"error": "daemon_state_unwritable"});
            }
            cleared.push("daemon_state");
        }
    }
    if identity_is_invalid
        && (records::remove_invalid_discovery(home)
            || (invalid_discovery_existed && !discovery_path.exists()))
    {
        cleared.push("daemon_discovery_key");
    }
    json!({"repaired": true, "cleared": cleared})
}
