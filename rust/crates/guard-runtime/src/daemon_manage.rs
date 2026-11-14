//! `daemon-manage --stdin`: retiring a Guard home's daemons and repairing its
//! approval-center locator, in place of the retired Python `manager.py`.
//!
//! Ops (schema `daemon-manage.v1`):
//! - `retire`: stop every daemon of the home except one on `keep_port`;
//!   answers `{"retired": [pid, ...]}`.
//! - `retirement_complete`: whether no signed, pending or enumerable daemon
//!   remains; answers `{"complete": bool}`.
//! - `repair_locator`: remove the locator and any untrusted daemon state;
//!   answers `{"repaired": true, "cleared": [...]}` or `{"error": code}`.
//! - `ensure`: reuse, adopt or launch the home's daemon; answers
//!   `{"url": url}` or `{"error": message, "kind": "timeout"|"runtime"}`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::daemon_policy_authority::load_authenticated_daemon_identity;

#[path = "daemon_manage_ensure.rs"]
mod ensure;
#[path = "daemon_manage_host.rs"]
mod host;
#[path = "daemon_manage_live_probe.rs"]
mod live_probe;
#[cfg(all(test, unix))]
#[path = "daemon_manage_orphan_tests.rs"]
mod orphan_tests;
#[path = "daemon_manage_peer.rs"]
mod peer;
#[path = "daemon_manage_records.rs"]
mod records;
#[path = "daemon_manage_recover.rs"]
mod recover;
#[path = "daemon_manage_recovery_host.rs"]
pub(crate) mod recovery_host;
#[path = "daemon_manage_retire.rs"]
mod retire;
#[path = "daemon_manage_start_progress.rs"]
mod start_progress;
#[path = "daemon_manage_state.rs"]
mod state;
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
    #[serde(default)]
    launch: Map<String, Value>,
    #[serde(default)]
    serve_executable: Option<String>,
    #[serde(default)]
    executable: Option<String>,
    #[serde(default)]
    home_dir: Option<String>,
    #[serde(default)]
    launch_cwd: Option<String>,
    #[serde(default)]
    preferred_port: Option<i64>,
    #[serde(default)]
    background_maintenance: bool,
    #[serde(default)]
    allow_windows_job_breakaway: bool,
    #[serde(default)]
    start_lock_held: bool,
    #[serde(default)]
    launcher_env: BTreeMap<String, String>,
    #[serde(default)]
    env_port: Option<String>,
    #[serde(default)]
    failure_kind: Option<String>,
    #[serde(default)]
    reservation: Option<String>,
    #[serde(default)]
    worker_env: BTreeMap<String, String>,
    #[serde(default)]
    worker_cwd: Option<String>,
    #[serde(default)]
    wake: Option<String>,
    #[serde(default)]
    args: Map<String, Value>,
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
    let raw: Map<String, Value> = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let request: Request =
        serde_json::from_value(Value::Object(raw.clone())).map_err(|_| invalid())?;
    let answer = answer(&request, &raw)?;
    serde_json::to_vec(&answer).map_err(|_| "daemon_manage_response_unencodable".to_owned())
}

fn invalid() -> String {
    "daemon_manage_request_invalid".to_owned()
}

fn answer(request: &Request, raw: &Map<String, Value>) -> Result<Value, String> {
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
    let caller = caller_of(request);
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
        "posture" => Ok(json!({"posture": recover::posture(&caller.guard_home)})),
        "repair_locator" => Ok(repair_locator(&caller, deadline)),
        "ensure" | "recover" | "schedule_recovery" | "schedule_ensure" => {
            let ensure = ensure_of(request);
            let failure_kind = request.failure_kind.as_deref().unwrap_or("");
            Ok(match request.op.as_str() {
                "recover" => {
                    let answer = recover::recover(&caller, &ensure, failure_kind, deadline);
                    if let Some(key) = request.reservation.as_deref() {
                        recover::clear(&caller, key);
                    }
                    answer
                }
                "schedule_recovery" => recover::schedule(
                    &caller,
                    failure_kind,
                    raw.clone(),
                    &request.worker_env,
                    request.worker_cwd.as_deref(),
                ),
                "schedule_ensure" => {
                    let current = request
                        .launch
                        .get("state")
                        .and_then(Value::as_object)
                        .cloned()
                        .unwrap_or_default();
                    let predicted = request
                        .args
                        .get("predicted_url")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    state::schedule_ensure(
                        &caller,
                        raw.clone(),
                        current,
                        predicted,
                        &request.worker_env,
                        request.worker_cwd.as_deref(),
                    )
                }
                _ => {
                    let answer = match ensure::ensure(&caller, &ensure, deadline) {
                        Ok(url) => json!({"url": url}),
                        Err(failure) => failure.reply(),
                    };
                    if let Some(key) = request.wake.as_deref() {
                        state::wake_clear(&caller.guard_home, key);
                    }
                    answer
                }
            })
        }
        op => state::answer(&caller, op, &request.args, deadline).ok_or_else(invalid),
    }
}

/// The caller a request names; an absent PID defaults to this process.
fn caller_of(request: &Request) -> host::Caller {
    let own_pid = i64::from(std::process::id());
    host::Caller {
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
    }
}

/// The launch configuration an `ensure` request carries.
fn ensure_of(request: &Request) -> ensure::Ensure<'_> {
    ensure::Ensure {
        launch: &request.launch,
        serve_executable: request.serve_executable.as_deref(),
        executable: request.executable.as_deref(),
        home_dir: request.home_dir.as_deref(),
        launch_cwd: request.launch_cwd.as_deref(),
        preferred_port: request.preferred_port,
        background_maintenance: request.background_maintenance,
        allow_windows_job_breakaway: request.allow_windows_job_breakaway,
        start_lock_held: request.start_lock_held,
        launcher_env: &request.launcher_env,
        env_port: request.env_port.as_deref(),
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
