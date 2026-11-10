//! What the operating system says about one process, for daemon management.
//!
//! Each probe answers the same question `guard/daemon/manager.py` asked of
//! Python before it moved here, through the code the runtime already uses for
//! that question: `process-identity` for start markers and owners,
//! `posix-processes` and `windows-process-command-lines` for command lines and
//! inventories, and `windows-process-lifecycle` for Windows liveness. A probe
//! that cannot be read answers `None`; callers treat that as unproven.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use guard_contracts::{DaemonLifecycleDecisionRequestV1, DAEMON_LIFECYCLE_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::codex_hook_identity;
use crate::daemon_lifecycle_decision_op::decide;

/// `GUARD_DAEMON_POLL_INTERVAL_SECONDS`.
pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(100);
const START_MARKER_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_FACT_ROUNDS: usize = 8;
const COMMAND_LINE_LIMIT_BYTES: i64 = 1024 * 1024;
const WINDOWS_INVENTORY_MAX_PROCESSES: i64 = 65_536;
/// The Windows images a daemon may run under (`_guard_daemon_process_inventory_for_guard_home`).
const WINDOWS_CANDIDATE_IMAGES: [&str; 6] = [
    "hol-guard.exe",
    "plugin-guard.exe",
    "py.exe",
    "python.exe",
    "python3.exe",
    "pythonw.exe",
];

/// The caller's view of its own process, which the inventory proof needs:
/// a daemon never competes with the process asking, nor with the frozen
/// bootloader that started it.
#[derive(Clone, Debug)]
pub(super) struct Caller {
    pub(super) guard_home: PathBuf,
    pub(super) implicit_home: String,
    pub(super) own_pid: i64,
    pub(super) parent_pid: i64,
    pub(super) frozen_runtime: bool,
    pub(super) frozen_parent_trusted: bool,
    pub(super) executable_name: Option<String>,
}

pub(super) fn nt() -> bool {
    cfg!(windows)
}

fn process_id(pid: i64) -> Option<u32> {
    u32::try_from(pid).ok().filter(|pid| *pid > 0)
}

/// `_guard_daemon_pid_is_running`: a POSIX permission error still proves a
/// live process; on Windows only a proven exit counts as stopped.
pub(super) fn pid_is_running(pid: i64) -> bool {
    let Some(pid) = process_id(pid) else {
        return false;
    };
    running(pid)
}

#[cfg(unix)]
fn running(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    match kill(Pid::from_raw(raw), None) {
        Ok(()) | Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn running(pid: u32) -> bool {
    windows_liveness(pid) != Some(false)
}

/// `_guard_daemon_pid_is_proven_dead`. A POSIX zombie has exited even though
/// it still answers a signal probe: its parent has not collected it yet.
pub(super) fn pid_is_proven_dead(pid: i64) -> bool {
    let Some(id) = process_id(pid) else {
        return true;
    };
    if nt() {
        return windows_liveness(id) == Some(false);
    }
    !running(id) || is_zombie(id)
}

#[cfg(target_os = "linux")]
fn is_zombie(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state == "Z")
}

#[cfg(all(unix, not(target_os = "linux")))]
fn is_zombie(pid: u32) -> bool {
    posix_query("state", Some(pid))
        .and_then(|answer| {
            answer
                .get("state")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|state| state.starts_with('Z'))
}

#[cfg(not(unix))]
fn is_zombie(_pid: u32) -> bool {
    false
}

/// `_wait_for_guard_daemon_pid_death`.
pub(super) fn wait_for_death(pid: i64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pid_is_proven_dead(pid) {
            return true;
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
    pid_is_proven_dead(pid)
}

pub(super) fn start_marker(pid: i64) -> Option<String> {
    let pid = process_id(pid)?;
    codex_hook_identity::process_start_token_within(pid, START_MARKER_TIMEOUT)
        .filter(|marker| !marker.is_empty())
}

pub(super) fn owner_marker(pid: i64) -> Option<String> {
    codex_hook_identity::process_owner_marker(process_id(pid)?).filter(|owner| !owner.is_empty())
}

pub(super) fn own_owner_marker() -> Option<String> {
    owner_marker(i64::from(std::process::id()))
}

/// `_guard_daemon_command_for_pid`.
pub(super) fn command_for_pid(pid: i64) -> Option<String> {
    let id = process_id(pid)?;
    if nt() {
        let request = json!({
            "schema": "windows-process-command-lines.v1",
            "op": "read",
            "pids": [id],
            "max_command_line_bytes": COMMAND_LINE_LIMIT_BYTES,
        });
        let answer = run(
            |bytes| crate::windows_process_command_lines::run_command(bytes),
            &request,
        )?;
        return answer["command_lines"][0].as_str().map(str::to_owned);
    }
    posix_query("command", Some(id))?
        .get("command")?
        .as_str()
        .map(str::to_owned)
}

pub(super) fn parent_pid(pid: i64) -> Option<i64> {
    let id = process_id(pid)?;
    posix_query("parent", Some(id))?
        .get("parent_pid")?
        .as_i64()
        .filter(|parent| *parent > 0)
}

pub(super) fn posix_query(op: &str, pid: Option<u32>) -> Option<Value> {
    let mut request = json!({"schema": "posix-processes.v1", "op": op});
    if let Some(pid) = pid {
        request["pid"] = pid.into();
    }
    run(|bytes| crate::posix_processes::run_command(bytes), &request)
}

fn run(command: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>, request: &Value) -> Option<Value> {
    let text = request.to_string();
    let bytes = command(text.as_bytes()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn windows_lifecycle(request: Value) -> Option<Value> {
    let mut request = request;
    request["schema"] = "windows-process-lifecycle.v1".into();
    run(
        |bytes| crate::windows_process_lifecycle::run_command(bytes),
        &request,
    )
}

pub(super) fn windows_liveness(pid: u32) -> Option<bool> {
    windows_lifecycle(json!({"op": "liveness", "pids": [pid]}))?["liveness"][0].as_bool()
}

/// `windows_process_creation_time`; always `None` off Windows.
pub(super) fn windows_creation_time(pid: i64) -> Option<i64> {
    if !nt() {
        return None;
    }
    let pid = process_id(pid)?;
    windows_lifecycle(json!({"op": "creation_time", "pids": [pid]}))?["creation_times"][0].as_i64()
}

/// `windows_terminate_process_if_creation_time`.
pub(super) fn windows_terminate_if_creation_time(
    pid: i64,
    creation_time: i64,
    timeout: Option<Duration>,
) -> bool {
    let Some(pid) = process_id(pid) else {
        return false;
    };
    let mut request = json!({
        "op": "terminate_if_creation_time",
        "pid": pid,
        "expected_creation_time": creation_time,
    });
    if let Some(timeout) = timeout {
        request["timeout_ms"] = i64::try_from(timeout.as_millis())
            .unwrap_or(i64::MAX)
            .into();
    }
    windows_lifecycle(request)
        .and_then(|answer| answer.get("terminated").and_then(Value::as_bool))
        .unwrap_or(false)
}

/// Sends `signal` to `pid`: `Ok(true)` when delivered, `Ok(false)` when the
/// process is already gone, `Err` for any other refusal.
#[cfg(unix)]
pub(super) fn signal(pid: i64, kill_now: bool) -> Result<bool, ()> {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    let raw = i32::try_from(pid).map_err(|_| ())?;
    let signal = if kill_now {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };
    match kill(Pid::from_raw(raw), signal) {
        Ok(()) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(_) => Err(()),
    }
}

#[cfg(not(unix))]
pub(super) fn signal(_pid: i64, _kill_now: bool) -> Result<bool, ()> {
    Err(())
}

/// `_guard_daemon_process_inventory_for_guard_home`: the daemons of this home
/// as `(pid, port)`, or `None` when the process table cannot prove them.
pub(super) fn daemon_inventory(caller: &Caller) -> Option<Vec<(i64, i64)>> {
    let mut query = json!({
        "check": "process_inventory",
        "guard_home": caller.guard_home.to_string_lossy(),
        "implicit_home": caller.implicit_home,
        "own_pid": caller.own_pid,
        "parent_pid": caller.parent_pid,
        "frozen_runtime": caller.frozen_runtime,
    });
    if nt() {
        let mut names: Vec<String> = WINDOWS_CANDIDATE_IMAGES.map(str::to_owned).to_vec();
        if let Some(name) = &caller.executable_name {
            names.push(name.to_lowercase());
        }
        let request = json!({
            "schema": "windows-process-command-lines.v1",
            "op": "inventory",
            "candidate_executable_names": names,
            "max_processes": WINDOWS_INVENTORY_MAX_PROCESSES,
            "max_command_line_bytes": COMMAND_LINE_LIMIT_BYTES,
        });
        let answer = run(
            |bytes| crate::windows_process_command_lines::run_command(bytes),
            &request,
        )?;
        query["entries"] = answer.get("entries").filter(|e| e.is_array())?.clone();
    } else {
        let answer = posix_query("inventory", None)?;
        if let Some(listing) = answer.get("listing").and_then(Value::as_str) {
            query["ps_output"] = listing.into();
        } else {
            query["entries"] = answer.get("entries").filter(|e| e.is_array())?.clone();
        }
    }
    let verdict = lifecycle(caller, query)?;
    if verdict.get("known").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    verdict
        .get("processes")?
        .as_array()?
        .iter()
        .map(|entry| Some((entry.get(0)?.as_i64()?, entry.get(1)?.as_i64()?)))
        .collect()
}

/// `_guard_daemon_pid_command_identity`: `Some(true)` for this home's daemon,
/// `Some(false)` for any other process, `None` when it cannot be read.
pub(super) fn command_identity(
    caller: &Caller,
    pid: i64,
    expected_home: Option<&Path>,
) -> Option<bool> {
    let command = command_for_pid(pid)?;
    command_identity_of(caller, &command, expected_home)
}

fn command_identity_of(
    caller: &Caller,
    command: &str,
    expected_home: Option<&Path>,
) -> Option<bool> {
    let mut query = json!({
        "check": "command_identity",
        "command": command,
        "implicit_home": caller.implicit_home,
    });
    if let Some(home) = expected_home {
        query["expected_home"] = home.to_string_lossy().into();
    }
    lifecycle(caller, query)?.get("identity")?.as_bool()
}

/// One lifecycle verdict, with every fact it names answered from this host.
pub(super) fn lifecycle(caller: &Caller, query: Value) -> Option<Value> {
    let mut facts: BTreeMap<String, Value> = BTreeMap::new();
    for _ in 0..MAX_FACT_ROUNDS {
        let request: DaemonLifecycleDecisionRequestV1 = serde_json::from_value(json!({
            "schema": DAEMON_LIFECYCLE_REQUEST_SCHEMA,
            "platform": if nt() { "nt" } else { "posix" },
            "facts": facts,
            "query": query,
        }))
        .ok()?;
        let result = decide(&request);
        if result.get("need").and_then(Value::as_str) != Some("facts") {
            return Some(result);
        }
        let needed = result.get("keys")?.as_array()?;
        if needed.is_empty() {
            return None;
        }
        for key in needed {
            let key = key.as_str()?;
            facts.insert(key.to_owned(), fact(caller, key));
        }
    }
    None
}

/// `_lifecycle_fact_resolver`: one fact a lifecycle verdict asked for.
fn fact(caller: &Caller, key: &str) -> Value {
    let (kind, argument) = key.split_once(':').unwrap_or((key, ""));
    match kind {
        "argv" => windows_lifecycle(json!({"op": "command_line_to_argv", "command": argument}))
            .and_then(|answer| answer.get("argv").cloned())
            .unwrap_or(Value::Null),
        "frozen" => frozen_payload(argument).unwrap_or(Value::Null),
        "resolve" => Value::String(
            resolve_lenient(Path::new(argument))
                .to_string_lossy()
                .into_owned(),
        ),
        "frozen_parent_trusted" => caller.frozen_parent_trusted.into(),
        "heartbeat_age" => Value::Null,
        _ => {
            let Ok(pid) = argument.parse::<i64>() else {
                return Value::Null;
            };
            match kind {
                "pid_running" => pid_is_running(pid).into(),
                "cmd" => command_for_pid(pid).map_or(Value::Null, Value::String),
                "start_token" => start_marker(pid).map_or(Value::Null, Value::String),
                "win_ctime" => windows_creation_time(pid).map_or(Value::Null, Value::from),
                "win_live" => process_id(pid)
                    .and_then(windows_liveness)
                    .map_or(Value::Null, Value::Bool),
                "matches_command" => {
                    let home = caller.guard_home.clone();
                    (command_identity(caller, pid, Some(&home)) == Some(true)).into()
                }
                _ => Value::Null,
            }
        }
    }
}

/// `decode_frozen_daemon_serve_payload`, as the fact the verdicts read.
fn frozen_payload(raw: &str) -> Option<Value> {
    let payload: Value = serde_json::from_str(raw).ok()?;
    let map = payload.as_object()?;
    if map.len() != 3 {
        return None;
    }
    let guard_home = map.get("guard_home")?.as_str()?;
    let home_dir = map.get("home_dir")?.as_str()?;
    let port = map
        .get("port")?
        .as_i64()
        .filter(|port| (1..=65535).contains(port))?;
    if !Path::new(guard_home).is_absolute() || !Path::new(home_dir).is_absolute() {
        return None;
    }
    Some(json!({"guard_home": guard_home, "port": port}))
}

/// Python's non-strict `Path.resolve()`: the existing prefix canonicalised,
/// the rest appended as written.
pub(super) fn resolve_lenient(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let mut existing = absolute.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&existing) {
            let mut out = plain(resolved);
            for part in rest.iter().rev() {
                if part == ".." {
                    out.pop();
                } else if part != "." {
                    out.push(part);
                }
            }
            return out;
        }
        let Some(name) = existing.file_name().map(|name| name.to_os_string()) else {
            return absolute
                .components()
                .filter(|part| !matches!(part, Component::CurDir))
                .collect();
        };
        rest.push(name);
        if !existing.pop() {
            return absolute;
        }
    }
}

/// The path without the Windows verbatim prefix `fs::canonicalize` adds.
fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{unc}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// `secrets.compare_digest` for two text markers.
pub(super) fn same_text(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |acc, (l, r)| acc | (l ^ r))
            == 0
}
