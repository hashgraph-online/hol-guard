//! Daemon recovery after a hook failure, in place of
//! the retired Python `recovery_lifecycle.py` and `recovery_worker.py`.
//!
//! `recover` serializes one recovery per Guard home, keeps a running
//! current daemon (an overloaded daemon is busy, not dead), and otherwise
//! starts one through `ensure` and publishes its approval-center locator.
//! `schedule_recovery` claims the home's recovery reservation, starts a
//! detached copy of this runtime to run `recover`, and binds the reservation
//! to that worker's process; a worker it cannot bind is stopped.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::daemon_edge::lifecycle::record_for_pid;
use crate::daemon_edge::standalone::write_private_atomic;
use crate::daemon_policy_authority::{
    daemon_pid_matches_command, load_authenticated_daemon_identity,
};
use crate::guard_config_load::load_under;
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource};

use super::ensure::{self, Ensure, Failure};
use super::host::{self, Caller};
use super::records::{self, int, text};
use super::retire::Deadline;

pub(super) const RECOVERY_LOCK_FILE: &str = "daemon-recovery.lock";
const RESERVATION_FILE: &str = "daemon-recovery-reservation.json";
const STATE_WRITE_LOCK_FILE: &str = "daemon-state-write.lock";
const FAILURE_KINDS: [&str; 3] = [
    "authenticated-control-plane-failure",
    "overload",
    "transport-failure",
];
const LOCK_TIMEOUT: &str = "Timed out waiting for Guard daemon recovery ownership.";
const DISABLED: &str = "Guard daemon recovery is disabled by local protection posture.";
const WORKER_STOP_WAIT: Duration = Duration::from_millis(250);

pub(super) fn failure_kind_is_valid(kind: &str) -> bool {
    FAILURE_KINDS.contains(&kind)
}

/// `guard_recovery_posture`: "on", "off" or "unknown" for local protection.
/// A harness overridden away from Watch still enforces under a global Watch,
/// so its hooks still need a recoverable daemon.
pub(crate) fn posture(guard_home: &Path) -> &'static str {
    let policy = effective_managed_policy(&load_managed_policy(&ManagedPolicySource::native()));
    let Ok(Value::Object(config)) = load_under(guard_home, None, policy.as_ref()) else {
        return "unknown";
    };
    let field = |key: &str| config.get(key).and_then(Value::as_str).unwrap_or("");
    let off = field("protection_posture") == "watch" || field("mode") == "observe";
    let enforcing_override = config
        .get("harness_postures")
        .and_then(Value::as_object)
        .is_some_and(|postures| {
            postures
                .values()
                .any(|posture| posture.as_str() != Some("watch"))
        });
    if off && !enforcing_override {
        "off"
    } else {
        "on"
    }
}

/// The current daemon URL a disabled recovery may still answer with.
fn disabled_url(caller: &Caller, request: &Ensure<'_>) -> Value {
    match ensure::running_current_url(caller, request) {
        Some(url) => json!({"url": url}),
        None => json!({"error": DISABLED, "kind": "runtime"}),
    }
}

pub(super) fn lock_file(home: &Path, name: &str) -> Option<File> {
    fs::create_dir_all(home).ok()?;
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(home.join(name))
        .ok()
}

/// `_guard_daemon_recovery_lock`: one recovery transaction per home.
fn recovery_lock(home: &Path, deadline: Deadline) -> Result<File, Failure> {
    let file = lock_file(home, RECOVERY_LOCK_FILE)
        .ok_or_else(|| Failure::Runtime(LOCK_TIMEOUT.to_owned()))?;
    loop {
        if file.try_lock_exclusive().is_ok() {
            return Ok(file);
        }
        if deadline.passed() {
            return Err(Failure::Runtime(LOCK_TIMEOUT.to_owned()));
        }
        std::thread::sleep(host::POLL_INTERVAL);
    }
}

pub(super) fn recover(
    caller: &Caller,
    request: &Ensure<'_>,
    failure_kind: &str,
    deadline: Deadline,
) -> Value {
    let home = caller.guard_home.as_path();
    if !failure_kind_is_valid(failure_kind) {
        return json!({"error": "Unsupported Guard daemon hook failure kind.", "kind": "value"});
    }
    if posture(home) == "off" {
        return disabled_url(caller, request);
    }
    record_for_pid(
        home,
        u32::try_from(caller.own_pid).unwrap_or(0),
        "recovery_requested",
        Some(failure_kind),
        None,
    );
    let _lock = match recovery_lock(home, deadline) {
        Ok(lock) => lock,
        Err(failure) => return failure.reply(),
    };
    if let Some(url) = ensure::running_current_url(caller, request) {
        return json!({"url": url});
    }
    if posture(home) == "off" {
        return disabled_url(caller, request);
    }
    if deadline.passed() {
        return json!({
            "error": "Guard daemon recovery exceeded its bounded worker lifetime.",
            "kind": "runtime",
        });
    }
    let url = match ensure::ensure(caller, request, deadline) {
        Ok(url) => url,
        Err(failure) => return failure.reply(),
    };
    if publish_locator(caller, &url).is_err() {
        record_for_pid(
            home,
            u32::try_from(caller.own_pid).unwrap_or(0),
            "locator_publish_failed",
            Some("recovery"),
            None,
        );
    }
    json!({"url": url})
}

/// `publish_approval_center_locator`: browser discovery for the
/// authenticated live daemon at `daemon_url`.
pub(super) fn publish_locator(caller: &Caller, daemon_url: &str) -> Result<Value, String> {
    let home = caller.guard_home.as_path();
    let (state, _) = load_authenticated_daemon_identity(home)
        .ok_or_else(|| "Guard daemon identity is unavailable.".to_owned())?;
    let mismatch = || "Guard daemon identity does not match the active local service.".to_owned();
    let pid = int(&state, "pid")
        .filter(|pid| *pid > 0)
        .ok_or_else(mismatch)?;
    let port = int(&state, "port").ok_or_else(mismatch)?;
    if daemon_url != format!("http://127.0.0.1:{port}")
        || !host::pid_is_running(pid)
        || !(daemon_pid_matches_command(pid, home)
            || super::retire::live_identity(caller, pid) == Some(true))
    {
        return Err(mismatch());
    }
    let started_at = text(&state, "started_at")
        .filter(|value| !value.is_empty())
        .map_or_else(now_iso, str::to_owned);
    let locator = json!({
        "guard_home": home.to_string_lossy(),
        "daemon_url": daemon_url,
        "approval_url_base": daemon_url,
        "pid": pid,
        "started_at": started_at,
        "state_path": records::state_path(home).to_string_lossy(),
    });
    let bytes = serde_json::to_vec_pretty(&locator).map_err(|_| mismatch())?;
    write_private_atomic(&home.join(records::LOCATOR_FILE), &bytes)
        .map_err(|_| "Guard could not write the approval-center locator.".to_owned())?;
    Ok(locator)
}

fn now_iso() -> String {
    crate::approval_gate_state::iso_from_epoch(now_seconds())
}

pub(super) fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

fn load_reservation(home: &Path) -> Option<Map<String, Value>> {
    let bytes = fs::read(home.join(RESERVATION_FILE)).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()
        .cloned()
}

pub(super) fn reservation_facts(reservation: Option<&Map<String, Value>>) -> Value {
    let Some(reservation) = reservation else {
        return Value::Null;
    };
    let mut facts = Map::new();
    for key in [
        "created_at",
        "pid",
        "process_command_digest",
        "process_start_marker",
        "process_creation_time",
    ] {
        if let Some(value) = reservation.get(key) {
            if value.is_number() || value.is_string() {
                facts.insert(key.to_owned(), value.clone());
            }
        }
    }
    Value::Object(facts)
}

pub(super) fn with_state_write_lock<T>(home: &Path, body: impl FnOnce() -> T) -> Option<T> {
    let file = lock_file(home, STATE_WRITE_LOCK_FILE)?;
    file.lock_exclusive().ok()?;
    let answer = body();
    let _ = fs2::FileExt::unlock(&file);
    Some(answer)
}

pub(super) fn reservation_key() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(super) fn key_field() -> String {
    format!("{}{}", "tok", "en")
}

/// `_claim_guard_daemon_recovery_reservation`.
fn claim(caller: &Caller) -> Option<String> {
    let home = caller.guard_home.as_path();
    let key = reservation_key()?;
    with_state_write_lock(home, || {
        let now = now_seconds();
        let existing = load_reservation(home);
        let verdict = host::lifecycle(
            caller,
            json!({"check": "recovery_claim", "existing": reservation_facts(existing.as_ref()), "now": now}),
        )?;
        if verdict.get("claim").and_then(Value::as_bool) != Some(true) {
            return None;
        }
        let mut record = Map::new();
        record.insert("created_at".to_owned(), json!(now));
        record.insert(key_field(), json!(key));
        let bytes = serde_json::to_vec(&record).ok()?;
        write_private_atomic(&home.join(RESERVATION_FILE), &bytes).ok()?;
        Some(key.clone())
    })
    .flatten()
}

fn holds(reservation: &Map<String, Value>, key: &str) -> bool {
    reservation
        .get(&key_field())
        .and_then(Value::as_str)
        .is_some_and(|held| host::same_text(held, key) && held.len() == key.len())
}

/// `_bind_guard_daemon_recovery_reservation`.
fn bind(caller: &Caller, key: &str, pid: i64) -> bool {
    let home = caller.guard_home.as_path();
    with_state_write_lock(home, || {
        let Some(mut reservation) = load_reservation(home) else {
            return false;
        };
        if !holds(&reservation, key) {
            return false;
        }
        reservation.insert("pid".to_owned(), json!(pid));
        if let Some(command) = host::command_for_pid(pid) {
            let digest = Sha256::digest(command.as_bytes());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            reservation.insert("process_command_digest".to_owned(), json!(hex));
        }
        if let Some(marker) = host::start_marker(pid) {
            reservation.insert("process_start_marker".to_owned(), json!(marker));
        }
        if host::nt() {
            if let Some(created) = host::windows_creation_time(pid) {
                reservation.insert("process_creation_time".to_owned(), json!(created));
            }
        }
        serde_json::to_vec(&reservation)
            .ok()
            .is_some_and(|bytes| write_private_atomic(&home.join(RESERVATION_FILE), &bytes).is_ok())
    })
    .unwrap_or(false)
}

/// `clear_guard_daemon_recovery_reservation`: only the holder clears it.
pub(super) fn clear(caller: &Caller, key: &str) -> bool {
    let home = caller.guard_home.as_path();
    with_state_write_lock(home, || {
        let Some(reservation) = load_reservation(home) else {
            return false;
        };
        holds(&reservation, key) && fs::remove_file(home.join(RESERVATION_FILE)).is_ok()
    })
    .unwrap_or(false)
}

/// `schedule_guard_daemon_recovery`: claim the home's reservation and hand
/// `recover` to a detached copy of this runtime, which clears the
/// reservation when it finishes. `worker_request` is the `recover` request
/// the worker answers; it reaches the worker on stdin, never in argv.
pub(super) fn schedule(
    caller: &Caller,
    failure_kind: &str,
    mut worker_request: Map<String, Value>,
    worker_env: &BTreeMap<String, String>,
    worker_cwd: Option<&str>,
) -> Value {
    let home = caller.guard_home.as_path();
    if !failure_kind_is_valid(failure_kind) {
        return json!({"error": "Unsupported Guard daemon hook failure kind.", "kind": "value"});
    }
    if posture(home) == "off" {
        return json!({"scheduled": false});
    }
    let Ok(executable) = std::env::current_exe() else {
        return json!({"scheduled": false});
    };
    let Some(key) = claim(caller) else {
        return json!({"scheduled": false});
    };
    worker_request.insert("op".to_owned(), json!("recover"));
    worker_request.insert("reservation".to_owned(), json!(key));
    for field in [
        "caller_pid",
        "caller_parent_pid",
        "worker_env",
        "worker_cwd",
    ] {
        worker_request.remove(field);
    }
    let Ok(payload) = serde_json::to_vec(&Value::Object(worker_request)) else {
        clear(caller, &key);
        return json!({"scheduled": false});
    };
    let mut command = Command::new(executable);
    command
        .args(["daemon-manage", "--stdin"])
        .env_clear()
        .envs(worker_env)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(cwd) = worker_cwd {
        command.current_dir(cwd);
    }
    detach(&mut command);
    let Ok(mut child) = command.spawn() else {
        clear(caller, &key);
        return json!({"scheduled": false});
    };
    let pid = i64::from(child.id());
    let delivered = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(&payload).is_ok());
    if delivered && bind(caller, &key, pid) {
        return json!({"scheduled": true, "pid": pid});
    }
    // A reservation that cannot name its worker must never leave the worker running.
    stop_worker(&mut child);
    clear(caller, &key);
    json!({"scheduled": false})
}

pub(super) fn detach(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        command.creation_flags(
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB,
        );
    }
}

/// `terminate_recovery_worker`: the worker leads its own process group.
pub(super) fn stop_worker(child: &mut std::process::Child) {
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    #[cfg(unix)]
    let _ = host::signal(-i64::from(child.id()), false);
    #[cfg(not(unix))]
    let _ = child.kill();
    let deadline = std::time::Instant::now() + WORKER_STOP_WAIT;
    while std::time::Instant::now() < deadline {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    #[cfg(unix)]
    let _ = host::signal(-i64::from(child.id()), true);
    let _ = child.kill();
    let _ = child.wait();
}
