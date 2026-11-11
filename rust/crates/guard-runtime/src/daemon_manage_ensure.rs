//! Starting the Guard home's daemon (`ensure_guard_daemon`).
//!
//! Reuses a live current daemon, adopts a running one that lost its state,
//! retires stale or untrusted generations, and otherwise launches the native
//! daemon directly. A launch is recorded as a signed pending receipt before
//! the child may publish, and only a handoff that binds that receipt's nonce,
//! pid, start marker and owner is accepted.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use pep440_rs::Version;
use serde_json::{json, Map, Value};

use crate::daemon_edge::standalone::{
    self, write_record_tombstone, write_signed_record, LaunchConfig,
};
use crate::daemon_policy_authority::{
    daemon_pid_matches_command, healthz_payload_is_current, healthz_payload_matches_guard_home,
    http_get_json, load_authenticated_daemon_identity, load_daemon_discovery_key,
    read_private_regular_text, verify_daemon_state,
};

use super::host::{self, Caller};
use super::records::{self, int, text};
use super::retire::{self, Deadline};

const COMPATIBILITY_VERSION: i64 = 2;
const START_LOCK_FILE: &str = "daemon-start.lock";
const PROGRESS_FILE: &str = "daemon-start-progress.json";
const PENDING_FILE: &str = "daemon-launch-pending.json";
const PROGRESS_MAX_BYTES: u64 = 4096;
const WORKER_READY_FLOOR_SECONDS: f64 = 14.0;
const MARKER_ATTEMPTS: usize = 10;
const MARKER_RETRY: Duration = Duration::from_millis(20);
const TERMINATE_WAIT: Duration = Duration::from_secs(1);
const NONCE_ENV: &str = "HOL_GUARD_DAEMON_LAUNCH_NONCE";

const PREVIOUS_LAUNCH: &str = "A previous Guard daemon launch could not be retired safely.";
const IN_PROGRESS: &str = "In-progress Guard daemon launch could not be retired safely.";
const NOT_CONTAINED: &str =
    "Guard approval center did not start; launch ownership could not be proven contained.";

#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x0000_0008;
#[cfg(windows)]
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

/// What the caller hands over: the launch configuration it built and the
/// process environment the daemon may inherit.
pub(super) struct Ensure<'a> {
    pub(super) launch: &'a Map<String, Value>,
    pub(super) serve_executable: Option<&'a str>,
    pub(super) executable: Option<&'a str>,
    pub(super) home_dir: Option<&'a str>,
    pub(super) launch_cwd: Option<&'a str>,
    pub(super) preferred_port: Option<i64>,
    pub(super) background_maintenance: bool,
    pub(super) allow_windows_job_breakaway: bool,
    pub(super) start_lock_held: bool,
    pub(super) launcher_env: &'a BTreeMap<String, String>,
    pub(super) env_port: Option<&'a str>,
}

/// Why no daemon URL came back.
pub(super) enum Failure {
    Timeout(String),
    Runtime(String),
}

impl Failure {
    pub(super) fn reply(self) -> Value {
        match self {
            Self::Timeout(message) => json!({"error": message, "kind": "timeout"}),
            Self::Runtime(message) => json!({"error": message, "kind": "runtime"}),
        }
    }
}

fn runtime(message: &str) -> Failure {
    Failure::Runtime(message.to_owned())
}

struct Context<'a> {
    caller: &'a Caller,
    request: &'a Ensure<'a>,
    deadline: Deadline,
    current: Map<String, Value>,
}

impl Context<'_> {
    fn home(&self) -> &Path {
        &self.caller.guard_home
    }

    fn current_text(&self, key: &str) -> Option<&str> {
        text(&self.current, key)
    }
}

pub(super) fn ensure(
    caller: &Caller,
    request: &Ensure<'_>,
    deadline: Deadline,
) -> Result<String, Failure> {
    let current = request
        .launch
        .get("state")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| runtime("Guard daemon launch configuration is invalid."))?;
    if deadline.0.is_none() {
        return Err(runtime("Guard daemon launch configuration is invalid."));
    }
    let context = Context {
        caller,
        request,
        deadline,
        current,
    };
    let home = context.home().to_path_buf();
    let initial_pending = records::load_pending(&home);
    let initial_progress = load_progress(&home);
    let progress_live = initial_progress
        .as_ref()
        .is_some_and(|progress| progress_is_live(caller, progress));
    if !progress_live
        && records::is_generation_bound(initial_pending.as_ref())
        && !records::pending_is_resolved(&home)
        && !retire::resolve_abandoned(caller, initial_pending.as_ref())
    {
        return Err(runtime(PREVIOUS_LAUNCH));
    }
    if let Some(url) = live_or_newer(&context) {
        return Ok(url);
    }
    let _lock = if request.start_lock_held {
        None
    } else {
        Some(start_lock(&home, deadline)?)
    };
    locked(&context)
}

/// `authenticated_live_current_daemon_url`: the URL of a running current
/// daemon whatever its health, so recovery from overload never restarts a
/// daemon that is only busy. A recorded daemon that is gone is journalled.
pub(super) fn running_current_url(caller: &Caller, request: &Ensure<'_>) -> Option<String> {
    let current = request.launch.get("state")?.as_object()?.clone();
    let context = Context {
        caller,
        request,
        deadline: Deadline(None),
        current,
    };
    let home = context.home();
    let (state, _) = load_authenticated_daemon_identity(home)?;
    let pid = int(&state, "pid").filter(|pid| *pid > 0)?;
    if !host::pid_is_running(pid) {
        crate::daemon_edge::lifecycle::record_for_pid(
            home,
            u32::try_from(pid).unwrap_or(0),
            "death_observed",
            Some("process_missing"),
            text(&state, "state_id"),
        );
        return None;
    }
    let port = int(&state, "port").filter(|port| (1..=65_535).contains(port))?;
    text(&state, "state_id").filter(|id| !id.is_empty())?;
    if !runtime_matches(&context, &state) || !daemon_pid_matches_command(pid, home) {
        return None;
    }
    Some(format!("http://127.0.0.1:{port}"))
}

fn locked(context: &Context<'_>) -> Result<String, Failure> {
    let caller = context.caller;
    let home = context.home().to_path_buf();
    let request = context.request;
    let deadline = context.deadline;
    if request.executable.is_some() {
        if let Some(url) = live_or_newer(context) {
            return Ok(url);
        }
        if let Some(url) = live_url(context, true, None) {
            match request.preferred_port {
                None => return Ok(url),
                Some(port) if url_port(&url) == Some(port) => return Ok(url),
                Some(_) => {
                    retire::retire_all(caller, None, deadline);
                    if !retire::retirement_is_complete(caller) {
                        return Err(runtime(
                            "Existing Guard daemon could not be retired safely.",
                        ));
                    }
                    clear_state(&home)?;
                }
            }
        }
    }
    let state_path = records::state_path(&home);
    if state_path.is_file()
        && load_authenticated_daemon_identity(&home).is_none()
        && (request.background_maintenance || !records::is_exact_tombstone(&state_path))
    {
        retire::retire_all(caller, None, deadline);
        if !records::is_exact_tombstone(&state_path) && !retire::retirement_is_complete(caller) {
            return Err(runtime(
                "Untrusted Guard daemon state could not be retired safely.",
            ));
        }
        records::remove_invalid_discovery(&home);
    }
    if !host::nt() && request.executable.is_none() {
        if let Some(url) = adopt(context) {
            clear_progress(&home);
            return Ok(url);
        }
    }
    if let Some(stale) = records::load_state_unverified(&home) {
        let pid = int(&stale, "pid").unwrap_or(0);
        if runtime_matches(context, &stale) {
            if pid > 0 && host::pid_is_running(pid) {
                if let Some(url) = wait_live(context) {
                    return Ok(url);
                }
                retire::retire_all(caller, None, deadline);
                if !retire::retirement_is_complete(caller) {
                    return Err(runtime(IN_PROGRESS));
                }
            }
        } else if pid > 0 && !retire_process(caller, &stale, deadline) {
            return Err(runtime("Stale Guard daemon could not be retired safely."));
        }
    }
    let progress = load_progress(&home);
    let mut progress_live = false;
    if let Some(progress) = progress {
        if progress_is_live(caller, &progress) {
            progress_live = true;
            if let Some(url) = wait_live(context) {
                clear_progress(&home);
                return Ok(url);
            }
            clear_progress(&home);
            retire::retire_all(caller, None, deadline);
            if !retire::retirement_is_complete(caller) {
                return Err(runtime(IN_PROGRESS));
            }
        } else {
            clear_progress(&home);
        }
    }
    let pending_path = records::pending_path(&home);
    let pending = records::load_pending(&home);
    if pending_path.is_file() || pending.is_some() {
        if records::is_generation_bound(pending.as_ref())
            && !records::pending_is_resolved(&home)
            && !retire::resolve_abandoned(caller, pending.as_ref())
        {
            return Err(runtime(PREVIOUS_LAUNCH));
        }
        if host::nt() && !progress_live {
            retire::retire_all(caller, None, deadline);
        }
        if !records::pending_is_resolved(&home) {
            return Err(runtime(PREVIOUS_LAUNCH));
        }
    }
    clear_state(&home)?;
    if request.background_maintenance {
        retire::reap_orphaned_workers(caller, deadline);
    }
    for port in candidate_ports(context) {
        if deadline.passed() {
            break;
        }
        if let Some(url) = launch_once(context, port)? {
            return Ok(url);
        }
    }
    Err(runtime(&format!(
        "Guard approval center did not start. Expected state file at {}.",
        state_path.display()
    )))
}

fn clear_state(home: &Path) -> Result<(), Failure> {
    records::clear_state(home)
        .map_err(|_| runtime("Guard daemon state could not be cleared safely."))
}

/// The cross-process start lock every launcher of this home takes.
pub(super) fn start_lock(home: &Path, deadline: Deadline) -> Result<File, Failure> {
    let unavailable = || runtime("Guard daemon start lock could not be opened.");
    fs::create_dir_all(home).map_err(|_| unavailable())?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(home.join(START_LOCK_FILE))
        .map_err(|_| unavailable())?;
    loop {
        if file.try_lock_exclusive().is_ok() {
            return Ok(file);
        }
        if deadline.passed() {
            return Err(Failure::Timeout(
                "Timed out waiting to start the Guard daemon.".to_owned(),
            ));
        }
        std::thread::sleep(host::POLL_INTERVAL);
    }
}

pub(super) fn url_port(url: &str) -> Option<i64> {
    url.rsplit_once(':')?.1.parse().ok()
}

/// `daemon_state_matches_current_runtime`.
fn runtime_matches(context: &Context<'_>, payload: &Map<String, Value>) -> bool {
    runtime_matches_current(&context.current, payload)
}

fn runtime_matches_current(current: &Map<String, Value>, payload: &Map<String, Value>) -> bool {
    if int(payload, "compatibility_version") != Some(COMPATIBILITY_VERSION) {
        return false;
    }
    let Some(fingerprint) = text(payload, "runtime_fingerprint").filter(|f| !f.trim().is_empty())
    else {
        return false;
    };
    let current_version = current.get("package_version");
    let current_root = current.get("source_root");
    let same_version = payload.get("package_version") == current_version;
    if same_version && payload.get("source_root") != current_root {
        return true;
    }
    if Some(fingerprint) == text(current, "runtime_fingerprint") {
        return true;
    }
    if payload.get("source_root") == current_root {
        return false;
    }
    if same_version {
        return true;
    }
    if !desktop_core_source_available(payload.get("source_root")) {
        return false;
    }
    version_at_least(
        text(payload, "package_version"),
        text(current, "package_version"),
        false,
    )
}

pub(super) fn version_at_least(
    candidate: Option<&str>,
    current: Option<&str>,
    strictly: bool,
) -> bool {
    let parse = |value: Option<&str>| {
        value
            .filter(|v| !v.trim().is_empty())
            .and_then(|v| v.trim().parse::<Version>().ok())
    };
    match (parse(candidate), parse(current)) {
        (Some(candidate), Some(current)) if strictly => candidate > current,
        (Some(candidate), Some(current)) => candidate >= current,
        _ => false,
    }
}

/// `daemon_source_is_desktop_core`.
pub(super) fn source_is_desktop_core(source_root: &str) -> bool {
    let lowered = source_root.replace('\\', "/").to_lowercase();
    let parts: Vec<&str> = lowered.split('/').filter(|part| !part.is_empty()).collect();
    let n = parts.len();
    let window = |at: usize, wanted: &[&str]| parts.get(at..at + wanted.len()) == Some(wanted);
    if (0..n).any(|i| window(i, &["org.hol.guard.desktop", "core", "versions"])) {
        return true;
    }
    if parts.contains(&"hol guard.app") {
        return true;
    }
    if (0..n).any(|i| window(i, &["hol guard", "hol-guard"])) {
        return true;
    }
    if parts
        .last()
        .is_some_and(|last| ["current-hol-guard", "current-hol-guard.cmd"].contains(last))
    {
        return true;
    }
    if (0..n).any(|i| parts[i] == "bundled" && parts.get(i + 2) == Some(&"bin")) {
        return true;
    }
    if (0..n).any(|i| {
        parts[i] == "bundled"
            && n - i == 5
            && parts[i + 2..i + 4] == ["lib", "hol-guard-core"]
            && ["hol-guard", "hol-guard.exe"].contains(&parts[i + 4])
    }) {
        return true;
    }
    n >= 3 && parts[n - 3] == "versions"
}

/// `daemon_desktop_core_source_available`.
pub(super) fn desktop_core_source_available(source_root: Option<&Value>) -> bool {
    let Some(root) = source_root
        .and_then(Value::as_str)
        .filter(|r| !r.trim().is_empty())
    else {
        return false;
    };
    if !source_is_desktop_core(root) {
        return false;
    }
    let path = PathBuf::from(root.replace('\\', "/"));
    !path.is_absolute() || path.exists()
}

/// `_live_guard_daemon_url`.
fn live_url(
    context: &Context<'_>,
    require_current: bool,
    expected_pid: Option<i64>,
) -> Option<String> {
    live_identity_of(context, require_current, expected_pid).map(|(url, _)| url)
}

/// `_live_guard_daemon_identity` for a caller that names only the current
/// runtime identity: the live URL and the home's shared auth value.
pub(super) fn live_identity(
    caller: &Caller,
    current: Map<String, Value>,
    require_current: bool,
    expected_pid: Option<i64>,
) -> Option<(String, String)> {
    let launch = Map::new();
    let env = BTreeMap::new();
    let request = Ensure {
        launch: &launch,
        serve_executable: None,
        executable: None,
        home_dir: None,
        launch_cwd: None,
        preferred_port: None,
        background_maintenance: false,
        allow_windows_job_breakaway: false,
        start_lock_held: false,
        launcher_env: &env,
        env_port: None,
    };
    let context = Context {
        caller,
        request: &request,
        deadline: Deadline(None),
        current,
    };
    live_identity_of(&context, require_current, expected_pid)
}

/// `daemon_state_matches_current_runtime` against a named current identity.
pub(super) fn state_matches(current: &Map<String, Value>, payload: &Map<String, Value>) -> bool {
    runtime_matches_current(current, payload)
}

fn live_identity_of(
    context: &Context<'_>,
    require_current: bool,
    expected_pid: Option<i64>,
) -> Option<(String, String)> {
    let home = context.home();
    let (state, auth) = load_authenticated_daemon_identity(home)?;
    if require_current && !runtime_matches(context, &state) {
        return None;
    }
    let mut payload = Map::new();
    for key in ["compatibility_version", "port", "pid"] {
        if let Some(value) = int(&state, key) {
            payload.insert(key.into(), value.into());
        }
    }
    let gate = host::lifecycle(
        context.caller,
        json!({"check": "live_state_gate", "payload": payload}),
    )?;
    if gate.get("ok").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let port = gate.get("port")?.as_i64()?;
    let pid = gate.get("pid")?.as_i64()?;
    if let Some(expected) = expected_pid {
        if !retire::is_spawned_launch(context.caller, pid, expected) {
            return None;
        }
    }
    let url = format!("http://127.0.0.1:{port}");
    let health = http_get_json(&format!("{url}/healthz"), &[])?;
    if !healthz_payload_is_current(&health) {
        return None;
    }
    if daemon_pid_matches_command(pid, home) {
        return Some((url, auth));
    }
    let header = format!("X-Guard-{}", "Token");
    let details = http_get_json(
        &format!("{url}/v1/healthz/details"),
        &[(header.as_str(), auth.as_str())],
    )?;
    healthz_payload_matches_guard_home(&details, home).then_some((url, auth))
}

/// `_live_or_newer_guard_daemon_url`: a newer live Desktop daemon is never
/// replaced by an older caller.
fn live_or_newer(context: &Context<'_>) -> Option<String> {
    if context.request.executable.is_some() {
        let newer = load_authenticated_daemon_identity(context.home()).is_some_and(|(state, _)| {
            version_at_least(
                text(&state, "package_version"),
                context.current_text("package_version"),
                true,
            )
        });
        if newer {
            return live_url(context, false, None);
        }
    }
    let url = live_url(context, true, None)?;
    match context.request.preferred_port {
        Some(port) if url_port(&url) != Some(port) => None,
        _ => Some(url),
    }
}

fn wait_live(context: &Context<'_>) -> Option<String> {
    loop {
        if let Some(url) = live_url(context, true, None) {
            return Some(url);
        }
        if context.deadline.passed() {
            return None;
        }
        std::thread::sleep(host::POLL_INTERVAL);
    }
}

fn ports_answer(answer: Option<Value>) -> Vec<i64> {
    answer
        .and_then(|answer| answer.get("ports").cloned())
        .and_then(|ports| serde_json::from_value::<Vec<i64>>(ports).ok())
        .unwrap_or_default()
}

fn candidate_ports(context: &Context<'_>) -> Vec<i64> {
    ports_answer(host::lifecycle(
        context.caller,
        json!({
            "check": "candidate_ports",
            "env_port": context.request.env_port,
            "guard_home": context.home().to_string_lossy(),
            "preferred_port": context.request.preferred_port,
        }),
    ))
}

/// `_adopt_existing_guard_daemon`: a running daemon of this home that lost
/// its state is published again rather than replaced.
fn adopt(context: &Context<'_>) -> Option<String> {
    let home = context.home();
    let state_port = records::load_state_unverified(home).and_then(|state| int(&state, "port"));
    let running: Vec<i64> = host::daemon_inventory(context.caller)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, port)| port)
        .collect();
    let mut ports: Vec<i64> = context
        .request
        .preferred_port
        .filter(|port| *port > 0)
        .into_iter()
        .collect();
    ports.extend(ports_answer(host::lifecycle(
        context.caller,
        json!({
            "check": "adoptable_ports",
            "env_port": context.request.env_port,
            "guard_home": home.to_string_lossy(),
            "state_port": state_port,
            "running_ports": running,
        }),
    )));
    let mut seen = Vec::new();
    ports.retain(|port| {
        let fresh = !seen.contains(port);
        seen.push(*port);
        fresh
    });
    for port in ports {
        let Some(pid) = existing_daemon_pid(context, port) else {
            continue;
        };
        let (Ok(port16), Ok(pid32)) = (u16::try_from(port), u32::try_from(pid)) else {
            continue;
        };
        let config = launch_config(context, port16, None)?;
        if standalone::publish(home, &config, port16, pid32).is_ok() {
            return Some(format!("http://127.0.0.1:{port}"));
        }
    }
    None
}

/// `_initialize_existing_guard_daemon`: the pid of a current daemon of this
/// home answering on `port`.
fn existing_daemon_pid(context: &Context<'_>, port: i64) -> Option<i64> {
    let home = context.home();
    let url = format!("http://127.0.0.1:{port}");
    let health = http_get_json(&format!("{url}/healthz"), &[])?;
    if !healthz_payload_is_current(&health) {
        return None;
    }
    let auth = crate::daemon_policy_authority::load_guard_daemon_auth_token(home)?;
    if auth.trim().is_empty() {
        return None;
    }
    let header = format!("X-Guard-{}", "Token");
    let details = http_get_json(
        &format!("{url}/v1/healthz/details"),
        &[(header.as_str(), auth.as_str())],
    )?;
    let map = details.as_object()?;
    if !healthz_payload_matches_guard_home(&details, home) {
        return None;
    }
    let fingerprint_current = text(map, "runtime_fingerprint").is_some()
        && text(map, "runtime_fingerprint") == context.current_text("runtime_fingerprint");
    let runtime_current = fingerprint_current
        || (map.get("source_root").is_some_and(Value::is_string) && runtime_matches(context, map));
    if !runtime_current {
        return None;
    }
    int(map, "pid").filter(|pid| *pid > 0)
}

/// The launch line for one daemon on `port`.
fn launch_config(context: &Context<'_>, port: u16, nonce: Option<&str>) -> Option<LaunchConfig> {
    let mut launch = context.request.launch.clone();
    launch.insert("port".into(), port.into());
    match nonce {
        Some(nonce) => launch.insert("launch_nonce".into(), nonce.into()),
        None => launch.remove("launch_nonce"),
    };
    LaunchConfig::parse(&serde_json::to_vec(&Value::Object(launch)).ok()?)
}

pub(super) fn load_progress(home: &Path) -> Option<Map<String, Value>> {
    let raw = read_private_regular_text(&home.join(PROGRESS_FILE), PROGRESS_MAX_BYTES, true)?;
    let Value::Object(payload) = serde_json::from_str(&raw).ok()? else {
        return None;
    };
    if !verify_daemon_state(&payload, &load_daemon_discovery_key(home)?)
        || text(&payload, "state_kind") != Some("daemon_start_progress")
    {
        return None;
    }
    int(&payload, "pid").filter(|pid| *pid > 0)?;
    int(&payload, "port").filter(|port| (1..=65535).contains(port))?;
    int(&payload, "recorded_at_ns").filter(|at| *at > 0)?;
    int(&payload, "spawned_at_ns").filter(|at| *at > 0)?;
    let marker_key = format!("process_start_{}", "token");
    text(&payload, &marker_key).filter(|marker| !marker.is_empty())?;
    let recorded = host::resolve_lenient(Path::new(text(&payload, "guard_home")?));
    (recorded == host::resolve_lenient(home)).then_some(payload)
}

fn progress_is_live(caller: &Caller, progress: &Map<String, Value>) -> bool {
    let marker_key = format!("process_start_{}", "token");
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as i64);
    let mut record = Map::new();
    record.insert(
        "pid".into(),
        progress.get("pid").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        marker_key.clone(),
        progress.get(&marker_key).cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "recorded_at_ns".into(),
        progress
            .get("recorded_at_ns")
            .cloned()
            .unwrap_or(Value::Null),
    );
    host::lifecycle(
        caller,
        json!({
            "check": "start_progress_live",
            "record": record,
            "now_ns": now_ns,
            "worker_ready_floor": WORKER_READY_FLOOR_SECONDS,
        }),
    )
    .and_then(|answer| answer.get("live").and_then(Value::as_bool))
    .unwrap_or(false)
}

fn clear_progress(home: &Path) {
    if home.join(PROGRESS_FILE).is_file() {
        let _ = write_record_tombstone(home, PROGRESS_FILE);
    }
}

/// `_retire_guard_daemon_process`: a stale state's daemon, signalled only
/// when its recorded generation still runs.
fn retire_process(caller: &Caller, stale: &Map<String, Value>, deadline: Deadline) -> bool {
    let pid = int(stale, "pid").unwrap_or(0);
    if pid <= 0 {
        return false;
    }
    let marker = text(stale, "process_start_marker").filter(|marker| !marker.is_empty());
    let owner = text(stale, "user").filter(|owner| !owner.is_empty());
    match marker {
        None => {
            host::pid_is_proven_dead(pid)
                || host::command_identity(caller, pid, Some(&caller.guard_home)) == Some(false)
        }
        Some(marker) => retire::retire_generation(caller, pid, marker, owner, deadline),
    }
}

fn nonce() -> Result<String, Failure> {
    let mut buffer = [0u8; 32];
    getrandom::fill(&mut buffer)
        .map_err(|_| runtime("Guard daemon launch nonce is unavailable."))?;
    Ok(hex::encode(buffer))
}

/// One launch: spawn, record the signed pending receipt, release the gate,
/// then wait for a handoff that binds this launch.
fn launch_once(context: &Context<'_>, port: i64) -> Result<Option<String>, Failure> {
    let port16 = u16::try_from(port).map_err(|_| runtime("Guard daemon port is invalid."))?;
    let nonce = nonce()?;
    let request = context.request;
    let home = context.home();
    let native = request.executable.is_none();
    let mut command = match request.executable {
        Some(executable) => {
            let mut command = Command::new(executable);
            command.args(["daemon", "--serve", "--guard-home"]);
            command.arg(home);
            command.arg("--home");
            command.arg(request.home_dir.unwrap_or_default());
            command.args(["--port", &port.to_string()]);
            command
        }
        None => {
            let serve = request
                .serve_executable
                .ok_or_else(|| runtime("Guard daemon requires the native runtime."))?;
            let mut command = Command::new(serve);
            command.args([standalone::SERVE_COMMAND, "--guard-home"]);
            command.arg(launch_home(request.launch)?);
            command.args(["--port", &port.to_string()]);
            command
        }
    };
    let config_line = if native {
        if launch_config(context, port16, Some(&nonce)).is_none() {
            return Err(runtime("Guard daemon launch configuration is invalid."));
        }
        let mut launch = request.launch.clone();
        launch.insert("port".into(), port16.into());
        launch.insert("launch_nonce".into(), nonce.clone().into());
        let mut line = serde_json::to_vec(&Value::Object(launch))
            .map_err(|_| runtime("Guard daemon launch configuration is invalid."))?;
        line.push(b'\n');
        Some(line)
    } else {
        None
    };
    command.env_clear();
    command.envs(request.launcher_env);
    if !native {
        command.env(NONCE_ENV, &nonce);
    }
    if let Some(cwd) = request.launch_cwd {
        command.current_dir(cwd);
    }
    command
        .stdin(if native {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Breakaway first on Windows: the launcher's own job is closed when the
    // call returns and must not take the handed-off daemon with it. A job
    // that forbids breakaway refuses the spawn, so retry inside it.
    detach(
        &mut command,
        native,
        cfg!(windows) || request.allow_windows_job_breakaway,
    );
    let spawned = match command.spawn() {
        Ok(child) => Ok(child),
        Err(_) if cfg!(windows) && !request.allow_windows_job_breakaway => {
            detach(&mut command, native, false);
            command.spawn()
        }
        Err(error) => Err(error),
    };
    let mut child = spawned.map_err(|_| runtime("Guard daemon process could not be started."))?;
    match supervise(context, &mut child, port, &nonce, config_line) {
        // Handed off: the process belongs to the daemon lifecycle now.
        Ok(Handoff::Done(outcome)) => outcome.map(Some),
        Ok(Handoff::Missing) => {
            terminate(&mut child);
            Err(runtime(NOT_CONTAINED))
        }
        Err(failure) => {
            terminate(&mut child);
            Err(failure)
        }
    }
}

fn launch_home(launch: &Map<String, Value>) -> Result<&str, Failure> {
    text(launch, "guard_home")
        .ok_or_else(|| runtime("Guard daemon launch configuration is invalid."))
}

/// Puts the daemon outside the launcher's process group, console and job,
/// so the launcher's cleanup never reaches a daemon it handed off. The
/// native daemon leaves the session itself (`setsid` in `daemon-serve`).
fn detach(command: &mut Command, native: bool, allow_breakaway: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if !native {
            command.process_group(0);
        }
        let _ = allow_breakaway;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = native;
        let mut flags = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;
        if allow_breakaway {
            flags |= CREATE_BREAKAWAY_FROM_JOB;
        }
        command.creation_flags(flags);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (command, native, allow_breakaway);
    }
}

fn child_exited(child: &mut Child) -> bool {
    !matches!(child.try_wait(), Ok(None))
}

fn retried_marker(child: &mut Child, read: fn(i64) -> Option<String>, pid: i64) -> Option<String> {
    for attempt in 0..MARKER_ATTEMPTS {
        if let Some(marker) = read(pid).filter(|marker| !marker.is_empty()) {
            return Some(marker);
        }
        if child_exited(child) {
            return None;
        }
        if attempt + 1 < MARKER_ATTEMPTS {
            std::thread::sleep(MARKER_RETRY);
        }
    }
    None
}

enum Handoff {
    Done(Result<String, Failure>),
    /// The child never handed off; its receipt stays.
    Missing,
}

fn supervise(
    context: &Context<'_>,
    child: &mut Child,
    port: i64,
    nonce: &str,
    config_line: Option<Vec<u8>>,
) -> Result<Handoff, Failure> {
    let home = context.home();
    let pid = i64::from(child.id());
    let marker = retried_marker(child, host::start_marker, pid)
        .ok_or_else(|| runtime("Guard daemon process start marker could not be recorded."))?;
    let owner = retried_marker(child, host::owner_marker, pid)
        .ok_or_else(|| runtime("Guard daemon process owner could not be recorded."))?;
    let creation_time = if host::nt() {
        Some(
            host::windows_creation_time(pid)
                .ok_or_else(|| runtime("Guard daemon process identity could not be recorded."))?,
        )
    } else {
        None
    };
    let mut pending = Map::new();
    pending.insert("state_kind".into(), "daemon_launch_pending".into());
    pending.insert(
        "guard_home".into(),
        host::resolve_lenient(home)
            .to_string_lossy()
            .into_owned()
            .into(),
    );
    pending.insert("pid".into(), pid.into());
    pending.insert("port".into(), port.into());
    for key in ["launch_nonce", "launch_generation", "generation"] {
        pending.insert(key.into(), nonce.into());
    }
    pending.insert("process_start_marker".into(), marker.clone().into());
    pending.insert("user".into(), owner.clone().into());
    pending.insert("owner".into(), owner.into());
    if let Some(fingerprint) = context.current.get("runtime_fingerprint") {
        pending.insert("runtime_fingerprint".into(), fingerprint.clone());
    }
    if let Some(created) = creation_time {
        pending.insert("process_creation_time".into(), created.into());
    }
    write_signed_record(home, PENDING_FILE, pending)
        .map_err(|_| runtime("Guard daemon launch receipt could not be recorded."))?;
    if let Some(line) = config_line {
        let released = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(&line).and_then(|()| stdin.flush()).is_ok());
        if !released {
            return Ok(Handoff::Missing);
        }
    }
    let native = context.request.executable.is_none();
    let remaining = context.deadline.remaining().unwrap_or_default();
    let reserve = remaining.mul_f64(0.25).min(Duration::from_secs(3));
    let wait_deadline = Instant::now() + remaining.saturating_sub(reserve);
    loop {
        let url = if native {
            live_url(context, true, None)
        } else {
            live_url(context, false, Some(pid))
        };
        if let Some(url) = url {
            if handoff_binds(context, nonce, pid, url_port(&url), native) {
                let cleared = records::clear_pending_if_current(
                    home,
                    pid,
                    creation_time,
                    Some(nonce),
                    Some(&marker),
                );
                return Ok(Handoff::Done(if cleared {
                    Ok(url)
                } else {
                    Err(runtime(
                        "Guard daemon pending launch state could not be cleared safely.",
                    ))
                }));
            }
        }
        if child_exited(child) || Instant::now() >= wait_deadline {
            return Ok(Handoff::Missing);
        }
        std::thread::sleep(host::POLL_INTERVAL);
    }
}

/// `_guard_daemon_handoff_matches_launch`.
fn handoff_binds(
    context: &Context<'_>,
    nonce: &str,
    pid: i64,
    expected_port: Option<i64>,
    require_same_runtime: bool,
) -> bool {
    if !retire::handoff_matches_launch(context.caller, nonce, pid) {
        return false;
    }
    let home = context.home();
    let (Some(pending), Some((state, _))) = (
        records::load_pending(home),
        load_authenticated_daemon_identity(home),
    ) else {
        return false;
    };
    if expected_port.is_some_and(|port| int(&state, "port") != Some(port)) {
        return false;
    }
    !require_same_runtime || pending.get("runtime_fingerprint") == state.get("runtime_fingerprint")
}

/// `_terminate_spawned_guard_daemon`.
fn terminate(child: &mut Child) {
    let pid = i64::from(child.id());
    let wait = |child: &mut Child| {
        let until = Instant::now() + TERMINATE_WAIT;
        while Instant::now() < until {
            if child_exited(child) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        child_exited(child)
    };
    if host::signal(pid, false).is_err() {
        let _ = child.kill();
    }
    if wait(child) {
        return;
    }
    if host::signal(pid, true).is_err() {
        let _ = child.kill();
    }
    let _ = wait(child);
}

#[cfg(test)]
mod tests {
    use super::source_is_desktop_core;

    #[test]
    fn desktop_core_shapes_match_only_desktop_layouts() {
        for shape in [
            "/Users/a/Library/Application Support/org.hol.guard.desktop/core/versions/1.2.3",
            "/Applications/HOL Guard.app/Contents/Resources/hol-guard",
            r"C:\Program Files\HOL Guard\hol-guard\hol-guard.exe",
            "/opt/x/current-hol-guard",
            "/opt/x/bundled/1.2.3/bin/hol-guard",
            "/opt/x/bundled/1.2.3/lib/hol-guard-core/hol-guard",
            "/opt/core/versions/1.2.3/hol-guard",
        ] {
            assert!(source_is_desktop_core(shape), "{shape}");
        }
        for shape in ["/src/hol-guard", "/home/a/.local/pipx/venvs/hol-guard/lib"] {
            assert!(!source_is_desktop_core(shape), "{shape}");
        }
    }
}
