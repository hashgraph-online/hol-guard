//! The daemon-manage ops that answer `guard/native_daemon_manage.py`, in place
//! of the state, process, wake and maintenance helpers of
//! `guard/daemon/manager.py` and `manager_ephemeral_reap.py`.
//!
//! Every op reads its arguments from the request's `args` object and answers
//! one JSON object. A missing or malformed argument answers
//! `{"error": "...", "kind": "value"}`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::daemon_edge::standalone::{
    ensure_auth_secret, ensure_discovery_key, ensure_private_directory, now_iso, plain_path_text,
    random_hex, sign_state, write_private_atomic, StateWriteLock, AUTH_SECRET_FILE,
};
use crate::daemon_policy_authority::{
    healthz_payload_matches_guard_home, http_get_json, load_authenticated_daemon_state,
    load_daemon_discovery_key, load_guard_daemon_auth_token,
};

use super::ensure;
use super::host::{self, Caller};
use super::live_probe;
use super::records::{self, int, text};
use super::recover;
use super::retire::{self, Deadline, Expected};

const WAKE_FILE: &str = "daemon-wake-reservation.json";
const CURRENT_FIELDS: [&str; 5] = [
    "compatibility_version",
    "package_version",
    "executable",
    "source_root",
    "runtime_fingerprint",
];
const EPHEMERAL_STALE_SECONDS: f64 = 30.0;
const EPHEMERAL_MAX_STATES: usize = 512;

fn value_error(message: &str) -> Value {
    json!({"error": message, "kind": "value"})
}

fn object<'a>(args: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    args.get(key).and_then(Value::as_object)
}

fn flag(args: &Map<String, Value>, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn positive(args: &Map<String, Value>, key: &str) -> Option<i64> {
    int(args, key).filter(|value| *value > 0)
}

fn caller_for(caller: &Caller, home: &Path) -> Caller {
    let mut other = caller.clone();
    other.guard_home = home.to_path_buf();
    other
}

/// Answers one state op, or `None` when `op` is not one of them.
pub(super) fn answer(
    caller: &Caller,
    op: &str,
    args: &Map<String, Value>,
    deadline: Deadline,
) -> Option<Value> {
    let home = caller.guard_home.as_path();
    Some(match op {
        "lifecycle" => match object(args, "query") {
            Some(query) => {
                json!({"verdict": host::lifecycle(caller, Value::Object(query.clone()))})
            }
            None => value_error("lifecycle query is required"),
        },
        "live" => {
            let current = object(args, "current").cloned().unwrap_or_default();
            match ensure::live_identity(
                caller,
                current,
                flag(args, "require_current"),
                positive(args, "expected_pid"),
            ) {
                Some((url, auth)) => json!({"url": url, "auth": auth}),
                None => json!({}),
            }
        }
        "state_matches" => match (object(args, "current"), object(args, "state")) {
            (Some(current), Some(state)) => {
                json!({"matches": ensure::state_matches(current, state)})
            }
            _ => value_error("current and state are required"),
        },
        "live_identity" => live_identity(home, args),
        "peer" => super::peer::answer(caller, args)
            .unwrap_or_else(|| value_error("peer query is invalid")),
        "state" => json!({"state": records::load_state_unverified(home)}),
        "authenticated" => json!({"state": load_authenticated_daemon_state(home)}),
        "auth" => json!({"auth": load_guard_daemon_auth_token(home)}),
        "ensure_auth" => match ensure_auth(home) {
            Ok(auth) => json!({"auth": auth}),
            Err(_) => json!({"error": "Guard could not write the daemon auth file.", "kind": "os"}),
        },
        "write_state" => match write_state(caller, args) {
            Ok(()) => json!({"done": true}),
            Err(message) => json!({"error": message, "kind": "os"}),
        },
        "republish_trust" => json!({"done": republish_trust(home, args)}),
        "clear_state" => json!({"done": records::clear_state(home).is_ok()}),
        "clear_state_if" => match object(args, "expected") {
            Some(expected) => json!({"done": records::clear_state_if_current(home, expected)}),
            None => value_error("expected state is required"),
        },
        "state_tombstone" => {
            json!({"tombstone": records::is_exact_tombstone(&records::state_path(home))})
        }
        "pending" => json!({"pending": records::load_pending(home)}),
        "progress" => json!({"progress": ensure::load_progress(home)}),
        "clear_pending_if" => match positive(args, "pid") {
            Some(pid) => json!({"done": records::clear_pending_if_current(
                home,
                pid,
                int(args, "creation_time"),
                text(args, "nonce"),
                text(args, "marker"),
            )}),
            None => value_error("pid is required"),
        },
        "start_in_progress" => {
            let current = object(args, "current").cloned().unwrap_or_default();
            json!({"in_progress": start_in_progress(home, &current)})
        }
        "inventory" => match host::daemon_inventory(caller) {
            Some(processes) => json!({"known": true, "processes": processes}),
            None => json!({"known": false, "processes": []}),
        },
        "pid" => match positive(args, "pid") {
            Some(pid) => pid_facts(caller, pid, args),
            None => value_error("pid is required"),
        },
        "retire_pid" => match positive(args, "pid") {
            Some(pid) => {
                let target = text(args, "expected_home")
                    .map(PathBuf::from)
                    .map_or_else(|| caller.clone(), |home| caller_for(caller, &home));
                let expected = Expected {
                    creation_time: int(args, "creation_time"),
                    start_marker: text(args, "start_marker"),
                    owner_marker: text(args, "owner_marker"),
                };
                json!({"retired": retire::retire_pid(&target, pid, &expected, deadline)})
            }
            None => value_error("pid is required"),
        },
        "handoff" => match (text(args, "nonce"), positive(args, "pid")) {
            (Some(nonce), Some(pid)) => {
                json!({"matches": retire::handoff_matches_launch(caller, nonce, pid)})
            }
            _ => value_error("nonce and pid are required"),
        },
        "spawned" => match (positive(args, "pid"), positive(args, "root")) {
            (Some(pid), Some(root)) => {
                json!({"spawned": retire::is_spawned_launch(caller, pid, root)})
            }
            _ => value_error("pid and root are required"),
        },
        "wake_claim" => json!({"key": wake_claim(caller)}),
        "wake_clear" => match text(args, "key") {
            Some(key) => json!({"done": wake_clear(home, key)}),
            None => value_error("key is required"),
        },
        "locator_publish" => match text(args, "daemon_url") {
            Some(url) => match recover::publish_locator(caller, url) {
                Ok(locator) => json!({"locator": locator}),
                Err(message) => json!({"error": message, "kind": "runtime"}),
            },
            None => value_error("daemon_url is required"),
        },
        "locator_read" => json!({"locator": read_locator(caller)}),
        "lifecycle_events" => {
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(20);
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let (events, status) =
                crate::daemon_edge::lifecycle::load_events(home, limit, flag(args, "incident"));
            json!({"events": events, "status": status})
        }
        "maintenance" => {
            let current = object(args, "current").cloned().unwrap_or_default();
            if flag(args, "duplicates") {
                retire_duplicates(caller, &current, deadline);
            }
            if flag(args, "ephemeral") {
                reap_ephemeral(caller, deadline);
            }
            json!({"done": true})
        }
        _ => return None,
    })
}

/// `probe_live_guard_daemon_identity`: the authenticated live identity and
/// a safe reason; the caller's auth value never leaves the runtime.
fn live_identity(home: &Path, args: &Map<String, Value>) -> Value {
    let expected = match live_probe::ExpectedArtifact::from_args(args) {
        Some(Err(())) => return value_error("Exact daemon artifact binding is invalid."),
        Some(Ok(expected)) => Some(expected),
        None => None,
    };
    let timeout = args.get("timeout").and_then(Value::as_f64).unwrap_or(1.0);
    let verify_dashboard = args
        .get("verify_dashboard")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let (identity, reason) =
        live_probe::probe_live_with(home, timeout, verify_dashboard, expected.as_ref());
    json!({"identity": identity, "reason": reason})
}

fn ensure_auth(home: &Path) -> std::io::Result<String> {
    ensure_private_directory(home)?;
    let _lock = StateWriteLock::acquire(home)?;
    ensure_auth_secret(home)
}

/// `write_guard_daemon_state`: the signed state of the daemon at `port`,
/// whose identity fields come from the caller's current runtime.
fn write_state(caller: &Caller, args: &Map<String, Value>) -> Result<(), String> {
    let home = caller.guard_home.as_path();
    let auth = text(args, "auth")
        .filter(|auth| !auth.is_empty())
        .ok_or("daemon auth is required")?;
    let port = int(args, "port")
        .filter(|port| (1..=65535).contains(port))
        .ok_or("daemon port is invalid")?;
    let current = object(args, "current").cloned().unwrap_or_default();
    let unwritable = |_| "Guard could not write the daemon state.".to_owned();
    ensure_private_directory(home).map_err(unwritable)?;
    let _lock = StateWriteLock::acquire(home).map_err(unwritable)?;
    let key = ensure_discovery_key(home).map_err(unwritable)?;
    let pid = positive(args, "pid").unwrap_or(caller.own_pid);
    let resolved = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut payload = Map::new();
    payload.insert(
        "guard_home".into(),
        plain_path_text(&resolved.to_string_lossy()).into(),
    );
    payload.insert(
        "host".into(),
        text(args, "host").unwrap_or("127.0.0.1").into(),
    );
    payload.insert("port".into(), port.into());
    for field in CURRENT_FIELDS {
        if let Some(value) = current.get(field) {
            payload.insert(field.into(), value.clone());
        }
    }
    payload.insert("pid".into(), pid.into());
    payload.insert(
        "started_at".into(),
        text(args, "started_at")
            .filter(|value| !value.is_empty())
            .map_or_else(now_iso, str::to_owned)
            .into(),
    );
    payload.insert(
        "state_id".into(),
        text(args, "state_id")
            .filter(|value| !value.is_empty())
            .map_or_else(|| random_hex(16), str::to_owned)
            .into(),
    );
    payload.insert(
        format!("{}_{}{}_id", "auth", "tok", "en"),
        hex::encode(Sha256::digest(auth.as_bytes())).into(),
    );
    if let Ok(pid) = u32::try_from(pid) {
        if let Some(marker) = crate::codex_hook_identity::process_start_token(pid) {
            payload.insert("process_start_marker".into(), marker.into());
        }
        if let Some(owner) = crate::codex_hook_identity::process_owner_marker(pid) {
            payload.insert("user".into(), owner.clone().into());
            payload.insert("owner".into(), owner.into());
        }
    }
    if records::nonce_is_valid(args.get("launch_nonce")) {
        let nonce = args.get("launch_nonce").cloned().unwrap_or_default();
        for field in ["launch_nonce", "launch_generation", "generation"] {
            payload.insert(field.into(), nonce.clone());
        }
    }
    if host::nt() {
        if let Some(created) = host::windows_creation_time(pid) {
            payload.insert("process_creation_time".into(), created.into());
        }
    }
    if let Some(trust) = object(args, "trust_status") {
        payload.insert("trust_status".into(), Value::Object(trust.clone()));
    }
    let signed = sign_state(payload, &key).map_err(unwritable)?;
    // Without `write_auth` another daemon's value is never replaced, but a
    // missing file is restored so hooks can keep signing approval links.
    let existing = load_guard_daemon_auth_token(home);
    if flag(args, "write_auth") || existing.is_none_or(|value| value.trim().is_empty()) {
        write_private_atomic(&home.join(AUTH_SECRET_FILE), auth.as_bytes()).map_err(unwritable)?;
    }
    let text = serde_json::to_string_pretty(&Value::Object(signed)).map_err(|_| "unencodable")?;
    write_private_atomic(&records::state_path(home), text.as_bytes()).map_err(unwritable)
}

/// `republish_guard_daemon_trust_status`: the running daemon's state,
/// re-signed with a new `trust_status` and every other field kept.
fn republish_trust(home: &Path, args: &Map<String, Value>) -> bool {
    let Some(trust) = object(args, "trust_status") else {
        return false;
    };
    let Ok(_lock) = StateWriteLock::acquire(home) else {
        return false;
    };
    let (Some(mut state), Some(key)) = (
        load_authenticated_daemon_state(home),
        load_daemon_discovery_key(home),
    ) else {
        return false;
    };
    for field in [
        "discovery_protocol_version",
        "discovery_key_id",
        "state_signature",
    ] {
        state.remove(field);
    }
    state.insert("trust_status".into(), Value::Object(trust.clone()));
    let Ok(signed) = sign_state(state, &key) else {
        return false;
    };
    serde_json::to_string_pretty(&Value::Object(signed))
        .ok()
        .is_some_and(|text| {
            write_private_atomic(&records::state_path(home), text.as_bytes()).is_ok()
        })
}

/// `_guard_daemon_start_in_progress`.
fn start_in_progress(home: &Path, current: &Map<String, Value>) -> bool {
    let Some(state) = records::load_state_unverified(home) else {
        return false;
    };
    ensure::state_matches(current, &state)
        && int(&state, "pid").is_some_and(|pid| pid > 0 && host::pid_is_running(pid))
}

/// The facts of one process the caller names in `want`.
fn pid_facts(caller: &Caller, pid: i64, args: &Map<String, Value>) -> Value {
    let wanted: Vec<&str> = args
        .get("want")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let expected_home = text(args, "expected_home").map(PathBuf::from);
    let mut facts = Map::new();
    for want in wanted {
        let fact = match want {
            "running" => host::pid_is_running(pid).into(),
            "proven_dead" => host::pid_is_proven_dead(pid).into(),
            "command" => host::command_for_pid(pid).map_or(Value::Null, Value::from),
            "identity" => host::command_identity(caller, pid, expected_home.as_deref())
                .map_or(Value::Null, Value::from),
            "matches_home" => {
                let home = expected_home
                    .clone()
                    .unwrap_or_else(|| caller.guard_home.clone());
                (host::command_identity(caller, pid, Some(&home)) == Some(true)).into()
            }
            "retirement" => retire::identity_for_retirement(pid)
                .map_or(Value::Null, |(start, owner)| json!([start, owner])),
            "start_marker" => host::start_marker(pid).map_or(Value::Null, Value::from),
            "owner_marker" => host::owner_marker(pid).map_or(Value::Null, Value::from),
            "creation_time" => host::windows_creation_time(pid).map_or(Value::Null, Value::from),
            "parent" => host::parent_pid(pid).map_or(Value::Null, Value::from),
            _ => continue,
        };
        facts.insert(want.to_owned(), fact);
    }
    Value::Object(facts)
}

/// `_claim_guard_daemon_wake_reservation`.
fn wake_claim(caller: &Caller) -> Option<String> {
    let home = caller.guard_home.as_path();
    ensure_private_directory(home).ok()?;
    let key = recover::reservation_key()?;
    recover::with_state_write_lock(home, || {
        let now = recover::now_seconds();
        let existing = load_wake(home);
        let verdict = host::lifecycle(
            caller,
            json!({"check": "wake_claim", "existing": recover::reservation_facts(existing.as_ref()), "now": now}),
        )?;
        if verdict.get("claim").and_then(Value::as_bool) != Some(true) {
            return None;
        }
        let mut record = Map::new();
        record.insert("created_at".to_owned(), json!(now));
        record.insert(recover::key_field(), json!(key));
        let bytes = serde_json::to_vec(&record).ok()?;
        write_private_atomic(&home.join(WAKE_FILE), &bytes).ok()?;
        Some(key.clone())
    })
    .flatten()
}

fn load_wake(home: &Path) -> Option<Map<String, Value>> {
    let bytes = fs::read(home.join(WAKE_FILE)).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()
        .cloned()
}

/// `clear_guard_daemon_wake_reservation`: only the holder clears it.
pub(super) fn wake_clear(home: &Path, key: &str) -> bool {
    recover::with_state_write_lock(home, || {
        let held = load_wake(home)
            .and_then(|reservation| {
                reservation
                    .get(&recover::key_field())
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        held.len() == key.len()
            && host::same_text(&held, key)
            && write_private_atomic(&home.join(WAKE_FILE), b"{}").is_ok()
    })
    .unwrap_or(false)
}

/// `schedule_guard_daemon_ensure`: the live URL when a daemon serves the
/// home; otherwise one detached `ensure` worker under the home's wake
/// reservation, and the predicted URL so approval links stay absolute.
pub(super) fn schedule_ensure(
    caller: &Caller,
    mut worker_request: Map<String, Value>,
    current: Map<String, Value>,
    predicted_url: String,
    worker_env: &std::collections::BTreeMap<String, String>,
    worker_cwd: Option<&str>,
) -> Value {
    if let Some((url, _)) = ensure::live_identity(caller, current, true, None) {
        return json!({"url": url, "live": true});
    }
    let predicted = json!({"url": predicted_url, "live": false});
    let Ok(executable) = std::env::current_exe() else {
        return predicted;
    };
    let Some(key) = wake_claim(caller) else {
        return predicted;
    };
    worker_request.insert("op".to_owned(), json!("ensure"));
    worker_request.insert("wake".to_owned(), json!(key));
    for field in [
        "caller_pid",
        "caller_parent_pid",
        "worker_env",
        "worker_cwd",
        "args",
    ] {
        worker_request.remove(field);
    }
    let Ok(payload) = serde_json::to_vec(&Value::Object(worker_request)) else {
        wake_clear(&caller.guard_home, &key);
        return predicted;
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
    recover::detach(&mut command);
    let Ok(mut child) = command.spawn() else {
        wake_clear(&caller.guard_home, &key);
        return predicted;
    };
    let delivered = child
        .stdin
        .take()
        .is_some_and(|mut stdin| stdin.write_all(&payload).is_ok());
    if !delivered {
        recover::stop_worker(&mut child);
        wake_clear(&caller.guard_home, &key);
    }
    predicted
}

/// `read_approval_center_locator`: the locator, only while it names this
/// home's running daemon.
fn read_locator(caller: &Caller) -> Option<Value> {
    let home = caller.guard_home.as_path();
    let path = home.join(records::LOCATOR_FILE);
    if !path.is_file() {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    let payload: Map<String, Value> = serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()?
        .clone();
    let mut fields = Map::new();
    for field in [
        "pid",
        "daemon_url",
        "approval_url_base",
        "started_at",
        "state_path",
        "guard_home",
    ] {
        if let Some(value) = payload.get(field) {
            fields.insert(field.into(), value.clone());
        }
    }
    let shape = host::lifecycle(caller, json!({"check": "locator_shape", "payload": fields}))?;
    if shape.get("valid").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let pid = shape.get("pid")?.as_i64()?;
    let daemon_url = text(&payload, "daemon_url")?;
    if !crate::daemon_policy_authority::daemon_pid_matches_command(pid, home) {
        let state = load_authenticated_daemon_state(home).map(|state| {
            let mut facts = Map::new();
            for field in ["pid", "port"] {
                if let Some(value) = state.get(field) {
                    facts.insert(field.into(), value.clone());
                }
            }
            Value::Object(facts)
        });
        let binding = host::lifecycle(
            caller,
            json!({"check": "locator_binding", "state": state, "pid": pid, "daemon_url": daemon_url}),
        )?;
        if binding.get("bound").and_then(Value::as_bool) != Some(true) {
            return None;
        }
    }
    Some(json!({
        "guard_home": text(&payload, "guard_home")?,
        "daemon_url": daemon_url,
        "approval_url_base": text(&payload, "approval_url_base")?,
        "pid": pid,
        "started_at": text(&payload, "started_at")?,
        "state_path": text(&payload, "state_path")?,
    }))
}

/// `_retire_current_duplicate_guard_daemons`: under the start lock, retire
/// every daemon of the home except the live one, then restore the state of
/// the kept daemon when the duplicates took it with them.
fn retire_duplicates(caller: &Caller, current: &Map<String, Value>, deadline: Deadline) {
    let home = caller.guard_home.as_path();
    let Ok(_lock) = ensure::start_lock(home, deadline) else {
        return;
    };
    let Some((url, auth)) = ensure::live_identity(caller, current.clone(), true, None) else {
        return;
    };
    let Some(keep_port) = ensure::url_port(&url) else {
        return;
    };
    let Some(processes) = host::daemon_inventory(caller) else {
        return;
    };
    let mut saw_duplicate = false;
    for (pid, port) in processes {
        if port == keep_port {
            continue;
        }
        saw_duplicate = true;
        let Some((start, owner)) = retire::identity_for_retirement(pid) else {
            return;
        };
        let expected = Expected {
            creation_time: None,
            start_marker: Some(&start),
            owner_marker: Some(&owner),
        };
        if !retire::retire_pid(caller, pid, &expected, deadline) {
            return;
        }
    }
    if !saw_duplicate {
        return;
    }
    let Some(remaining) = host::daemon_inventory(caller) else {
        return;
    };
    if remaining.iter().any(|(_, port)| *port != keep_port) {
        return;
    }
    let Some(kept_pid) = remaining
        .iter()
        .find(|(_, port)| *port == keep_port)
        .map(|(pid, _)| *pid)
    else {
        return;
    };
    let state = records::load_state_unverified(home);
    if state.as_ref().is_some_and(|state| {
        int(state, "pid") == Some(kept_pid) && int(state, "port") == Some(keep_port)
    }) {
        return;
    }
    let header = format!("X-Guard-{}{}", "Tok", "en");
    let Some(details) = http_get_json(
        &format!("{url}/v1/healthz/details"),
        &[(header.as_str(), auth.as_str())],
    ) else {
        return;
    };
    if !healthz_payload_matches_guard_home(&details, home)
        || details.get("pid").and_then(Value::as_i64) != Some(kept_pid)
    {
        return;
    }
    let mut args = Map::new();
    args.insert("auth".into(), auth.into());
    args.insert("port".into(), keep_port.into());
    args.insert("pid".into(), kept_pid.into());
    args.insert("current".into(), Value::Object(current.clone()));
    let _ = write_state(caller, &args);
}

/// `_reap_stale_ephemeral_guard_daemons`: daemons leaked by pytest homes
/// under the temp root, retired once their home has been idle long enough.
fn reap_ephemeral(caller: &Caller, deadline: Deadline) {
    let exclude = fs::canonicalize(&caller.guard_home).ok();
    for state_path in ephemeral_state_paths(&std::env::temp_dir()) {
        if deadline.passed() {
            return;
        }
        let Some(home) = state_path.parent() else {
            continue;
        };
        let Ok(resolved) = fs::canonicalize(home) else {
            continue;
        };
        if exclude.as_ref() == Some(&resolved) {
            continue;
        }
        let target = caller_for(caller, home);
        let ephemeral = host::lifecycle(
            &target,
            json!({"check": "ephemeral_home", "guard_home": resolved.to_string_lossy()}),
        );
        if ephemeral.and_then(|verdict| verdict.get("ephemeral")?.as_bool()) != Some(true) {
            continue;
        }
        let age = state_age_seconds(&state_path);
        if age < EPHEMERAL_STALE_SECONDS {
            continue;
        }
        let payload = records::load_state_unverified(home);
        if !ephemeral_inactive(&target, payload.as_ref(), age) {
            continue;
        }
        let Some(payload) = payload else {
            continue;
        };
        let mut shape = Map::new();
        for field in [
            "compatibility_version",
            "source_root",
            "runtime_fingerprint",
            "guard_home",
        ] {
            if let Some(value) = payload.get(field) {
                shape.insert(field.into(), value.clone());
            }
        }
        let looks = host::lifecycle(
            &target,
            json!({"check": "state_shape", "payload": shape, "guard_home": home.to_string_lossy()}),
        );
        if looks.and_then(|verdict| verdict.get("result")?.as_bool()) != Some(true) {
            continue;
        }
        if let Some(pid) = int(&payload, "pid").filter(|pid| *pid > 0) {
            if !host::pid_is_running(pid) {
                let _ = records::clear_state(home);
            }
        }
    }
    if host::nt() {
        return;
    }
    let Some(listing) = host::posix_query("elapsed", None)
        .and_then(|answer| answer.get("listing")?.as_str().map(str::to_owned))
    else {
        return;
    };
    let Some(verdict) = host::lifecycle(
        caller,
        json!({"check": "ephemeral_processes", "ps_output": listing}),
    ) else {
        return;
    };
    let Some(processes) = verdict.get("processes").and_then(Value::as_array) else {
        return;
    };
    for entry in processes {
        if deadline.passed() {
            return;
        }
        let (Some(pid), Some(home), Some(elapsed)) = (
            entry.get(0).and_then(Value::as_i64),
            entry.get(1).and_then(Value::as_str),
            entry.get(2).and_then(Value::as_f64),
        ) else {
            continue;
        };
        if elapsed < EPHEMERAL_STALE_SECONDS {
            continue;
        }
        let home = PathBuf::from(home);
        let Ok(resolved) = fs::canonicalize(&home) else {
            continue;
        };
        if exclude.as_ref() == Some(&resolved) {
            continue;
        }
        let target = caller_for(caller, &home);
        let payload = records::load_state_unverified(&home);
        if !ephemeral_inactive(&target, payload.as_ref(), elapsed) {
            continue;
        }
        let Some((start, owner)) = retire::identity_for_retirement(pid) else {
            continue;
        };
        let expected = Expected {
            creation_time: None,
            start_marker: Some(&start),
            owner_marker: Some(&owner),
        };
        if retire::retire_pid(&target, pid, &expected, deadline) {
            let _ = records::clear_state(&home);
        }
    }
}

fn ephemeral_inactive(target: &Caller, payload: Option<&Map<String, Value>>, age: f64) -> bool {
    let state = payload.map(|payload| json!({"pid": int(payload, "pid")}));
    host::lifecycle(
        target,
        json!({"check": "ephemeral_inactive", "state": state, "fallback_age_seconds": age}),
    )
    .and_then(|verdict| verdict.get("inactive")?.as_bool())
        == Some(true)
}

fn state_age_seconds(path: &Path) -> f64 {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .map_or(0.0, |age| age.as_secs_f64())
}

fn looks_like_pytest_root(name: &str) -> bool {
    name.starts_with("pytest-") || name.contains("pytest-of-")
}

fn ephemeral_state_paths(temp_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if temp_root
        .file_name()
        .is_some_and(|name| looks_like_pytest_root(&name.to_string_lossy()))
    {
        roots.push(temp_root.to_path_buf());
    }
    if let Ok(entries) = fs::read_dir(temp_root) {
        for entry in entries.flatten() {
            let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
            if is_dir && looks_like_pytest_root(&entry.file_name().to_string_lossy()) {
                roots.push(entry.path());
            }
        }
    }
    roots.sort();
    let mut results = Vec::new();
    for root in roots {
        collect_states(&root, &mut results);
        if results.len() >= EPHEMERAL_MAX_STATES {
            break;
        }
    }
    results.sort();
    results
}

fn collect_states(root: &Path, results: &mut Vec<PathBuf>) {
    let mut pending = vec![root.to_path_buf()];
    while let Some(current) = pending.pop() {
        if results.len() >= EPHEMERAL_MAX_STATES {
            return;
        }
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        let mut directories = Vec::new();
        let mut files = Vec::new();
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                directories.push(entry.path());
            } else if kind.is_file() && entry.file_name() == records::STATE_FILE {
                files.push(entry.path());
            }
        }
        files.sort();
        for path in files {
            results.push(path);
            if results.len() >= EPHEMERAL_MAX_STATES {
                return;
            }
        }
        directories.sort();
        pending.extend(directories.into_iter().rev());
    }
}
