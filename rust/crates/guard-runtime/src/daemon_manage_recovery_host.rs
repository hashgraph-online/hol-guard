//! The native effect host for `daemon-recovery` sessions.
//!
//! A recovery session asks for effects (clock, locks, stop, start, live
//! probes, the snapshot store). With a host the runtime answers them itself
//! from the same records `daemon-manage` owns; only `authorize`,
//! `protection_health` and the caller's own `emit`/`record` output still go
//! back to the caller.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde_json::{json, Map, Value};

use super::ensure::{self, Failure};
use super::host::{self, Caller};
use super::live_probe;
use super::records;
use super::recover;
use super::retire::{self, Deadline, Expected};
use super::Request;
use crate::daemon_policy_authority::load_authenticated_daemon_state;
use crate::native_review_link::now_micros;
use crate::policy_bundle_time::micros_to_utc_isoformat;

/// How the host answered one need.
pub(crate) enum Served {
    Answer(Value),
    Raise(&'static str),
    /// The caller answers, with these arguments.
    Forward(Value),
}

pub(crate) struct RecoveryHost {
    request: Request,
    caller: Caller,
    current: Map<String, Value>,
    locks: HashMap<String, File>,
    epoch: Instant,
}

/// A host for the `daemon-manage.v1` request `raw` (any op; the launch
/// fields are what `start` uses).
pub(crate) fn recovery_host(raw: Map<String, Value>) -> Result<RecoveryHost, String> {
    let request: Request =
        serde_json::from_value(Value::Object(raw)).map_err(|_| super::invalid())?;
    if request.schema != super::SCHEMA || !request.guard_home.is_absolute() {
        return Err(super::invalid());
    }
    let caller = super::caller_of(&request);
    let current = request
        .launch
        .get("state")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    Ok(RecoveryHost {
        request,
        caller,
        current,
        locks: HashMap::new(),
        epoch: Instant::now(),
    })
}

fn seconds(args: &Value, key: &str) -> f64 {
    args.get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .unwrap_or(0.0)
        .max(0.0)
}

fn within(secs: f64) -> Deadline {
    Deadline(Some(
        Instant::now() + Duration::from_secs_f64(secs.min(600.0)),
    ))
}

impl RecoveryHost {
    fn home(&self) -> &Path {
        &self.caller.guard_home
    }

    pub(crate) fn serve(&mut self, need: &str, args: &Value) -> Served {
        match need {
            "clock" => Served::Answer(json!(self.epoch.elapsed().as_secs_f64())),
            "wall" => match now_micros().and_then(|now| micros_to_utc_isoformat(now, "+00:00")) {
                Some(text) => Served::Answer(json!(text)),
                None => Served::Raise("runtime"),
            },
            "posture" => Served::Answer(json!(recover::posture(self.home()))),
            "update_busy" => Served::Answer(json!(live_probe::update_busy(self.home()))),
            "user_marker" => Served::Answer(json!(host::own_owner_marker())),
            "owner_marker" => Served::Answer(json!(args
                .get("pid")
                .and_then(Value::as_i64)
                .and_then(host::owner_marker))),
            "lock" => self.lock(
                args.get("name").and_then(Value::as_str).unwrap_or_default(),
                seconds(args, "timeout"),
            ),
            "release" => {
                if let Some(name) = args.get("name").and_then(Value::as_str) {
                    self.locks.remove(name);
                }
                Served::Answer(Value::Null)
            }
            "process_dead" => match identity_pid(args) {
                Some(pid) => Served::Answer(json!(host::pid_is_proven_dead(pid))),
                None => Served::Raise("value"),
            },
            "stop" => self.stop(args),
            "start" => self.start(seconds(args, "remaining")),
            "inspect" => {
                let timeout = args.get("timeout").and_then(Value::as_f64).unwrap_or(1.0);
                let posture = recover::posture(self.home());
                let busy = live_probe::update_busy(self.home());
                Served::Answer(json!({
                    "service": self.inspect_service(timeout.max(0.0)),
                    "posture": posture,
                    "update_busy": busy,
                }))
            }
            "verify_ready" => {
                let service = self.inspect_service(seconds(args, "remaining"));
                let ready = service["service"] == "ready"
                    && service["authenticated"] == true
                    && service["dashboard_ready"] == true;
                Served::Answer(json!({
                    "ready": ready,
                    "identity": service["identity"],
                    "reason_code": if ready { json!("healthy") } else { service["reason_code"].clone() },
                }))
            }
            "load_snapshot" => Served::Answer(self.durable_snapshot()),
            "load_receipt" => self.receipt(args.get("request_id").and_then(Value::as_str)),
            "emit" => {
                let snapshot = args.get("snapshot").cloned().unwrap_or(Value::Null);
                if args.get("persist").and_then(Value::as_bool) == Some(true) {
                    if let Err(kind) = self.persist(&snapshot) {
                        return Served::Raise(kind);
                    }
                }
                Served::Forward(json!({"snapshot": snapshot, "persist": false}))
            }
            "expire" => {
                let snapshot = args.get("snapshot").cloned().unwrap_or(Value::Null);
                Served::Answer(json!(self.persist(&snapshot).is_ok()))
            }
            _ => Served::Forward(args.clone()),
        }
    }

    fn store(&self, request: Value) -> Result<Value, &'static str> {
        let home = self.home().to_string_lossy();
        crate::daemon_recovery_store::answer(&home, &request).map_err(|fail| match fail.kind {
            "storage" => "os",
            "state" => "runtime",
            _ => "value",
        })
    }

    fn persist(&self, snapshot: &Value) -> Result<(), &'static str> {
        self.store(json!({"op": "persist", "snapshot": snapshot}))
            .map(|_| ())
    }

    fn validated(&self, snapshot: Value) -> Option<Value> {
        self.store(json!({"op": "validate", "snapshot": snapshot, "allow_inspection": false}))
            .ok()
    }

    /// The persisted snapshot for the runtime's pending check.
    fn durable_snapshot(&self) -> Value {
        match self.store(json!({"op": "latest"})) {
            Err(_) => json!({"kind": "unavailable"}),
            Ok(Value::Null) => json!({"kind": "none"}),
            Ok(snapshot @ Value::Object(_)) => match self.validated(snapshot) {
                Some(valid) => json!({"kind": "snapshot", "snapshot": valid}),
                None => json!({"kind": "unavailable"}),
            },
            Ok(_) => json!({"kind": "unavailable"}),
        }
    }

    /// One validated durable record for `request_id`, as a replay hint only.
    fn receipt(&self, request_id: Option<&str>) -> Served {
        let Some(request_id) = request_id else {
            return Served::Answer(Value::Null);
        };
        let raw = match self.store(json!({"op": "receipt", "operation_id": request_id})) {
            Ok(Value::Null) => return Served::Answer(Value::Null),
            Ok(raw @ Value::Object(_)) => raw,
            _ => return Served::Raise("receipt_unavailable"),
        };
        let candidate = raw.get("snapshot").cloned().unwrap_or(raw);
        if !candidate.is_object() {
            return Served::Raise("receipt_unavailable");
        }
        match self.validated(candidate) {
            Some(snapshot)
                if snapshot.get("operationId").and_then(Value::as_str) == Some(request_id) =>
            {
                Served::Answer(snapshot)
            }
            _ => Served::Raise("receipt_unavailable"),
        }
    }

    fn lock(&mut self, name: &str, timeout: f64) -> Served {
        let file = match name {
            "recovery" => {
                let Some(file) = recover::lock_file(self.home(), recover::RECOVERY_LOCK_FILE)
                else {
                    return Served::Raise("lock_unavailable");
                };
                let deadline = within(timeout);
                loop {
                    if file.try_lock_exclusive().is_ok() {
                        break file;
                    }
                    if deadline.passed() {
                        return Served::Raise("lock_timeout");
                    }
                    std::thread::sleep(host::POLL_INTERVAL);
                }
            }
            "start" => match ensure::start_lock(self.home(), within(timeout)) {
                Ok(file) => file,
                Err(Failure::Timeout(_)) => return Served::Raise("timeout"),
                Err(Failure::Runtime(_)) => return Served::Raise("runtime"),
            },
            _ => return Served::Raise("value"),
        };
        self.locks.insert(name.to_owned(), file);
        Served::Answer(Value::Null)
    }

    /// Stop exactly the generation `identity` names.
    fn stop(&self, args: &Value) -> Served {
        let unconfirmed =
            json!({"exit_confirmed": false, "reason_code": "worker_exit_unconfirmed"});
        let Some(identity) = args.get("identity").and_then(Value::as_object) else {
            return Served::Raise("value");
        };
        let (Some(pid), Some(marker), Some(user)) = (
            identity
                .get("pid")
                .and_then(Value::as_i64)
                .filter(|pid| *pid > 0),
            identity.get("start_marker").and_then(Value::as_str),
            identity.get("user").and_then(Value::as_str),
        ) else {
            return Served::Answer(unconfirmed);
        };
        if host::start_marker(pid).as_deref() != Some(marker)
            || host::owner_marker(pid).as_deref() != Some(user)
        {
            return Served::Answer(unconfirmed);
        }
        let creation_time = match marker.strip_prefix("windows:") {
            Some(raw) => match raw.parse::<i64>() {
                Ok(value) => Some(value),
                Err(_) => return Served::Answer(unconfirmed),
            },
            None => None,
        };
        let expected = Expected {
            creation_time,
            start_marker: Some(marker),
            owner_marker: None,
        };
        let deadline = within(seconds(args, "remaining"));
        if retire::retire_pid(&self.caller, pid, &expected, deadline) {
            Served::Answer(json!({"exit_confirmed": true, "reason_code": "healthy"}))
        } else {
            Served::Answer(unconfirmed)
        }
    }

    /// Clear a verified dead generation's record, then launch through the
    /// same `ensure` path every launcher uses.
    fn start(&self, remaining: f64) -> Served {
        let home = self.home();
        if load_authenticated_daemon_state(home).is_some() && records::clear_state(home).is_err() {
            return Served::Raise("os");
        }
        let mut request = super::ensure_of(&self.request);
        request.start_lock_held = self.locks.contains_key("start");
        if let Err(failure) = ensure::ensure(&self.caller, &request, within(remaining)) {
            return Served::Raise(match failure {
                Failure::Timeout(_) => "timeout",
                Failure::Runtime(_) => "runtime",
            });
        }
        let unverified =
            json!({"started": true, "identity": null, "reason_code": "identity_unverified"});
        let Some(state) = load_authenticated_daemon_state(home) else {
            return Served::Answer(unverified);
        };
        match self.identity_from(&state) {
            Some(identity) if self.same_home(&identity["guard_home"]) => Served::Answer(
                json!({"started": true, "identity": identity, "reason_code": "healthy"}),
            ),
            _ => Served::Answer(unverified),
        }
    }

    fn same_home(&self, value: &Value) -> bool {
        value.as_str().is_some_and(|raw| {
            host::resolve_lenient(Path::new(raw)) == host::resolve_lenient(self.home())
        })
    }

    /// `_identity_from_value`: every identity field present and non-empty.
    fn identity_from(&self, value: &Map<String, Value>) -> Option<Value> {
        let marker = |keys: [&str; 2]| {
            keys.iter()
                .find_map(|key| value.get(*key))
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
                .map(str::to_owned)
        };
        let pid = value
            .get("pid")
            .and_then(Value::as_i64)
            .filter(|pid| *pid > 0)?;
        if value.get("pid").is_some_and(Value::is_boolean) {
            return None;
        }
        let generation = marker(["generation", "state_id"])?;
        let runtime = marker(["runtime", "runtime_fingerprint"])?;
        let home = value.get("guard_home").and_then(Value::as_str)?;
        let user = marker(["user", "uid"])?;
        let start = marker(["start_marker", "process_start_marker"])?;
        Some(json!({
            "pid": pid,
            "generation": generation,
            "runtime": runtime,
            "guard_home": host::resolve_lenient(&PathBuf::from(home)).to_string_lossy(),
            "user": user,
            "start_marker": start,
            "handle": null,
        }))
    }

    fn os_evidence_matches(identity: &Value) -> bool {
        let (Some(pid), Some(start), Some(user)) = (
            identity["pid"].as_i64(),
            identity["start_marker"].as_str(),
            identity["user"].as_str(),
        ) else {
            return false;
        };
        host::start_marker(pid).as_deref() == Some(start)
            && host::owner_marker(pid).as_deref() == Some(user)
    }

    /// `_default_inspect_service`.
    fn inspect_service(&self, timeout: f64) -> Value {
        let service = |service: &str, reason: &str, identity: &Value, running: bool| {
            json!({
                "service": service,
                "reason_code": reason,
                "identity": identity,
                "process_running": running,
                "authenticated": false,
                "dashboard_ready": false,
                "protection": "unknown",
                "checks": [],
            })
        };
        let home = self.home();
        let Some(state) = load_authenticated_daemon_state(home) else {
            let count = host::daemon_inventory(&self.caller).map_or(0, |items| items.len());
            let reason = match count {
                0 => "service_missing",
                1 => "identity_unverified",
                _ => "multiple_instances",
            };
            return service("unavailable", reason, &Value::Null, false);
        };
        let Some(identity) = self.identity_from(&state) else {
            return service("unavailable", "identity_unverified", &Value::Null, false);
        };
        if !self.same_home(&identity["guard_home"]) {
            return service("unavailable", "identity_unverified", &identity, true);
        }
        if !ensure::state_matches(&self.current, &state) {
            return service("unavailable", "runtime_mismatch", &identity, true);
        }
        let pid = identity["pid"].as_i64().unwrap_or_default();
        if !host::pid_is_running(pid) {
            return service("unavailable", "service_missing", &identity, false);
        }
        match host::command_identity(&self.caller, pid, Some(home)) {
            Some(true) => {}
            Some(false) => return service("unavailable", "endpoint_conflict", &identity, true),
            None => return service("unavailable", "identity_unverified", &identity, true),
        }
        if !Self::os_evidence_matches(&identity) {
            return service("unavailable", "identity_unverified", &identity, true);
        }
        let (live, reason) = live_probe::probe_live(self.home(), timeout.min(1.0));
        let Some(live) = live else {
            return service("unavailable", "service_unresponsive", &identity, true);
        };
        let live_identity = self.identity_from(&live).unwrap_or(identity);
        if !Self::os_evidence_matches(&live_identity) {
            return service("unavailable", "identity_unverified", &live_identity, true);
        }
        let mut ready = service("ready", reason, &live_identity, true);
        ready["authenticated"] = json!(true);
        ready["dashboard_ready"] = json!(reason == "healthy");
        ready
    }
}

fn identity_pid(args: &Value) -> Option<i64> {
    args.get("identity")?
        .get("pid")?
        .as_i64()
        .filter(|pid| *pid > 0)
}
