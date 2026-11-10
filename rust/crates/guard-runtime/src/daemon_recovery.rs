//! `daemon-recovery --stdin`: the user-requested daemon recovery sequence, in
//! place of the coordinator in `guard/daemon/user_recovery.py`.
//!
//! The session is a line protocol. The caller writes one request line; the
//! runtime then asks for each effect it needs (`{"need", "args", "state"}`)
//! and reads one answer line per ask (`{"ok": value}` or `{"raise": kind}`).
//! The caller owns the effects only: hooks, locks, the process-local
//! operation registry and the durable receipts. Every decision, deadline,
//! phase and public snapshot is made here. The session ends with
//! `{"done": snapshot, "state"}`, or `{"reraise": true, "state"}` when an
//! effect failed where the caller must see its own error.
//!
//! Modes (schema `daemon-recovery.v1`):
//! - `inspect`: classify the service read-only.
//! - `run`: one bounded recovery attempt for an operation the caller
//!   registered.
//! - `snapshot`: build one contract-valid snapshot from the given fields.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

const SCHEMA: &str = "daemon-recovery.v1";
pub(crate) const SNAPSHOT_SCHEMA: &str = "hol-guard-recovery.v1";
pub(crate) const MAX_EVENT_BYTES: usize = 16 * 1024;
pub(crate) const CAPABILITIES: [&str; 4] = ["diagnostics", "inspect", "restart", "status"];
pub(crate) const PHASES: [&str; 11] = [
    "checking",
    "awaiting_approval",
    "waiting_for_owner",
    "stopping",
    "starting",
    "reconnecting",
    "verifying",
    "complete",
    "needs_action",
    "failed",
    "timed_out_waiting",
];
pub(crate) const OUTCOMES: [&str; 5] = [
    "pending",
    "reconnected",
    "started",
    "restarted",
    "not_recovered",
];
pub(crate) const CHECK_IDS: [&str; 7] = [
    "update_idle",
    "protection_posture",
    "process_identity",
    "runtime_identity",
    "authenticated_service",
    "dashboard_ready",
    "protection_health",
];
pub(crate) const REASON_CODES: [&str; 19] = [
    "healthy",
    "service_missing",
    "service_unresponsive",
    "session_invalid",
    "endpoint_conflict",
    "identity_unverified",
    "runtime_mismatch",
    "multiple_instances",
    "protection_off",
    "approval_required",
    "operation_busy",
    "update_busy",
    "permission_denied",
    "storage_unavailable",
    "startup_failed",
    "deadline_exceeded",
    "worker_exit_unconfirmed",
    "unsupported_protocol",
    "unknown",
];
/// Persisted phases after an attempted mutation. They are only hints of
/// unresolved work: a fresh identity and a proven exit are still required.
const UNRESOLVED_PHASES: [&str; 5] = [
    "stopping",
    "starting",
    "verifying",
    "failed",
    "timed_out_waiting",
];
/// Raised kinds `(OSError, RuntimeError, TimeoutError)` the coordinator
/// treats as an unconfirmed effect rather than a fault.
const PROCESS_ERRORS: [&str; 3] = ["os", "runtime", "timeout"];
/// Raised kinds a readiness probe after a start reports as a failed start.
const READY_ERRORS: [&str; 6] = ["import", "os", "runtime", "timeout", "type", "value"];

pub(crate) fn is_command(command: &str) -> bool {
    command == "daemon-recovery"
}

/// One recovery session over `reader` and `writer`.
pub(crate) fn run_session(mut reader: impl BufRead, writer: impl Write) -> Result<(), String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|error| format!("daemon-recovery: {error}"))?;
    let request: Request = serde_json::from_str(line.trim())
        .map_err(|error| format!("daemon-recovery: invalid request: {error}"))?;
    if request.schema != SCHEMA {
        return Err("daemon-recovery: unsupported schema".to_owned());
    }
    if request.mode == "store" {
        let store = request.store.unwrap_or(Value::Null);
        let reply = match crate::daemon_recovery_store::answer(&request.guard_home, &store) {
            Ok(value) => json!({"done": value}),
            Err(fail) => json!({"error": fail.code, "kind": fail.kind}),
        };
        let mut writer = writer;
        let mut line = serde_json::to_vec(&reply).map_err(|error| error.to_string())?;
        line.push(b'\n');
        return writer
            .write_all(&line)
            .and_then(|()| writer.flush())
            .map_err(|error| format!("daemon-recovery: {error}"));
    }
    let mut session = Session {
        reader,
        writer,
        guard_home: request.guard_home,
        active_budget_seconds: request.active_budget_seconds.max(0.0),
        lock_timeout_seconds: request.lock_timeout_seconds.max(0.0),
        op: request.operation.unwrap_or_default(),
        can_persist: request.can_persist,
        held: Vec::new(),
    };
    let outcome = match request.mode.as_str() {
        "inspect" => session.inspect_mode(),
        "run" => session.run(),
        "snapshot" => session.snapshot_mode(request.fields.unwrap_or_default()),
        _ => return Err("daemon-recovery: unsupported mode".to_owned()),
    };
    let reply = match outcome {
        Ok(snapshot) => json!({"done": snapshot, "state": session.state()}),
        Err(Fault::Raise(_)) => json!({"reraise": true, "state": session.state()}),
        Err(Fault::Io(error)) => return Err(error),
    };
    session.write_line(&reply).map_err(|fault| match fault {
        Fault::Io(error) | Fault::Raise(error) => error,
    })
}

#[derive(Deserialize)]
struct Request {
    schema: String,
    mode: String,
    guard_home: String,
    #[serde(default = "default_budget")]
    active_budget_seconds: f64,
    #[serde(default)]
    lock_timeout_seconds: f64,
    /// Whether the caller can persist snapshots; without it a pending
    /// receipt can never be expired.
    #[serde(default)]
    can_persist: bool,
    #[serde(default)]
    operation: Option<Operation>,
    #[serde(default)]
    fields: Option<Map<String, Value>>,
    /// Mode `store`: one request for `daemon_recovery_store::answer`.
    #[serde(default)]
    store: Option<Value>,
}

fn default_budget() -> f64 {
    60.0
}

#[derive(Clone, Default, Deserialize)]
struct Operation {
    operation_id: Option<String>,
    request_id: Option<String>,
    #[serde(default)]
    started_at: String,
    #[serde(default)]
    started_monotonic: f64,
    #[serde(default)]
    deadline_monotonic: f64,
    #[serde(default = "initial_sequence")]
    sequence: i64,
    #[serde(default)]
    unresolved_owner: bool,
    #[serde(default)]
    unresolved_identity: Option<Identity>,
}

fn initial_sequence() -> i64 {
    -1
}

/// Private identity evidence for one daemon generation. `handle` is the
/// caller's own reference, echoed back so it can hand its hooks the object
/// they produced.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct Identity {
    pid: i64,
    generation: String,
    runtime: String,
    guard_home: String,
    user: Option<String>,
    start_marker: Option<String>,
    #[serde(default)]
    handle: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct Service {
    service: String,
    reason_code: String,
    #[serde(default)]
    identity: Option<Identity>,
    #[serde(default)]
    process_running: bool,
    #[serde(default)]
    authenticated: bool,
    #[serde(default)]
    dashboard_ready: bool,
    #[serde(default = "unknown")]
    protection: String,
    #[serde(default)]
    checks: Vec<Value>,
}

fn unknown() -> String {
    "unknown".to_owned()
}

#[derive(Clone, Debug, Deserialize)]
struct Inspection {
    service: Service,
    posture: String,
    update_busy: bool,
}

#[derive(Deserialize)]
struct Authorization {
    allowed: bool,
    requires_human_action: bool,
    reason_code: String,
}

#[derive(Deserialize)]
struct StopResult {
    exit_confirmed: bool,
    reason_code: String,
}

#[derive(Deserialize)]
struct StartResult {
    started: bool,
    #[serde(default)]
    identity: Option<Identity>,
    reason_code: String,
}

#[derive(Deserialize)]
struct ReadyResult {
    ready: bool,
    #[serde(default)]
    identity: Option<Identity>,
    reason_code: String,
}

#[derive(Clone, Deserialize)]
struct ProtectionResult {
    state: String,
    reason_code: String,
}

enum Fault {
    /// The session itself broke; nothing more can be asked.
    Io(String),
    /// An effect raised; the kind names the error class.
    Raise(String),
}

impl Fault {
    fn is(&self, kinds: &[&str]) -> bool {
        matches!(self, Fault::Raise(kind) if kinds.contains(&kind.as_str()))
    }
}

type Step<T> = Result<T, Fault>;

type Check = (String, String, String);

/// One snapshot to emit. Unset fields come from the inspection, as the
/// coordinator's defaults did.
struct Event {
    phase: &'static str,
    worker_active: bool,
    retry_allowed: bool,
    reason_code: Option<String>,
    service: Option<String>,
    protection: Option<String>,
    outcome: &'static str,
    requires_human_action: bool,
    checks: Option<Vec<Check>>,
    persist: bool,
}

impl Event {
    /// A progress event (`_emit`).
    fn progress(phase: &'static str) -> Self {
        Self {
            phase,
            worker_active: true,
            retry_allowed: false,
            reason_code: None,
            service: None,
            protection: None,
            outcome: "pending",
            requires_human_action: false,
            checks: None,
            persist: true,
        }
    }

    /// A terminal event (`_finish_action`).
    fn finish(phase: &'static str, reason_code: &str) -> Self {
        Self {
            phase,
            worker_active: false,
            retry_allowed: true,
            reason_code: Some(reason_code.to_owned()),
            service: None,
            protection: None,
            outcome: "not_recovered",
            requires_human_action: false,
            checks: None,
            persist: true,
        }
    }

    fn worker(mut self, active: bool) -> Self {
        self.worker_active = active;
        self
    }

    fn retry(mut self, allowed: bool) -> Self {
        self.retry_allowed = allowed;
        self
    }

    fn human(mut self) -> Self {
        self.requires_human_action = true;
        self
    }

    fn human_if(mut self, required: bool) -> Self {
        self.requires_human_action = required;
        self
    }

    fn service(mut self, service: &str) -> Self {
        self.service = Some(service.to_owned());
        self
    }

    fn protection(mut self, protection: String) -> Self {
        self.protection = Some(protection);
        self
    }

    fn checks(mut self, checks: Vec<Check>) -> Self {
        self.checks = Some(checks);
        self
    }

    fn outcome(mut self, outcome: &'static str) -> Self {
        self.outcome = outcome;
        self
    }

    fn no_persist(mut self) -> Self {
        self.persist = false;
        self
    }
}

struct Session<R, W> {
    reader: R,
    writer: W,
    guard_home: String,
    active_budget_seconds: f64,
    lock_timeout_seconds: f64,
    op: Operation,
    can_persist: bool,
    /// Locks the caller holds for this session, innermost last.
    held: Vec<&'static str>,
}

impl<R: BufRead, W: Write> Session<R, W> {
    // ---- transport ------------------------------------------------------

    fn state(&self) -> Value {
        json!({
            "sequence": self.op.sequence,
            "started_monotonic": self.op.started_monotonic,
            "deadline_monotonic": self.op.deadline_monotonic,
            "unresolved_owner": self.op.unresolved_owner,
            "unresolved_identity": self.op.unresolved_identity,
        })
    }

    fn write_line(&mut self, value: &Value) -> Step<()> {
        let mut text =
            serde_json::to_string(value).map_err(|error| Fault::Io(error.to_string()))?;
        text.push('\n');
        self.writer
            .write_all(text.as_bytes())
            .and_then(|()| self.writer.flush())
            .map_err(|error| Fault::Io(format!("daemon-recovery: {error}")))
    }

    fn ask(&mut self, need: &str, args: Value) -> Step<Value> {
        let message = json!({"need": need, "args": args, "state": self.state()});
        self.write_line(&message)?;
        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .map_err(|error| Fault::Io(format!("daemon-recovery: {error}")))?;
        if read == 0 {
            return Err(Fault::Io(
                "daemon-recovery: caller closed the session".to_owned(),
            ));
        }
        let answer: Value = serde_json::from_str(line.trim())
            .map_err(|error| Fault::Io(format!("daemon-recovery: invalid answer: {error}")))?;
        if let Some(value) = answer.get("ok") {
            return Ok(value.clone());
        }
        if let Some(kind) = answer.get("raise").and_then(Value::as_str) {
            return Err(Fault::Raise(kind.to_owned()));
        }
        Err(Fault::Io("daemon-recovery: invalid answer".to_owned()))
    }

    fn ask_as<T: for<'de> Deserialize<'de>>(&mut self, need: &str, args: Value) -> Step<T> {
        let value = self.ask(need, args)?;
        serde_json::from_value(value)
            .map_err(|error| Fault::Io(format!("daemon-recovery: invalid {need} answer: {error}")))
    }

    // ---- effects --------------------------------------------------------

    fn clock(&mut self) -> Step<f64> {
        self.ask_as("clock", Value::Null)
    }

    fn wall(&mut self) -> Step<String> {
        self.ask_as("wall", Value::Null)
    }

    fn inspect(&mut self, timeout: Option<f64>) -> Step<Inspection> {
        self.ask_as("inspect", json!({"timeout": timeout}))
    }

    fn posture(&mut self) -> Step<String> {
        self.ask_as("posture", Value::Null)
    }

    fn update_busy(&mut self) -> Step<bool> {
        self.ask_as("update_busy", Value::Null)
    }

    fn authorize(&mut self) -> Step<Authorization> {
        self.ask_as("authorize", Value::Null)
    }

    fn user_marker(&mut self) -> Step<Option<String>> {
        self.ask_as("user_marker", Value::Null)
    }

    fn owner_marker(&mut self, pid: i64) -> Step<Option<String>> {
        self.ask_as("owner_marker", json!({"pid": pid}))
    }

    fn process_dead(&mut self, identity: &Identity) -> Step<bool> {
        self.ask_as("process_dead", json!({"identity": identity}))
    }

    fn lock(&mut self, name: &'static str, timeout: f64) -> Step<()> {
        self.ask("lock", json!({"name": name, "timeout": timeout}))?;
        self.held.push(name);
        Ok(())
    }

    fn release(&mut self, name: &'static str) -> Step<()> {
        if self.held.last() != Some(&name) {
            return Ok(());
        }
        self.held.pop();
        self.ask("release", json!({"name": name}))?;
        Ok(())
    }

    /// Release `name` after `body`, keeping the body's own fault first.
    fn locked<T>(&mut self, name: &'static str, body: Step<T>) -> Step<T> {
        let released = self.release(name);
        match (body, released) {
            (Err(fault), _) => Err(fault),
            (Ok(_), Err(fault)) => Err(fault),
            (Ok(value), Ok(())) => Ok(value),
        }
    }

    fn remaining(&mut self) -> Step<f64> {
        Ok((self.op.deadline_monotonic - self.clock()?).max(0.0))
    }

    fn elapsed_ms(&mut self) -> Step<i64> {
        Ok(((self.clock()? - self.op.started_monotonic).max(0.0) * 1000.0) as i64)
    }

    fn begin_budget(&mut self) -> Step<()> {
        self.op.started_monotonic = self.clock()?;
        self.op.deadline_monotonic = self.op.started_monotonic + self.active_budget_seconds;
        Ok(())
    }

    fn stop_process(&mut self, identity: &Identity, remaining: f64) -> Step<StopResult> {
        if remaining <= 0.0 {
            return Ok(StopResult {
                exit_confirmed: false,
                reason_code: "deadline_exceeded".to_owned(),
            });
        }
        let unconfirmed = StopResult {
            exit_confirmed: false,
            reason_code: "worker_exit_unconfirmed".to_owned(),
        };
        if identity.start_marker.as_deref().is_none_or(str::is_empty) {
            return Ok(unconfirmed);
        }
        let Some(user) = identity.user.as_deref() else {
            return Ok(unconfirmed);
        };
        if self.user_marker()?.as_deref() != Some(user) {
            return Ok(unconfirmed);
        }
        self.ask_as(
            "stop",
            json!({"identity": identity, "remaining": remaining}),
        )
    }

    fn start_process(&mut self, remaining: f64) -> Step<StartResult> {
        if remaining <= 0.0 {
            return Ok(StartResult {
                started: false,
                identity: None,
                reason_code: "deadline_exceeded".to_owned(),
            });
        }
        self.ask_as("start", json!({"remaining": remaining}))
    }

    fn verify_ready(&mut self, identity: Option<&Identity>, remaining: f64) -> Step<ReadyResult> {
        if remaining <= 0.0 {
            return Ok(ReadyResult {
                ready: false,
                identity: None,
                reason_code: "deadline_exceeded".to_owned(),
            });
        }
        self.ask_as(
            "verify_ready",
            json!({"identity": identity, "remaining": remaining}),
        )
    }

    fn protection_health(
        &mut self,
        identity: Option<&Identity>,
        remaining: f64,
    ) -> Step<ProtectionResult> {
        if remaining <= 0.0 {
            return Ok(ProtectionResult {
                state: "unknown".to_owned(),
                reason_code: "deadline_exceeded".to_owned(),
            });
        }
        self.ask_as(
            "protection_health",
            json!({"identity": identity, "remaining": remaining}),
        )
    }

    /// The durable snapshot left by an earlier attempt: `pending`, `none`
    /// or `unavailable`.
    fn pending_snapshot_state(&mut self) -> Step<&'static str> {
        let answer = match self.ask("load_snapshot", Value::Null) {
            Ok(answer) => answer,
            Err(fault @ Fault::Io(_)) => return Err(fault),
            Err(fault) if fault.is(&["os", "runtime", "value", "type"]) => {
                return Ok("unavailable")
            }
            Err(fault) => return Err(fault),
        };
        match answer.get("kind").and_then(Value::as_str) {
            Some("none") => Ok("none"),
            Some("snapshot") => {
                let snapshot = answer.get("snapshot").cloned().unwrap_or(Value::Null);
                let phase = snapshot.get("phase").and_then(Value::as_str);
                if snapshot.get("workerActive") == Some(&Value::Bool(true))
                    && snapshot.get("retryAllowed") == Some(&Value::Bool(false))
                    && phase.is_some_and(|phase| UNRESOLVED_PHASES.contains(&phase))
                {
                    Ok("pending")
                } else {
                    Ok("none")
                }
            }
            _ => Ok("unavailable"),
        }
    }

    fn identity_matches(
        &mut self,
        left: Option<&Identity>,
        right: Option<&Identity>,
    ) -> Step<bool> {
        let (Some(left), Some(right)) = (left, right) else {
            return Ok(false);
        };
        if left.guard_home != right.guard_home
            || right.guard_home != self.guard_home
            || left.pid != right.pid
            || left.generation != right.generation
            || left.runtime != right.runtime
        {
            return Ok(false);
        }
        if left.start_marker.is_none() || left.start_marker != right.start_marker {
            return Ok(false);
        }
        let (Some(left_user), Some(right_user)) = (left.user.as_deref(), right.user.as_deref())
        else {
            return Ok(false);
        };
        if left_user != right_user {
            return Ok(false);
        }
        if right_user.starts_with("sid:")
            && self.owner_marker(right.pid)?.as_deref() != Some(right_user)
        {
            return Ok(false);
        }
        Ok(self.user_marker()?.as_deref() == Some(left_user))
    }

    // ---- snapshots ------------------------------------------------------

    fn snapshot(&mut self, fields: SnapshotFields) -> Step<Value> {
        let now = self.wall()?;
        Ok(build_snapshot(fields, now))
    }

    fn emit(&mut self, inspection: &Inspection, event: Event) -> Step<Value> {
        self.op.sequence += 1;
        let elapsed = self.elapsed_ms()?;
        let fields = SnapshotFields {
            operation_id: self.op.operation_id.clone(),
            sequence: self.op.sequence,
            started_at: self.op.started_at.clone(),
            phase: event.phase.to_owned(),
            active_elapsed_ms: elapsed,
            worker_active: event.worker_active,
            retry_allowed: event.retry_allowed,
            outcome: event.outcome.to_owned(),
            reason_code: event
                .reason_code
                .unwrap_or_else(|| inspection_reason(inspection)),
            service: event
                .service
                .unwrap_or_else(|| inspection.service.service.clone()),
            protection: event
                .protection
                .unwrap_or_else(|| inspection_protection(inspection)),
            requires_human_action: event.requires_human_action,
            checks: event.checks.unwrap_or_else(|| checks_for(inspection)),
        };
        let snapshot = self.snapshot(fields)?;
        self.ask(
            "emit",
            json!({"snapshot": snapshot, "persist": event.persist}),
        )?;
        Ok(snapshot)
    }

    /// Adopt a durable receipt as this operation's latest event.
    fn adopt(&mut self, receipt: Value) -> Step<Value> {
        self.op.sequence = receipt.get("sequence").and_then(Value::as_i64).unwrap_or(0);
        self.ask("record", json!({"snapshot": receipt, "cached": true}))?;
        Ok(receipt)
    }

    fn expire_pending_snapshot(&mut self) -> Step<bool> {
        if !self.can_persist {
            return Ok(false);
        }
        let elapsed = self.elapsed_ms()?;
        let fields = SnapshotFields {
            operation_id: self.op.operation_id.clone(),
            sequence: (self.op.sequence + 1).max(0),
            started_at: self.op.started_at.clone(),
            phase: "needs_action".to_owned(),
            active_elapsed_ms: elapsed,
            worker_active: false,
            retry_allowed: false,
            outcome: "not_recovered".to_owned(),
            reason_code: "unknown".to_owned(),
            service: "unknown".to_owned(),
            protection: "unknown".to_owned(),
            requires_human_action: true,
            checks: Vec::new(),
        };
        let snapshot = self.snapshot(fields)?;
        let expired: bool = self.ask_as("expire", json!({"snapshot": snapshot}))?;
        if expired {
            self.op.sequence = snapshot
                .get("sequence")
                .and_then(Value::as_i64)
                .unwrap_or(0);
        }
        Ok(expired)
    }

    // ---- modes ----------------------------------------------------------

    fn inspect_mode(&mut self) -> Step<Value> {
        let inspection = self.inspect(None)?;
        let started_at = self.wall()?;
        let requires_human_action = inspection.posture == "off"
            || matches!(
                inspection.service.reason_code.as_str(),
                "identity_unverified"
                    | "runtime_mismatch"
                    | "endpoint_conflict"
                    | "multiple_instances"
            );
        let fields = SnapshotFields {
            operation_id: None,
            sequence: 0,
            started_at,
            phase: "checking".to_owned(),
            active_elapsed_ms: 0,
            worker_active: false,
            retry_allowed: !inspection.update_busy && inspection.posture == "on",
            outcome: "pending".to_owned(),
            reason_code: inspection_reason(&inspection),
            service: inspection.service.service.clone(),
            protection: inspection_protection(&inspection),
            requires_human_action,
            checks: checks_for(&inspection),
        };
        self.snapshot(fields)
    }

    fn snapshot_mode(&mut self, fields: Map<String, Value>) -> Step<Value> {
        let text = |key: &str| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned()
        };
        let flag = |key: &str| fields.get(key).and_then(Value::as_bool).unwrap_or(false);
        let number = |key: &str| fields.get(key).and_then(Value::as_i64).unwrap_or(0);
        let snapshot = SnapshotFields {
            operation_id: fields
                .get("operation_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            sequence: number("sequence"),
            started_at: text("started_at"),
            phase: text("phase"),
            active_elapsed_ms: number("active_elapsed_ms"),
            worker_active: flag("worker_active"),
            retry_allowed: flag("retry_allowed"),
            outcome: text("outcome"),
            reason_code: text("reason_code"),
            service: text("service"),
            protection: text("protection"),
            requires_human_action: flag("requires_human_action"),
            checks: coerce_checks(fields.get("checks").and_then(Value::as_array)),
        };
        self.snapshot(snapshot)
    }

    fn run(&mut self) -> Step<Value> {
        let initial = self.inspect(None)?;
        self.emit(&initial, Event::progress("checking").no_persist())?;
        if initial.posture != "on" {
            return self.finish_posture(&initial);
        }
        if initial.update_busy {
            return self.finish_update_busy(&initial);
        }
        let decision = self.authorize()?;
        if !decision.allowed {
            let phase = if decision.requires_human_action {
                "awaiting_approval"
            } else {
                "needs_action"
            };
            let event = Event::finish(phase, &decision.reason_code)
                .worker(false)
                .retry(false)
                .human();
            return self.emit(&initial, event);
        }
        // Approval and the preflight inspection happen before the active
        // budget; the deadline starts just before waiting on ownership.
        self.begin_budget()?;
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(&initial, false, None);
        }
        let timeout = self.remaining()?.min(self.lock_timeout_seconds);
        let body = match self.lock("recovery", timeout) {
            Ok(()) => {
                let body = self.run_locked(&initial);
                // Any lock this body still holds is released inside out.
                let body = self.locked("start", body);
                self.locked("recovery", body)
            }
            Err(fault) => Err(fault),
        };
        match body {
            Ok(snapshot) => Ok(snapshot),
            Err(Fault::Io(error)) => Err(Fault::Io(error)),
            Err(Fault::Raise(kind)) if kind == "lock_timeout" => {
                let event = Event::finish("waiting_for_owner", "operation_busy")
                    .worker(false)
                    .retry(false)
                    .no_persist();
                self.emit(&initial, event)
            }
            Err(Fault::Raise(kind)) if kind == "lock_unavailable" => {
                let event = Event::finish("failed", "unknown")
                    .worker(false)
                    .retry(false)
                    .human()
                    .no_persist();
                self.emit(&initial, event)
            }
            Err(Fault::Raise(_)) => {
                let event = Event::finish("failed", "unknown")
                    .worker(self.op.unresolved_owner)
                    .retry(false)
                    .human()
                    .no_persist();
                self.emit(&initial, event)
            }
        }
    }

    fn run_locked(&mut self, initial: &Inspection) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(initial, false, None);
        }
        let request_id = self.op.request_id.clone();
        let receipt = match self.ask("load_receipt", json!({"request_id": request_id})) {
            Ok(receipt) => receipt,
            Err(Fault::Raise(kind)) if kind == "receipt_unavailable" => {
                let event = Event::finish("failed", "unknown")
                    .worker(true)
                    .retry(false)
                    .human()
                    .no_persist();
                return self.emit(initial, event);
            }
            Err(fault) => return Err(fault),
        };
        let receipt_phase = receipt
            .get("phase")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if receipt_phase.as_deref() == Some("complete") {
            return self.adopt(receipt);
        }
        if receipt_phase
            .as_deref()
            .is_some_and(|phase| UNRESOLVED_PHASES.contains(&phase))
        {
            // A prior mutating request with this id is resumable only for
            // observation; an intentional retry must send a new request id.
            let remaining = self.remaining()?;
            let current = self.inspect(Some(remaining))?;
            if let Some(identity) = current.service.identity.as_ref() {
                match self.process_dead(identity) {
                    Ok(_) => {}
                    Err(fault) if fault.is(&PROCESS_ERRORS) => {}
                    Err(fault) => return Err(fault),
                }
            }
            return self.adopt(receipt);
        }
        if let Some(failure) = self.authorization_failure(initial)? {
            return Ok(failure);
        }
        let remaining = self.remaining()?;
        let mut current = self.inspect(Some(remaining))?;
        let mut pending = self.pending_snapshot_state()?;
        if pending == "unavailable" {
            let event = Event::finish("failed", "unknown")
                .worker(true)
                .retry(false)
                .human()
                .no_persist();
            return self.emit(&current, event);
        }
        let fresh_ready_identity =
            current.service.service == "ready" && current.service.identity.is_some();
        if pending == "pending" && !fresh_ready_identity {
            let identity = current.service.identity.clone();
            match identity {
                None if missing_inventory_proves_no_owner(&current) => {
                    if !self.expire_pending_snapshot()? {
                        self.op.unresolved_owner = true;
                        return self.emit(&current, unresolved_failure());
                    }
                    pending = "none";
                }
                None => return self.emit(&current, owner_busy()),
                Some(_) => {}
            }
            if pending == "pending" {
                if let Some(identity) = identity {
                    let reconciled = match self.process_dead(&identity) {
                        Ok(dead) => dead,
                        Err(fault) if fault.is(&PROCESS_ERRORS) => false,
                        Err(fault) => return Err(fault),
                    };
                    if !reconciled {
                        return self.emit(&current, owner_busy());
                    }
                    if self.remaining()? <= 0.0 {
                        return self.deadline_exceeded(&current, false, None);
                    }
                    let remaining = self.remaining()?;
                    current = self.inspect(Some(remaining))?;
                    if !missing_inventory_proves_no_owner(&current) {
                        return self.emit(&current, owner_busy());
                    }
                    if !self.expire_pending_snapshot()? {
                        self.op.unresolved_owner = true;
                        return self.emit(&current, unresolved_failure());
                    }
                }
            }
        }
        self.emit(&current, Event::progress("checking"))?;
        if current.posture != "on" {
            return self.finish_posture(&current);
        }
        if current.update_busy {
            return self.finish_update_busy(&current);
        }
        if current.service.service == "ready" {
            return self.reconnect(&current);
        }
        let reason = current.service.reason_code.clone();
        match reason.as_str() {
            "service_unresponsive" => self.replace(&current),
            "service_missing" => self.start_missing(&current),
            _ => self.emit(&current, Event::finish("needs_action", &reason).human()),
        }
    }

    fn finish_posture(&mut self, inspection: &Inspection) -> Step<Value> {
        let reason = if inspection.posture == "off" {
            "protection_off"
        } else {
            "unknown"
        };
        self.emit(inspection, Event::finish("needs_action", reason).human())
    }

    fn finish_update_busy(&mut self, inspection: &Inspection) -> Step<Value> {
        let event = Event::finish("waiting_for_owner", "update_busy")
            .worker(false)
            .retry(false);
        self.emit(inspection, event)
    }

    fn authorization_failure(&mut self, inspection: &Inspection) -> Step<Option<Value>> {
        let decision = self.authorize()?;
        if decision.allowed {
            return Ok(None);
        }
        let phase = if decision.requires_human_action {
            "awaiting_approval"
        } else {
            "needs_action"
        };
        let event = Event::finish(phase, &decision.reason_code)
            .worker(false)
            .retry(false)
            .human();
        self.emit(inspection, event).map(Some)
    }

    fn precondition_failure(&mut self, inspection: &Inspection) -> Step<Option<Value>> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, false, None).map(Some);
        }
        if inspection.posture != "on" {
            return self.finish_posture(inspection).map(Some);
        }
        if inspection.update_busy {
            return self.finish_update_busy(inspection).map(Some);
        }
        Ok(None)
    }

    /// The precondition and authorization checks every mutation repeats.
    fn mutation_gate(&mut self, inspection: &Inspection) -> Step<Option<Value>> {
        if let Some(failure) = self.precondition_failure(inspection)? {
            return Ok(Some(failure));
        }
        self.authorization_failure(inspection)
    }

    /// The service with fresh posture and update evidence.
    fn refreshed(&mut self, inspection: &Inspection) -> Step<Inspection> {
        let posture = self.posture()?;
        let update_busy = self.update_busy()?;
        Ok(Inspection {
            service: inspection.service.clone(),
            posture,
            update_busy,
        })
    }

    fn identity_unverified(&mut self, inspection: &Inspection) -> Step<Value> {
        self.emit(
            inspection,
            Event::finish("needs_action", "identity_unverified").human(),
        )
    }

    fn reconnect(&mut self, inspection: &Inspection) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        let event = Event::progress("reconnecting")
            .protection(protection_without_fresh_evidence(inspection))
            .checks(checks_without_fresh_protection(inspection, "unknown"));
        self.emit(inspection, event)?;
        let remaining = self.remaining()?;
        let ready = self.verify_ready(inspection.service.identity.as_ref(), remaining)?;
        if !ready.ready {
            if ready.reason_code == "deadline_exceeded" || self.remaining()? <= 0.0 {
                return self.deadline_exceeded(inspection, true, None);
            }
            let reason = ready.reason_code;
            let event = Event::finish("needs_action", &reason)
                .protection(protection_without_fresh_evidence(inspection))
                .checks(checks_without_fresh_protection(inspection, &reason))
                .human_if(matches!(
                    reason.as_str(),
                    "session_invalid" | "approval_required"
                ));
            return self.emit(inspection, event);
        }
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        let expected = inspection.service.identity.clone();
        if !self.identity_matches(expected.as_ref(), ready.identity.as_ref())? {
            let event = Event::finish("needs_action", "identity_unverified")
                .service("ready")
                .protection(protection_without_fresh_evidence(inspection))
                .worker(false)
                .retry(true)
                .human()
                .checks(checks_without_fresh_protection(
                    inspection,
                    "identity_unverified",
                ));
            return self.emit(inspection, event);
        }
        self.verify_protection(inspection, ready.identity.as_ref(), "reconnected")
    }

    fn replace(&mut self, inspection: &Inspection) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, false, None);
        }
        let remaining = self.remaining()?;
        self.lock("start", remaining)?;
        let body = self.replace_locked(inspection);
        self.locked("start", body)
    }

    fn replace_locked(&mut self, inspection: &Inspection) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, false, None);
        }
        let Some(target) = inspection.service.identity.clone() else {
            return self.identity_unverified(inspection);
        };
        let remaining = self.remaining()?;
        let rechecked = self.inspect(Some(remaining))?;
        if !self.identity_matches(Some(&target), rechecked.service.identity.as_ref())? {
            return self.identity_unverified(&rechecked);
        }
        if let Some(failure) = self.mutation_gate(&rechecked)? {
            return Ok(failure);
        }
        // A final read just before the stop guards against PID reuse or a
        // generation change while the progress event is emitted.
        let remaining = self.remaining()?;
        let before_stop = self.inspect(Some(remaining))?;
        if !self.identity_matches(Some(&target), before_stop.service.identity.as_ref())? {
            return self.identity_unverified(&before_stop);
        }
        if let Some(failure) = self.precondition_failure(&before_stop)? {
            return Ok(failure);
        }
        self.emit(&before_stop, Event::progress("stopping"))?;
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(&before_stop, false, None);
        }
        let last_before_stop = self.refreshed(&before_stop)?;
        if let Some(failure) = self.mutation_gate(&last_before_stop)? {
            return Ok(failure);
        }
        self.op.unresolved_owner = true;
        self.op.unresolved_identity = Some(target.clone());
        let remaining = self.remaining()?;
        let stop = match self.stop_process(&target, remaining) {
            Ok(stop) => stop,
            Err(fault) if fault.is(&PROCESS_ERRORS) => StopResult {
                exit_confirmed: false,
                reason_code: "worker_exit_unconfirmed".to_owned(),
            },
            Err(fault) => return Err(fault),
        };
        let stop_deadline_exceeded = stop.reason_code == "deadline_exceeded";
        if stop_deadline_exceeded || !stop.exit_confirmed {
            let exited = match self.process_dead(&target) {
                Ok(dead) => dead,
                Err(fault) if fault.is(&PROCESS_ERRORS) => false,
                Err(fault) => return Err(fault),
            };
            if !exited {
                return self.timeout(&before_stop);
            }
        }
        self.op.unresolved_owner = false;
        self.op.unresolved_identity = None;
        if stop_deadline_exceeded || self.remaining()? <= 0.0 {
            return self.deadline_exceeded(&before_stop, false, None);
        }
        let remaining = self.remaining()?;
        let after_stop = self.inspect(Some(remaining))?;
        if after_stop.service.identity.is_some()
            && !self.identity_matches(Some(&target), after_stop.service.identity.as_ref())?
        {
            return self.identity_unverified(&after_stop);
        }
        if after_stop.service.reason_code != "service_missing" {
            let reason = after_stop.service.reason_code.clone();
            return self.emit(&after_stop, Event::finish("needs_action", &reason).human());
        }
        self.start_after_stop(&after_stop, "restarted", None)
    }

    fn start_missing(&mut self, inspection: &Inspection) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, false, None);
        }
        let remaining = self.remaining()?;
        self.lock("start", remaining)?;
        let body = self.start_missing_locked(inspection);
        self.locked("start", body)
    }

    fn start_missing_locked(&mut self, inspection: &Inspection) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, false, None);
        }
        let remaining = self.remaining()?;
        let rechecked = self.inspect(Some(remaining))?;
        if rechecked.service.service == "ready" {
            return self.reconnect(&rechecked);
        }
        if rechecked.service.reason_code != "service_missing" {
            let reason = rechecked.service.reason_code.clone();
            return self.emit(&rechecked, Event::finish("needs_action", &reason).human());
        }
        if let Some(failure) = self.mutation_gate(&rechecked)? {
            return Ok(failure);
        }
        self.emit(&rechecked, Event::progress("starting"))?;
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(&rechecked, false, None);
        }
        let last_before_start = self.refreshed(&rechecked)?;
        if let Some(failure) = self.mutation_gate(&last_before_start)? {
            return Ok(failure);
        }
        let started = match self.launch(&last_before_start)? {
            Ok(started) => started,
            Err(failure) => return Ok(failure),
        };
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(&rechecked, started.started, None);
        }
        self.start_after_stop(&rechecked, "started", Some(started))
    }

    /// Start the service; the inner `Err` is the terminal snapshot of a
    /// launch that failed.
    fn launch(&mut self, last_before_start: &Inspection) -> Step<Result<StartResult, Value>> {
        self.op.unresolved_owner = true;
        self.op.unresolved_identity = None;
        let remaining = self.remaining()?;
        let started = match self.start_process(remaining) {
            Ok(started) => started,
            Err(fault) if fault.is(&PROCESS_ERRORS) => {
                let event = Event::finish("failed", "startup_failed")
                    .service("unknown")
                    .protection(protection_without_fresh_evidence(last_before_start))
                    .worker(true)
                    .retry(false)
                    .human()
                    .checks(checks_without_fresh_protection(
                        last_before_start,
                        "startup_failed",
                    ));
                return self.emit(last_before_start, event).map(Err);
            }
            Err(fault) => return Err(fault),
        };
        if !started.started {
            self.op.unresolved_owner = false;
            self.op.unresolved_identity = None;
            let reason = started.reason_code;
            let event = Event::finish("failed", &reason)
                .protection(protection_without_fresh_evidence(last_before_start))
                .checks(checks_without_fresh_protection(last_before_start, &reason))
                .human();
            return self.emit(last_before_start, event).map(Err);
        }
        Ok(Ok(started))
    }

    fn start_after_stop(
        &mut self,
        inspection: &Inspection,
        outcome: &'static str,
        started: Option<StartResult>,
    ) -> Step<Value> {
        let started = match started {
            Some(started) => {
                if self.remaining()? <= 0.0 {
                    return self.deadline_exceeded(inspection, started.started, None);
                }
                started
            }
            None => {
                if self.remaining()? <= 0.0 {
                    return self.deadline_exceeded(inspection, false, None);
                }
                let current = self.refreshed(inspection)?;
                if let Some(failure) = self.mutation_gate(&current)? {
                    return Ok(failure);
                }
                self.emit(inspection, Event::progress("starting"))?;
                if self.remaining()? <= 0.0 {
                    return self.deadline_exceeded(inspection, false, None);
                }
                let last_before_start = self.refreshed(inspection)?;
                if let Some(failure) = self.mutation_gate(&last_before_start)? {
                    return Ok(failure);
                }
                let started = match self.launch(&last_before_start)? {
                    Ok(started) => started,
                    Err(failure) => return Ok(failure),
                };
                if self.remaining()? <= 0.0 {
                    return self.deadline_exceeded(inspection, started.started, None);
                }
                started
            }
        };
        if started.started {
            self.op.unresolved_owner = true;
            self.op.unresolved_identity = started.identity.clone();
        }
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        // After a start, the persisted `starting` receipt stays until
        // readiness is proven: `reconnecting` cannot prove ownership.
        let event = Event::progress("reconnecting")
            .protection(protection_without_fresh_evidence(inspection))
            .checks(checks_without_fresh_protection(inspection, "unknown"))
            .no_persist();
        self.emit(inspection, event)?;
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        let identity = started.identity;
        let remaining = self.remaining()?;
        let ready = match self.verify_ready(identity.as_ref(), remaining) {
            Ok(ready) => ready,
            Err(fault) if fault.is(&READY_ERRORS) => ReadyResult {
                ready: false,
                identity: None,
                reason_code: "startup_failed".to_owned(),
            },
            Err(fault) => return Err(fault),
        };
        if !ready.ready {
            if ready.reason_code == "deadline_exceeded" || self.remaining()? <= 0.0 {
                return self.deadline_exceeded(inspection, true, None);
            }
            let reason = ready.reason_code;
            let event = Event::finish("failed", &reason)
                .service("unknown")
                .protection(protection_without_fresh_evidence(inspection))
                .worker(true)
                .retry(false)
                .human()
                .checks(checks_without_fresh_protection(inspection, &reason));
            return self.emit(inspection, event);
        }
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        if !self.identity_matches(identity.as_ref(), ready.identity.as_ref())? {
            // Ownership stays bound to the generation this request launched;
            // a different readiness identity is never adopted or stopped.
            self.op.unresolved_owner = true;
            self.op.unresolved_identity = identity;
            let event = Event::finish("needs_action", "identity_unverified")
                .service("unknown")
                .protection(protection_without_fresh_evidence(inspection))
                .worker(true)
                .retry(false)
                .human()
                .checks(checks_without_fresh_protection(
                    inspection,
                    "identity_unverified",
                ));
            return self.emit(inspection, event);
        }
        self.verify_protection(inspection, ready.identity.as_ref(), outcome)
    }

    fn verify_protection(
        &mut self,
        inspection: &Inspection,
        identity: Option<&Identity>,
        outcome: &'static str,
    ) -> Step<Value> {
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        let event = Event::progress("verifying")
            .protection(protection_without_fresh_evidence(inspection))
            .checks(checks_without_fresh_protection(inspection, "unknown"));
        self.emit(inspection, event)?;
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, None);
        }
        let remaining = self.remaining()?;
        let protection = match self.protection_health(identity, remaining) {
            Ok(protection) => protection,
            Err(fault) if fault.is(&PROCESS_ERRORS) => ProtectionResult {
                state: "unknown".to_owned(),
                reason_code: "unknown".to_owned(),
            },
            Err(fault) => return Err(fault),
        };
        if self.remaining()? <= 0.0 {
            return self.deadline_exceeded(inspection, true, Some(protection));
        }
        let mut checks = checks_for(inspection);
        set_check(&mut checks, "authenticated_service", "pass", "healthy");
        set_check(&mut checks, "dashboard_ready", "pass", "healthy");
        set_check(
            &mut checks,
            "protection_health",
            health_result(&protection.state),
            &protection.reason_code,
        );
        self.op.unresolved_owner = false;
        self.op.unresolved_identity = None;
        if protection.state != "verified" {
            let event = Event::finish("needs_action", &normal_reason(&protection.reason_code))
                .service("ready")
                .protection(protection.state.clone())
                .worker(false)
                .retry(true)
                .human()
                .checks(checks);
            return self.emit(inspection, event);
        }
        let event = Event::progress("complete")
            .outcome(outcome)
            .worker(false)
            .retry(true)
            .service("ready")
            .protection(protection.state.clone())
            .human_if(protection.state == "needs_attention")
            .checks(checks);
        let mut event = event;
        event.reason_code = Some("healthy".to_owned());
        self.emit(inspection, event)
    }

    fn timeout(&mut self, inspection: &Inspection) -> Step<Value> {
        self.op.unresolved_owner = true;
        let event = Event::finish("timed_out_waiting", "worker_exit_unconfirmed")
            .service("unknown")
            .protection("unknown".to_owned())
            .worker(true)
            .retry(false)
            .human();
        self.emit(inspection, event)
    }

    fn deadline_exceeded(
        &mut self,
        inspection: &Inspection,
        worker_active: bool,
        fresh_protection: Option<ProtectionResult>,
    ) -> Step<Value> {
        if worker_active {
            self.op.unresolved_owner = true;
            if self.op.unresolved_identity.is_none() {
                self.op.unresolved_identity = inspection.service.identity.clone();
            }
        }
        let mut checks = checks_for(inspection);
        let protection = match fresh_protection {
            None => {
                set_check(
                    &mut checks,
                    "protection_health",
                    "unknown",
                    "deadline_exceeded",
                );
                protection_without_fresh_evidence(inspection)
            }
            Some(fresh) => {
                let protection = normal_protection(&fresh.state);
                set_check(
                    &mut checks,
                    "protection_health",
                    health_result(&protection),
                    &fresh.reason_code,
                );
                protection
            }
        };
        let service = if worker_active {
            inspection.service.service.clone()
        } else {
            "unknown".to_owned()
        };
        let event = Event::finish("failed", "deadline_exceeded")
            .service(&service)
            .protection(protection)
            .worker(worker_active)
            .retry(false)
            .human()
            .checks(checks);
        self.emit(inspection, event)
    }
}

fn owner_busy() -> Event {
    Event::finish("waiting_for_owner", "operation_busy")
        .worker(true)
        .retry(false)
        .no_persist()
}

fn unresolved_failure() -> Event {
    Event::finish("failed", "unknown")
        .worker(true)
        .retry(false)
        .human()
        .no_persist()
}

fn missing_inventory_proves_no_owner(inspection: &Inspection) -> bool {
    let service = &inspection.service;
    service.service == "unavailable"
        && service.reason_code == "service_missing"
        && service.identity.is_none()
        && !service.process_running
}

fn health_result(protection: &str) -> &'static str {
    match protection {
        "verified" => "pass",
        "needs_attention" => "fail",
        _ => "unknown",
    }
}

fn normal_from(value: &str, allowed: &[&str], fallback: &str) -> String {
    if allowed.contains(&value) {
        value.to_owned()
    } else {
        fallback.to_owned()
    }
}

fn normal_reason(value: &str) -> String {
    normal_from(value, &REASON_CODES, "unknown")
}

fn normal_service(value: &str) -> String {
    normal_from(value, &["unknown", "unavailable", "ready"], "unknown")
}

fn normal_protection(value: &str) -> String {
    normal_from(
        value,
        &["unknown", "verified", "needs_attention", "off"],
        "unknown",
    )
}

fn normal_check_result(value: &str) -> String {
    normal_from(value, &["pass", "fail", "unknown"], "unknown")
}

fn inspection_reason(inspection: &Inspection) -> String {
    if inspection.posture == "off" {
        return "protection_off".to_owned();
    }
    if inspection.update_busy {
        return "update_busy".to_owned();
    }
    normal_reason(&inspection.service.reason_code)
}

fn inspection_protection(inspection: &Inspection) -> String {
    if inspection.posture == "off" {
        return "off".to_owned();
    }
    normal_protection(&inspection.service.protection)
}

fn protection_without_fresh_evidence(inspection: &Inspection) -> String {
    let observed = inspection_protection(inspection);
    if observed == "off" || observed == "needs_attention" {
        observed
    } else {
        "unknown".to_owned()
    }
}

fn coerce_checks(value: Option<&Vec<Value>>) -> Vec<Check> {
    let mut checks: Vec<Check> = Vec::new();
    for item in value.into_iter().flatten() {
        let Some(item) = item.as_object() else {
            continue;
        };
        let Some(id) = item.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !CHECK_IDS.contains(&id) || checks.iter().any(|check| check.0 == id) {
            continue;
        }
        let text = |key: &str| item.get(key).and_then(Value::as_str).unwrap_or("");
        checks.push((
            id.to_owned(),
            normal_check_result(text("result")),
            normal_reason(text("reasonCode")),
        ));
    }
    checks
}

fn set_check(checks: &mut Vec<Check>, id: &str, result: &str, reason_code: &str) {
    let entry = (
        id.to_owned(),
        normal_check_result(result),
        normal_reason(reason_code),
    );
    match checks.iter_mut().find(|check| check.0 == id) {
        Some(check) => *check = entry,
        None => checks.push(entry),
    }
}

fn checks_for(inspection: &Inspection) -> Vec<Check> {
    let service = &inspection.service;
    let mut checks = coerce_checks(Some(&service.checks));
    let (update_result, update_reason) = if inspection.update_busy {
        ("fail", "update_busy")
    } else {
        ("pass", "healthy")
    };
    set_check(&mut checks, "update_idle", update_result, update_reason);
    let posture_result = match inspection.posture.as_str() {
        "off" => "fail",
        "on" => "pass",
        _ => "unknown",
    };
    let posture_reason = if posture_result == "fail" {
        "protection_off"
    } else {
        "healthy"
    };
    set_check(
        &mut checks,
        "protection_posture",
        posture_result,
        posture_reason,
    );
    let identity_result = if service.identity.is_some() {
        "pass"
    } else {
        "unknown"
    };
    set_check(
        &mut checks,
        "process_identity",
        identity_result,
        &service.reason_code,
    );
    set_check(
        &mut checks,
        "runtime_identity",
        identity_result,
        &service.reason_code,
    );
    let passed = |ok: bool| if ok { "pass" } else { "unknown" };
    set_check(
        &mut checks,
        "authenticated_service",
        passed(service.authenticated),
        &service.reason_code,
    );
    set_check(
        &mut checks,
        "dashboard_ready",
        passed(service.dashboard_ready),
        &service.reason_code,
    );
    let protection = inspection_protection(inspection);
    set_check(
        &mut checks,
        "protection_health",
        health_result(&protection),
        &service.reason_code,
    );
    checks
}

fn checks_without_fresh_protection(inspection: &Inspection, reason_code: &str) -> Vec<Check> {
    let mut checks = checks_for(inspection);
    set_check(&mut checks, "protection_health", "unknown", reason_code);
    checks
}

struct SnapshotFields {
    operation_id: Option<String>,
    sequence: i64,
    started_at: String,
    phase: String,
    active_elapsed_ms: i64,
    worker_active: bool,
    retry_allowed: bool,
    outcome: String,
    reason_code: String,
    service: String,
    protection: String,
    requires_human_action: bool,
    checks: Vec<Check>,
}

fn checks_json(checks: &[Check]) -> Value {
    Value::Array(
        checks
            .iter()
            .map(|(id, result, reason)| json!({"id": id, "result": result, "reasonCode": reason}))
            .collect(),
    )
}

/// One public `hol-guard-recovery.v1` snapshot. A snapshot that would break
/// the contract becomes the conservative unknown one instead.
fn build_snapshot(fields: SnapshotFields, now: String) -> Value {
    let mut payload = json!({
        "schema": SNAPSHOT_SCHEMA,
        "capabilities": CAPABILITIES,
        "operationId": fields.operation_id,
        "sequence": fields.sequence.max(0),
        "startedAt": fields.started_at,
        "updatedAt": now,
        "phase": fields.phase,
        "activeElapsedMs": fields.active_elapsed_ms.max(0),
        "workerActive": fields.worker_active,
        "retryAllowed": fields.retry_allowed,
        "outcome": fields.outcome,
        "reasonCode": normal_reason(&fields.reason_code),
        "service": normal_service(&fields.service),
        "protection": normal_protection(&fields.protection),
        "requiresHumanAction": fields.requires_human_action,
        "checks": checks_json(&fields.checks),
    });
    if snapshot_valid(&payload) {
        return payload;
    }
    if let Some(object) = payload.as_object_mut() {
        object.insert("phase".to_owned(), json!("needs_action"));
        object.insert("outcome".to_owned(), json!("not_recovered"));
        object.insert("service".to_owned(), json!("unknown"));
        object.insert("protection".to_owned(), json!("unknown"));
        object.insert("reasonCode".to_owned(), json!("unknown"));
        object.insert("workerActive".to_owned(), json!(false));
        object.insert("retryAllowed".to_owned(), json!(false));
        object.insert("requiresHumanAction".to_owned(), json!(true));
        object.insert("checks".to_owned(), json!([]));
    }
    payload
}

/// The contract's phase, outcome and terminal invariants, and its size cap.
fn snapshot_valid(payload: &Value) -> bool {
    let text = |key: &str| payload.get(key).and_then(Value::as_str).unwrap_or("");
    let flag = |key: &str| payload.get(key).and_then(Value::as_bool).unwrap_or(false);
    let phase = text("phase");
    if !PHASES.contains(&phase) || !OUTCOMES.contains(&text("outcome")) {
        return false;
    }
    if phase == "complete"
        && (flag("workerActive")
            || !flag("retryAllowed")
            || text("service") != "ready"
            || matches!(text("outcome"), "pending" | "not_recovered"))
    {
        return false;
    }
    if phase == "timed_out_waiting" && (!flag("workerActive") || flag("retryAllowed")) {
        return false;
    }
    let checks = payload.get("checks").and_then(Value::as_array);
    if text("protection") == "verified"
        && !checks.into_iter().flatten().any(|check| {
            check.get("id").and_then(Value::as_str) == Some("protection_health")
                && check.get("result").and_then(Value::as_str) == Some("pass")
        })
    {
        return false;
    }
    serde_json::to_vec(payload).is_ok_and(|encoded| encoded.len() <= MAX_EVENT_BYTES)
}

#[cfg(test)]
#[path = "daemon_recovery_tests.rs"]
mod tests;
