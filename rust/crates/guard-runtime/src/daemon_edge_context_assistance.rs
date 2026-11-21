//! The built-in CIGAR engine's `/v1/context-assistance` routes: status,
//! installations, recheck, activate, stop, workspace access, the project
//! picker, versions and setup jobs.
//!
//! Each route is one `context_assistance` request to the resident, which owns
//! the engine. The edge frames the request, binds the reply to it (schema,
//! request id and canonical digest), checks the reply's shape and maps the
//! resident's refusal codes to HTTP statuses. Expanding workspace access and
//! changing the engine version pass the approval gate first. Codex lean mode,
//! short replies and the usage meter edit Codex config or read Guard's usage
//! records, so the daemon keeps answering those.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::super::ReadConfig;
use super::gate::{self, Gate};

const REQUEST_SCHEMA: &str = "guard-context-assistance-request.v1";
const RESULT_SCHEMA: &str = "guard-context-assistance-result.v1";
const STATUS_SCHEMA: &str = "guard-context-assistance-status.v2";
const WORKSPACE_SCHEMA: &str = "guard-cigar-workspace-result.v1";
const VERSIONS_SCHEMA: &str = "guard-cigar-versions-result.v1";
const CODE_PREFIX: &str = "native_context_assistance_";
const UNAVAILABLE: &str = "native_context_assistance_unavailable";
const INVALID: &str = "native_context_assistance_payload_invalid";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Engine control answers from state the resident already holds.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);
/// Workspace, folder and version requests may read the disk or start a job.
const SLOW_TIMEOUT: Duration = Duration::from_secs(8);
/// At most this many slow requests wait on the resident at once.
const SLOW_SLOTS: usize = 2;
/// Version actions that only read or stop a job; every other one changes
/// what runs and passes the approval gate.
const NO_EXPANSION: [&str; 3] = ["jobs", "job", "cancel"];

static REQUEST_IDS: AtomicU64 = AtomicU64::new(1);
static SLOW_BUSY: Mutex<usize> = Mutex::new(0);
static SLOW_FREED: Condvar = Condvar::new();

/// A route's reply: status, body and whether it is sent `no-store`.
pub(in crate::daemon_edge) type Reply = (u16, Value, bool);

/// The engine `GET` paths this module answers.
pub(in crate::daemon_edge) fn reads(path: &str) -> bool {
    matches!(
        path,
        "/v1/context-assistance"
            | "/v1/context-assistance/installations"
            | "/v1/context-assistance/jobs"
    )
}

/// The engine `POST` paths this module answers.
pub(in crate::daemon_edge) fn writes(path: &str) -> bool {
    write_kind(path).is_some()
}

fn write_kind(path: &str) -> Option<&'static str> {
    Some(match path {
        "/v1/context-assistance/versions" => "versions",
        "/v1/context-assistance/recheck" => "recheck",
        "/v1/context-assistance/activate" => "activate",
        "/v1/context-assistance/stop" => "stop",
        "/v1/context-assistance/workspace" => "workspace",
        "/v1/context-assistance/workspace-access" => "workspace_access",
        "/v1/context-assistance/workspace-grant" => "workspace_grant",
        "/v1/context-assistance/folders" => "folders",
        _ => return None,
    })
}

/// `GET path`.
pub(in crate::daemon_edge) fn get(path: &str, config: &ReadConfig) -> Option<Reply> {
    get_with(path, config, |query, slow| ask(config, &query, slow))
}

/// `POST path` with its JSON body.
pub(in crate::daemon_edge) fn post(
    path: &str,
    payload: &Map<String, Value>,
    config: &ReadConfig,
) -> Option<Reply> {
    post_with(path, payload, config, |query, slow| {
        ask(config, &query, slow)
    })
}

fn get_with(
    path: &str,
    config: &ReadConfig,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Option<Reply> {
    Some(match path {
        "/v1/context-assistance" => control("status", Map::new(), resident),
        "/v1/context-assistance/installations" => control("installations", Map::new(), resident),
        "/v1/context-assistance/jobs" => {
            let body = json!({"action": "jobs"});
            versions(Some(&body), &Map::new(), config, resident)
        }
        _ => return None,
    })
}

fn post_with(
    path: &str,
    payload: &Map<String, Value>,
    config: &ReadConfig,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Option<Reply> {
    Some(match write_kind(path)? {
        "versions" => versions(payload.get("input"), payload, config, resident),
        "folders" => folders(payload.clone(), resident),
        kind @ ("workspace" | "workspace_access" | "workspace_grant") => {
            let Some(Value::Object(input)) = payload.get("input") else {
                return Some(invalid_input());
            };
            if kind == "workspace_grant" {
                // Proof credentials stay out of the engine request.
                if let Some(refusal) = settings_gate(payload, config) {
                    return Some(refusal);
                }
            }
            match workspace(kind, input.clone(), resident) {
                Ok(data) => ok(Value::Object(data)),
                Err(code) => refusal(&code),
            }
        }
        kind => control(kind, payload.clone(), resident),
    })
}

/// `require_high_risk(purpose="settings_write")`, then `require_settings_write`
/// with its grant. `None` lets the request through; anything else is the
/// refusal to send. A gate the edge cannot ask fails closed.
fn settings_gate(payload: &Map<String, Value>, config: &ReadConfig) -> Option<Reply> {
    let grant = match gate::require_high_risk("settings_write", payload, config) {
        Some(Gate::Passed(grant)) => grant,
        Some(Gate::Refused(status, body)) => return Some((status, Value::Object(body), false)),
        None => return Some(gate_refusal(gate::unavailable())),
    };
    match gate::require_settings_write(grant, config).unwrap_or_else(gate::unavailable) {
        Gate::Passed(_) => None,
        refused => Some(gate_refusal(refused)),
    }
}

fn gate_refusal(gate: Gate) -> Reply {
    match gate {
        Gate::Refused(status, body) => (status, Value::Object(body), false),
        Gate::Passed(_) => refusal(UNAVAILABLE),
    }
}

/// Status, installations, recheck, activate and stop: the engine state.
fn control(
    kind: &str,
    input: Map<String, Value>,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Reply {
    let answer = resident(query(kind, input), false).and_then(|payload| {
        exact(&payload, &[("kind", Kind::Str), ("state", Kind::Object)])?;
        valid_state(&payload)?;
        Ok(payload)
    });
    match answer {
        Ok(mut payload) => ok(payload.remove("state").unwrap_or(Value::Null)),
        Err(code) => refusal(&code),
    }
}

/// The workspace result: `{schema, data_role, result}`.
fn workspace(
    kind: &str,
    input: Map<String, Value>,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Result<Map<String, Value>, String> {
    let mut payload = resident(query(kind, input), true)?;
    exact(
        &payload,
        &[
            ("kind", Kind::Str),
            ("state", Kind::Object),
            ("data", Kind::Object),
        ],
    )?;
    valid_state(&payload)?;
    let Some(Value::Object(data)) = payload.remove("data") else {
        return Err(INVALID.to_owned());
    };
    exact(
        &data,
        &[
            ("schema", Kind::Str),
            ("data_role", Kind::Bool),
            ("result", Kind::Object),
        ],
    )?;
    if data.get("schema").and_then(Value::as_str) != Some(WORKSPACE_SCHEMA)
        || data.get("data_role") != Some(&Value::Bool(true))
    {
        return Err(INVALID.to_owned());
    }
    Ok(data)
}

/// The project picker: folder names only; the grant re-checks every path.
fn folders(
    input: Map<String, Value>,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Reply {
    match workspace("folders", input, resident) {
        Ok(mut data) => ok(data.remove("result").unwrap_or(Value::Null)),
        Err(code) => {
            let short = code.strip_prefix(CODE_PREFIX).unwrap_or(&code);
            match folder_status(short) {
                Some(status) => (
                    status,
                    json!({"error": "folder_unavailable", "code": short}),
                    true,
                ),
                None => refusal(&code),
            }
        }
    }
}

fn folder_status(code: &str) -> Option<u16> {
    Some(match code {
        "folder_input_invalid" | "folder_not_absolute" | "folder_not_directory" => 400,
        "folder_not_found" => 404,
        "folder_denied" | "folder_unreadable" => 403,
        _ => return None,
    })
}

/// Engine versions and setup jobs. `body` is the request's `input`.
fn versions(
    body: Option<&Value>,
    payload: &Map<String, Value>,
    config: &ReadConfig,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Reply {
    let Some(Value::Object(body)) = body else {
        return invalid_input();
    };
    let Some(action) = body.get("action").and_then(Value::as_str) else {
        return invalid_input();
    };
    if !NO_EXPANSION.contains(&action) {
        if let Some(refusal) = settings_gate(payload, config) {
            return refusal;
        }
    }
    let answer = resident(query("versions", body.clone()), true).and_then(|mut payload| {
        exact(
            &payload,
            &[
                ("kind", Kind::Str),
                ("state", Kind::Object),
                ("data", Kind::Object),
            ],
        )?;
        valid_state(&payload)?;
        let Some(Value::Object(mut data)) = payload.remove("data") else {
            return Err(INVALID.to_owned());
        };
        exact(&data, &[("schema", Kind::Str), ("result", Kind::Object)])?;
        if data.get("schema").and_then(Value::as_str) != Some(VERSIONS_SCHEMA) {
            return Err(INVALID.to_owned());
        }
        data.insert(
            "state".to_owned(),
            payload.remove("state").unwrap_or(Value::Null),
        );
        Ok(data)
    });
    match answer {
        Ok(data) => ok(Value::Object(data)),
        Err(code) => (
            versions_status(&code),
            json!({"error": "context_assistance_unavailable", "code": code}),
            true,
        ),
    }
}

fn versions_status(code: &str) -> u16 {
    const CONFLICTS: [&str; 7] = [
        "disabled",
        "switch_busy",
        "context_stale",
        "selection_conflict",
        "recovery_required",
        "acknowledgement_required",
        "config_write_busy",
    ];
    if code.ends_with("request_invalid") || code.ends_with("idempotency_conflict") {
        400
    } else if CONFLICTS.iter().any(|suffix| code.ends_with(suffix)) {
        409
    } else {
        503
    }
}

/// The HTTP status for a refused control or workspace request.
fn refusal_status(code: &str) -> u16 {
    match code.strip_prefix(CODE_PREFIX).unwrap_or_default() {
        "control_input_invalid"
        | "workspace_input_invalid"
        | "request_invalid"
        | "context_request_invalid" => 400,
        "context_scope_denied" => 403,
        "context_stale" | "context_conflict" | "disabled" | "busy" | "context_busy" => 409,
        "context_resource_limit" => 429,
        _ => 503,
    }
}

fn refusal(code: &str) -> Reply {
    (
        refusal_status(code),
        json!({"error": "context_assistance_unavailable", "code": code}),
        true,
    )
}

fn invalid_input() -> Reply {
    (400, json!({"error": "invalid_context_input"}), false)
}

fn ok(body: Value) -> Reply {
    (200, body, true)
}

fn query(kind: &str, input: Map<String, Value>) -> Value {
    json!({"kind": kind, "input": input})
}

/// The kinds a reply field may hold.
#[derive(Clone, Copy)]
enum Kind {
    Str,
    Bool,
    Object,
    StrOrNull,
    ObjectOrNull,
    ListOrNull,
}

impl Kind {
    fn holds(self, value: &Value) -> bool {
        match self {
            Self::Str => value.is_string(),
            Self::Bool => value.is_boolean(),
            Self::Object => value.is_object(),
            Self::StrOrNull => value.is_string() || value.is_null(),
            Self::ObjectOrNull => value.is_object() || value.is_null(),
            Self::ListOrNull => value.is_array() || value.is_null(),
        }
    }
}

/// `value` has exactly `fields`, each of its kind.
fn exact(value: &Map<String, Value>, fields: &[(&str, Kind)]) -> Result<(), String> {
    let shaped = value.len() == fields.len()
        && fields
            .iter()
            .all(|(name, kind)| value.get(*name).is_some_and(|item| kind.holds(item)));
    if shaped {
        Ok(())
    } else {
        Err(INVALID.to_owned())
    }
}

const STATE_FIELDS: [(&str, Kind); 16] = [
    ("schema", Kind::Str),
    ("availability", Kind::Str),
    ("requested_enabled", Kind::Bool),
    ("effective_enabled", Kind::Bool),
    ("preferences", Kind::Object),
    ("effective_preferences", Kind::Object),
    ("restriction", Kind::StrOrNull),
    ("verification_permitted", Kind::Bool),
    ("generation", Kind::Str),
    ("diagnostic", Kind::StrOrNull),
    ("runtime", Kind::ObjectOrNull),
    ("last_check", Kind::ObjectOrNull),
    ("qualification", Kind::StrOrNull),
    ("capabilities", Kind::Object),
    ("installation_options", Kind::ListOrNull),
    ("job", Kind::ObjectOrNull),
];
/// State fields newer engines add.
const OPTIONAL_STATE_FIELDS: [(&str, Kind); 3] = [
    ("execution_ready", Kind::Bool),
    ("execution_observations", Kind::ListOrNull),
    ("upgrade", Kind::ObjectOrNull),
];

/// The engine status every reply carries in `state`.
fn valid_state(payload: &Map<String, Value>) -> Result<(), String> {
    let invalid = || INVALID.to_owned();
    let state = payload
        .get("state")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let mut fields = STATE_FIELDS.to_vec();
    fields.extend(
        OPTIONAL_STATE_FIELDS
            .iter()
            .filter(|(name, _)| state.contains_key(*name)),
    );
    exact(state, &fields)?;
    if state.get("schema").and_then(Value::as_str) != Some(STATUS_SCHEMA) {
        return Err(invalid());
    }
    let capabilities = state
        .get("capabilities")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let mut wanted = vec![
        ("shared_agents", Kind::Bool),
        ("private_persistence", Kind::Bool),
    ];
    if capabilities.contains_key("execution_context") {
        wanted.push(("execution_context", Kind::Bool));
    }
    exact(capabilities, &wanted)?;
    for runtime in ["runtime", "last_check"] {
        let Some(runtime) = state.get(runtime).and_then(Value::as_object) else {
            continue;
        };
        for flag in ["persistence_compile_verified", "execution_handoff_verified"] {
            if runtime.get(flag).is_some_and(|value| !value.is_boolean()) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

/// One resident request: the `ok` payload bound to it, or the refusal code.
fn ask(config: &ReadConfig, query: &Value, slow: bool) -> Result<Map<String, Value>, String> {
    let timeout = if slow { SLOW_TIMEOUT } else { CONTROL_TIMEOUT };
    let deadline = Instant::now() + timeout;
    let _slot = if slow {
        Some(SlowSlot::acquire(deadline).ok_or_else(|| UNAVAILABLE.to_owned())?)
    } else {
        None
    };
    let mut query = query.clone();
    query["guard_home"] = Value::from(config.guard_home.as_str());
    let request = json!({
        "schema": REQUEST_SCHEMA,
        "request_id": next_request_id(),
        "query": query,
    });
    let digest =
        crate::package_authority_op::request_digest_with_limit(&request, MAX_REQUEST_BYTES)
            .map_err(|_| format!("{CODE_PREFIX}request_invalid"))?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(UNAVAILABLE.to_owned());
    }
    let encoded = serde_json::to_vec(&json!({
        "operation": "context_assistance",
        "deadline_budget_ms": u64::try_from(remaining.as_millis()).unwrap_or(1).max(1),
        "request": request,
    }))
    .map_err(|_| format!("{CODE_PREFIX}request_invalid"))?;
    if encoded.len() > MAX_REQUEST_BYTES {
        return Err(UNAVAILABLE.to_owned());
    }
    let state_dir = std::fs::canonicalize(Path::new(&config.guard_home))
        .map_err(|_| format!("{CODE_PREFIX}home_unbound"))?
        .join("native-runtime");
    let output = crate::managed_resident::client_request(&state_dir, &encoded, remaining)
        .map_err(|_| UNAVAILABLE.to_owned())?;
    let envelope: Value = serde_json::from_slice(&output).map_err(|_| UNAVAILABLE.to_owned())?;
    bound(envelope, &request, &digest)
}

/// The `ok` payload of a reply bound to `request`, or the refusal code. A
/// reply for another request, or with a code outside the engine's, is the
/// engine being unavailable.
fn bound(envelope: Value, request: &Value, digest: &str) -> Result<Map<String, Value>, String> {
    let unavailable = || UNAVAILABLE.to_owned();
    let Value::Object(mut envelope) = envelope else {
        return Err(unavailable());
    };
    if envelope.get("schema").and_then(Value::as_str) != Some(RESULT_SCHEMA)
        || envelope.get("request_id") != request.get("request_id")
        || envelope.get("request_sha256").and_then(Value::as_str) != Some(digest)
    {
        return Err(unavailable());
    }
    let status = envelope.get("status").and_then(Value::as_str);
    let code = envelope.get("code").and_then(Value::as_str);
    if status == Some("error") {
        return Err(code
            .filter(|code| engine_code(code))
            .map_or_else(unavailable, str::to_owned));
    }
    let answered = status == Some("ok") && code == Some("ok");
    let kind = request.pointer("/query/kind");
    match envelope.remove("payload") {
        Some(Value::Object(payload)) if answered && payload.get("kind") == kind => Ok(payload),
        _ => Err(unavailable()),
    }
}

/// `^native_context_assistance_[a-z_]{1,64}$`.
fn engine_code(code: &str) -> bool {
    code.strip_prefix(CODE_PREFIX).is_some_and(|rest| {
        (1..=64).contains(&rest.len())
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    })
}

fn next_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        "context-assistance-edge-{}-{nanos:x}-{}",
        std::process::id(),
        REQUEST_IDS.fetch_add(1, Ordering::Relaxed)
    )
}

/// One of the [`SLOW_SLOTS`] places for a slow request, held until dropped.
struct SlowSlot;

impl SlowSlot {
    fn acquire(deadline: Instant) -> Option<Self> {
        let mut busy = SLOW_BUSY.lock().ok()?;
        while *busy >= SLOW_SLOTS {
            let wait = deadline.checked_duration_since(Instant::now())?;
            let (next, timeout) = SLOW_FREED.wait_timeout(busy, wait).ok()?;
            busy = next;
            if timeout.timed_out() && *busy >= SLOW_SLOTS {
                return None;
            }
        }
        *busy += 1;
        Some(Self)
    }
}

impl Drop for SlowSlot {
    fn drop(&mut self) {
        if let Ok(mut busy) = SLOW_BUSY.lock() {
            *busy = busy.saturating_sub(1);
        }
        SLOW_FREED.notify_one();
    }
}

#[cfg(test)]
#[path = "daemon_edge_context_assistance_tests.rs"]
mod tests;
