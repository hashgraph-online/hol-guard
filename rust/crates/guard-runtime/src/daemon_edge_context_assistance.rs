//! The built-in CIGAR engine's `/v1/context-assistance` routes: status,
//! installations, recheck, activate, stop, workspace access, the project
//! picker, versions, setup jobs and usage.
//!
//! Each route is one `context_assistance` request to the resident, which owns
//! the engine. The edge frames the request, binds the reply to it (schema,
//! request id and canonical digest), checks the reply's shape and maps the
//! resident's refusal codes to HTTP statuses. Expanding workspace access and
//! changing the engine version pass the approval gate first. The usage route
//! adds the meter's totals, counted here, to the resident's savings estimate.

use serde_json::{json, Map, Value};

use super::super::ReadConfig;
use super::gate::{self, Gate};

#[path = "daemon_edge_codex_config.rs"]
pub(super) mod codex_config;
#[path = "daemon_edge_context_assistance_resident.rs"]
mod resident;

use resident::ask;
#[cfg(test)]
use resident::{bound, SlowSlot, REQUEST_SCHEMA, RESULT_SCHEMA};

const STATUS_SCHEMA: &str = "guard-context-assistance-status.v2";
const WORKSPACE_SCHEMA: &str = "guard-cigar-workspace-result.v1";
const VERSIONS_SCHEMA: &str = "guard-cigar-versions-result.v1";
const CODE_PREFIX: &str = "native_context_assistance_";
const UNAVAILABLE: &str = "native_context_assistance_unavailable";
const INVALID: &str = "native_context_assistance_payload_invalid";
/// Version actions that only read or stop a job; every other one changes
/// what runs and passes the approval gate.
const NO_EXPANSION: [&str; 3] = ["jobs", "job", "cancel"];

/// A route's reply: status, body and whether it is sent `no-store`.
pub(in crate::daemon_edge) type Reply = (u16, Value, bool);

/// The engine `GET` paths this module answers.
pub(in crate::daemon_edge) fn reads(path: &str) -> bool {
    matches!(
        path,
        "/v1/context-assistance"
            | "/v1/context-assistance/installations"
            | "/v1/context-assistance/jobs"
            | "/v1/context-assistance/usage"
            | codex_config::LEAN
            | codex_config::SHORT_REPLIES
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
        codex_config::LEAN => "codex_lean",
        codex_config::SHORT_REPLIES => "codex_short_replies",
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
        "/v1/context-assistance/usage" => usage(config, resident),
        path => return codex_config::get(path, config),
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
        "codex_lean" | "codex_short_replies" => return codex_config::post(path, payload, config),
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

/// The usage meter's totals with this week's savings estimate. The first
/// count of a long history runs in the background; until it finishes the
/// state is `counting` and the page asks again. An older or stopped resident
/// has no estimate; the meter still shows.
fn usage(
    config: &ReadConfig,
    resident: impl FnOnce(Value, bool) -> Result<Map<String, Value>, String>,
) -> Reply {
    let Some(home) = codex_config::homes(config).map(|homes| homes.home_dir) else {
        return ok(crate::context_usage_meter::empty("unavailable"));
    };
    let env = ["CODEX_HOME", "CLAUDE_CONFIG_DIR"]
        .into_iter()
        .filter_map(|name| Some((name.to_owned(), std::env::var(name).ok()?)))
        .collect();
    let mut state =
        crate::context_usage_meter::read(&home, std::path::Path::new(&config.guard_home), env);
    state["savings"] = workspace("savings", Map::new(), resident)
        .ok()
        .and_then(|mut data| data.remove("result"))
        .unwrap_or(Value::Null);
    ok(state)
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

#[cfg(test)]
#[path = "daemon_edge_context_assistance_tests.rs"]
mod tests;
