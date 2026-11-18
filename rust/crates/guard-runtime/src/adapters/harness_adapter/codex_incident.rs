//! Codex: `hol-guard doctor codex --incident-export`, the small read-only
//! report `guard/cli/doctor_incident.py` assembled before it moved here.
//!
//! The report reads `config.toml` and `hooks.json` with bounded, race-checked
//! reads, counts the configured hook shapes without naming a command, asks the
//! verifier for the manifest integrity, and adds the authenticated daemon
//! discovery and a bounded lifecycle journal. It never echoes configuration
//! text or an error message. Request fields are `live_hook_state`'s.
//! Answer: `{"report": <sorted compact JSON>}` or
//! `{"error": "incident_report_size_limit"}`.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex::{config_path, hooks_path};
use super::codex_incident_read::{read_hook_files, status as fields_of, HookRead};
use super::codex_live_state::verified_live_state;
use super::codex_spec::with_spec;
use super::{caller, Ctx, Step};
use crate::pyjson::PyVal;

const MAX_REPORT_BYTES: usize = 8192;
const EVENTS: [&str; 4] = [
    "PreToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "PostToolUse",
];
const HOOKS_UNAVAILABLE: [&str; 5] = [
    "unreadable",
    "malformed",
    "too_large",
    "unsafe_file_type",
    "changed_during_read",
];
/// The class Python named for a failed integrity probe; the runtime raises
/// none, so every probe failure reports the one Python's adapter raised.
const PROBE_FAILURE_CLASS: &str = "RuntimeError";

pub(super) fn incident_report(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let report = report(ctx, fields, &collected_at())?;
    let encoded = ascii_json(&report);
    if encoded.len() > MAX_REPORT_BYTES {
        return Ok(json!({"error": "incident_report_size_limit"}));
    }
    Ok(json!({ "report": encoded }))
}

pub(super) fn report(ctx: &Ctx, fields: &Map<String, Value>, collected_at: &str) -> Step<Value> {
    let config = ctx.absolute(&config_path(ctx));
    let read = read_hook_files(&config, &ctx.absolute(&hooks_path(ctx)));
    let (group_counts, handler_counts) = shape_counts(&read.hooks);
    let integrity = integrity(ctx, fields, &config_path(ctx), &read);
    let mut configured = read.status;
    configured.insert("event_group_counts".into(), group_counts);
    configured.insert("event_handler_counts".into(), handler_counts);
    configured.extend(integrity);
    Ok(json!({
        "schema": "hol-guard.codex-incident.v1",
        "collected_at": collected_at,
        "harness": "codex",
        "cli_package_version": caller::version(ctx)?,
        "configured": configured,
        "workspace": workspace_observation(ctx),
        "daemon": daemon(&ctx.guard_home),
        "loaded_harness": {"state": "unknown", "reason_code": "loaded_session_not_observable"},
        "authenticated_hook_decision": {"state": "unknown", "reason_code": "decision_not_probed"},
        "timeline": timeline(&ctx.guard_home),
    }))
}

/// `_hook_shape_counts`: groups and handlers per managed event, `null` for
/// an event whose entries are malformed (a partial count would hide them).
pub(super) fn shape_counts(hooks: &PyVal) -> (Value, Value) {
    let PyVal::Dict(_) = hooks else {
        return (Value::Null, Value::Null);
    };
    let mut groups_by_event = Map::new();
    let mut handlers_by_event = Map::new();
    for event in EVENTS {
        let (groups, handlers) = match hooks.get(event) {
            None => (json!(0), json!(0)),
            Some(PyVal::List(groups))
                if groups.iter().all(|group| matches!(group, PyVal::Dict(_))) =>
            {
                (json!(groups.len()), handler_count(groups))
            }
            Some(_) => (Value::Null, Value::Null),
        };
        groups_by_event.insert(event.to_owned(), groups);
        handlers_by_event.insert(event.to_owned(), handlers);
    }
    (
        Value::Object(groups_by_event),
        Value::Object(handlers_by_event),
    )
}

fn handler_count(groups: &[PyVal]) -> Value {
    let mut count = 0usize;
    for group in groups {
        match group.get("hooks") {
            Some(PyVal::List(handlers))
                if handlers
                    .iter()
                    .all(|handler| matches!(handler, PyVal::Dict(_))) =>
            {
                count += handlers.len();
            }
            _ => return Value::Null,
        }
    }
    json!(count)
}

/// The manifest integrity fields of `configured`.
fn integrity(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    config: &Path,
    read: &HookRead,
) -> Map<String, Value> {
    let config_status = read.status.get("config_status").and_then(Value::as_str);
    let hooks_status = read.status.get("hooks_status").and_then(Value::as_str);
    let hooks_unavailable = hooks_status.is_some_and(|code| HOOKS_UNAVAILABLE.contains(&code));
    if !matches!(config_status, Some("read" | "missing")) || hooks_unavailable {
        let reason = if hooks_unavailable {
            "codex_hooks_unavailable"
        } else {
            "codex_config_unavailable"
        };
        return unverified(reason, Value::Null);
    }
    let verified = with_spec(ctx, fields).and_then(|request| {
        let spec = request
            .get("spec")
            .and_then(Value::as_object)
            .ok_or(super::Failure::Invalid)?;
        verified_live_state(
            ctx,
            spec,
            request.as_ref(),
            config,
            &read.hooks,
            &read.tokens,
        )
    });
    let Ok(state) = verified else {
        return unverified("codex_integrity_probe_failed", json!(PROBE_FAILURE_CLASS));
    };
    let status = safe_code(state.get("integrity_status"), "unknown");
    let reason = safe_code(
        state.get("integrity_reason"),
        "codex_hook_integrity_unknown",
    );
    let matches = state.get("event_matches").and_then(Value::as_object);
    let managed: Map<String, Value> = EVENTS
        .iter()
        .map(|event| {
            let matched = matches.and_then(|matches| matches.get(*event)) == Some(&json!(true));
            ((*event).to_owned(), json!(matched))
        })
        .collect();
    let valid = status == "valid";
    let field = |key: &str, safe: fn(&Value) -> bool| match state.get(key) {
        Some(value) if valid && safe(value) => value.clone(),
        _ => Value::Null,
    };
    let mut integrity = status_fields(&status, &reason, Value::Null, managed);
    integrity.insert(
        "manifest_package_version".into(),
        field("manifest_package_version", safe_version),
    );
    integrity.insert(
        "manifest_generated_at".into(),
        field("manifest_generated_at", safe_generation),
    );
    integrity.insert("bridge_sha256".into(), field("bridge_sha256", safe_digest));
    integrity.insert(
        "interpreter_sha256".into(),
        field("interpreter_sha256", safe_digest),
    );
    integrity
}

fn unverified(reason: &str, exception_class: Value) -> Map<String, Value> {
    let managed = EVENTS
        .iter()
        .map(|event| ((*event).to_owned(), json!(false)))
        .collect();
    let mut fields = status_fields("unverified", reason, exception_class, managed);
    for key in [
        "manifest_package_version",
        "manifest_generated_at",
        "bridge_sha256",
        "interpreter_sha256",
    ] {
        fields.insert(key.into(), Value::Null);
    }
    fields
}

fn status_fields(
    status: &str,
    reason: &str,
    exception_class: Value,
    managed: Map<String, Value>,
) -> Map<String, Value> {
    fields_of(&[
        ("manifest_integrity", json!(status)),
        ("reason_code", json!(reason)),
        ("integrity_probe_exception_class", exception_class),
        ("managed_events", Value::Object(managed)),
    ])
}

/// `_workspace_hook_observation`: the selected workspace's configured shapes,
/// never authenticated.
fn workspace_observation(ctx: &Ctx) -> Value {
    let Some(workspace) = &ctx.workspace else {
        return json!({"selected": false});
    };
    let root: PathBuf = ctx.absolute(&workspace.join(".codex"));
    let read = read_hook_files(&root.join("config.toml"), &root.join("hooks.json"));
    let (group_counts, handler_counts) = shape_counts(&read.hooks);
    let mut observation = read.status;
    observation.insert("selected".into(), json!(true));
    observation.insert(
        "authentication".into(),
        json!("unverified_local_configuration"),
    );
    observation.insert("event_group_counts".into(), group_counts);
    observation.insert("event_handler_counts".into(), handler_counts);
    Value::Object(observation)
}

fn daemon(guard_home: &Path) -> Value {
    let state = crate::daemon_policy_authority::load_authenticated_daemon_state(guard_home);
    let compatibility = state
        .as_ref()
        .and_then(|state| state.get("compatibility_version"))
        .filter(|value| value.is_i64() || value.is_u64())
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "discovery_authentication": if state.is_some() { "verified" } else { "unverified" },
        "package_version": state
            .as_ref()
            .and_then(|state| state.get("package_version"))
            .filter(|value| safe_version(value))
            .cloned(),
        "compatibility_version": compatibility,
        "liveness": "unknown",
    })
}

fn timeline(guard_home: &Path) -> Value {
    let (events, status) = crate::daemon_edge::lifecycle::load_events(guard_home, 20, true);
    let events: Vec<Value> = events
        .iter()
        .map(|event| {
            json!({
                "event": event.get("event").cloned().unwrap_or(Value::Null),
                "reason": event.get("reason").cloned().unwrap_or(Value::Null),
                "recorded_at_ns": event.get("recorded_at_ns").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    json!({
        "status": status,
        "scope": "recent_bounded_journal",
        "authentication": "unverified_local_observations",
        "events": events,
    })
}

fn safe_code(value: Option<&Value>, fallback: &str) -> String {
    match value.and_then(Value::as_str) {
        Some(code) if is_safe_code(code) => code.to_owned(),
        _ => fallback.to_owned(),
    }
}

/// `^[a-z][a-z0-9_]{0,79}$`
fn is_safe_code(code: &str) -> bool {
    let mut characters = code.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && code.len() <= 80
        && characters.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// `^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`
fn safe_version(value: &Value) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && text.len() <= 64
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-'))
}

/// `^[0-9a-f]{64}$`
fn safe_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    })
}

/// At most 64 of `[0-9T:.+\-Z]`.
fn safe_generation(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        !text.is_empty()
            && text.len() <= 64
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, 'T' | ':' | '.' | '+' | '-' | 'Z'))
    })
}

/// `datetime.now(timezone.utc).isoformat()`.
fn collected_at() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    crate::approval_gate_state::iso_from_epoch(seconds)
}

/// `json.dumps(report, sort_keys=True, separators=(",", ":"))`: the map is
/// already sorted, and every non-ASCII character is escaped as Python does.
pub(super) fn ascii_json(value: &Value) -> String {
    let mut out = String::new();
    for character in sorted(value).to_string().chars() {
        if character.is_ascii() {
            out.push(character);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in character.encode_utf16(&mut units) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
    out
}

/// Keys in sorted order whatever map the build links.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sorted(&map[key])))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
#[path = "codex_incident_tests.rs"]
mod tests;
