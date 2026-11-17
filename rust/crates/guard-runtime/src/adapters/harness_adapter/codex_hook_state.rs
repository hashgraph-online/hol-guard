//! Codex: the hook state launch and doctor read. Which managed events Guard
//! owns comes from the authenticated manifest, widened by the live hooks only
//! while that manifest is merely stale, and whether Codex still trusts them.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex::{
    compact, flag, registered, text, ENFORCEMENT_BOUNDARY, EVENTS, HOOK_UNAVAILABLE,
};
use super::codex_live_hooks::{event_matches, FALLBACK_REASONS};
use super::codex_merge::Entries;
use super::codex_owners::{long_paths, EVENTS as OWNER_EVENTS};
use super::files::{self, Doc};
use super::{codex_config_hooks, Ctx, Failure, Step};
use crate::cursor_hook_command::Syntax;
use crate::pyjson::{self, PyVal};

/// The state from the files read (`features`, `toml_hooks`, `json_hooks`),
/// the manifest's integrity state and the tokens standing for the TOML
/// values JSON cannot carry. `fields` holds `config_path`, `hooks_path` and
/// the command syntax.
pub(super) fn decide(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    read: Vec<(String, PyVal)>,
    integrity: Vec<(String, PyVal)>,
    tokens: Option<&Map<String, Value>>,
) -> Step<Value> {
    let read = PyVal::Dict(read);
    let features = read.get("features").and_then(PyVal::as_dict);
    let held = |event: &str| {
        let recorded = integrity.iter().find(|(key, _)| key == "event_matches");
        let found = recorded.and_then(|(_, matches)| matches.get(event));
        matches!(found, Some(PyVal::Bool(true)))
    };
    let field = |key: &str| integrity.iter().find(|(name, _)| name == key);
    let field = |key: &str| field(key).and_then(|(_, value)| value.as_str());
    let hooks = match read.get("toml_hooks") {
        Some(PyVal::Dict(hooks)) => Some(hooks),
        _ => read.get("json_hooks").and_then(|hooks| match hooks {
            PyVal::Dict(hooks) => Some(hooks),
            _ => None,
        }),
    };
    let (status, reason) = (field("integrity_status"), field("integrity_reason"));
    let matches = with_syntax(fields, |syntax| {
        Ok(owned_matches(status, reason, held, hooks, syntax))
    })?;
    let matched = |event: &str| matches.get(event).and_then(Value::as_bool) == Some(true);
    let [pre, permission, prompt, post] = EVENTS.map(|(event, ..)| matched(event));
    let managed = pre && permission && prompt && post;
    let shell = pre && permission;
    let valid = integrity
        .iter()
        .any(|(key, value)| key == "integrity_status" && value.as_str() == Some("valid"));
    let enabled = features.is_none_or(|features| {
        !features
            .iter()
            .any(|(key, value)| key == "hooks" && matches!(value, PyVal::Bool(false)))
    });
    let legacy = features.is_some_and(|features| {
        features
            .iter()
            .any(|(key, value)| key == "codex_hooks" && matches!(value, PyVal::Bool(true)))
    });
    let config = text(fields, "config_path")?;
    let hooks = text(fields, "hooks_path")?;
    let shell_active = enabled && shell && valid;
    let trust_stale = match read.get("toml_hooks") {
        Some(PyVal::Dict(hooks)) => {
            let tokens = tokens.ok_or(Failure::Invalid)?;
            // `fields` carries the `windows` and `long_paths` the owner check splits with.
            codex_config_hooks::trust_stale(ctx, fields, hooks, tokens, Path::new(config))?
        }
        _ => false,
    };
    let mut state = Doc::default();
    state
        .set("config_path", files::text(config))
        .set("config_present", PyVal::Bool(Path::new(config).is_file()))
        .set("hooks_path", files::text(hooks))
        .set("hooks_present", PyVal::Bool(Path::new(hooks).is_file()))
        .set(
            "toml_hooks_present",
            PyVal::Bool(registered(read.get("toml_hooks"))),
        )
        .set(
            "json_hooks_present",
            PyVal::Bool(registered(read.get("json_hooks"))),
        )
        .set("hooks_enabled", PyVal::Bool(enabled))
        .set("codex_hooks_enabled", PyVal::Bool(enabled))
        .set("legacy_codex_hooks_enabled", PyVal::Bool(legacy))
        .set("managed_pre_tool_hook_installed", PyVal::Bool(pre))
        .set(
            "managed_permission_request_hook_installed",
            PyVal::Bool(permission),
        )
        .set("managed_prompt_hook_installed", PyVal::Bool(prompt))
        .set("managed_post_tool_hook_installed", PyVal::Bool(post))
        .set("managed_hook_installed", PyVal::Bool(managed))
        .set(
            "shell_enforcement_boundary",
            files::text(ENFORCEMENT_BOUNDARY),
        )
        .set("shell_hook_installed", PyVal::Bool(shell))
        .set("shell_protection_active", PyVal::Bool(shell_active))
        .set(
            "shell_reason_code",
            if shell_active {
                PyVal::Null
            } else {
                files::text(HOOK_UNAVAILABLE)
            },
        )
        .set(
            "protection_active",
            PyVal::Bool(enabled && managed && valid),
        )
        .set("hook_trust_stale", PyVal::Bool(trust_stale));
    for (key, value) in integrity {
        if key != "event_matches" {
            state.set(&key, value);
        }
    }
    Ok(json!({ "state": compact(&state.value(), false) }))
}

/// `overlay_live_owned_event_matches`: the manifest's recorded matches,
/// widened by the live hooks only when the manifest is merely stale.
pub(super) fn owned_matches(
    status: Option<&str>,
    reason: Option<&str>,
    held: impl Fn(&str) -> bool,
    hooks: Option<&Entries>,
    syntax: &mut Syntax,
) -> Map<String, Value> {
    let stale = status != Some("valid") && reason.is_some_and(|r| FALLBACK_REASONS.contains(&r));
    let live = match hooks {
        Some(hooks) if stale => event_matches(hooks, syntax),
        _ => Map::new(),
    };
    let found = |event: &str| held(event) || live.get(event) == Some(&Value::Bool(true));
    OWNER_EVENTS
        .iter()
        .map(|event| ((*event).to_owned(), Value::Bool(found(event))))
        .collect()
}

/// Runs `body` over the caller's `windows` and `long_paths`. A short name
/// the request does not name is expanded by this host.
pub(super) fn with_syntax<T>(
    fields: &Map<String, Value>,
    body: impl FnOnce(&mut Syntax) -> Step<T>,
) -> Step<T> {
    let mut syntax = Syntax::new(flag(fields, "windows")?, long_paths(fields)?);
    body(&mut syntax)
}

/// `overlay_live_owned_event_matches`: keep stale-CLI ownership, but never
/// treat a missing or tampered manifest as installed.
pub(super) fn overlay(fields: &Map<String, Value>, syntax: &mut Syntax) -> Step<Value> {
    let integrity = fields
        .get("integrity")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let field = |key: &str| integrity.get(key).and_then(Value::as_str);
    let recorded = integrity.get("event_matches").and_then(Value::as_object);
    let held = |event: &str| recorded.and_then(|m| m.get(event)) == Some(&Value::Bool(true));
    let hooks = match pyjson::parse(text(fields, "hooks")?) {
        Ok(PyVal::Dict(hooks)) => Some(hooks),
        _ => None,
    };
    let (status, reason) = (field("integrity_status"), field("integrity_reason"));
    let matches = owned_matches(status, reason, held, hooks.as_ref(), syntax);
    Ok(json!({ "matches": matches }))
}
