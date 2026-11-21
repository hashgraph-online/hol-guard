//! Codex: whether a hook handler is a live Guard handler, whether Guard may
//! replace it, and what doctor says about the managed hooks
//! (`codex_hook_registration`).
//!
//! `live` judges one command, `owner` refuses a Guard handler with no proven
//! owner, `matches` reports which managed events still route Guard,
//! `install` appends the managed groups once every remaining Guard handler is
//! proven this install's, `overlay` keeps stale-CLI ownership visible, and
//! `doctor` writes the doctor copy and setup status.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::codex::{compact, dict, strings, text};
use super::codex_hook_state;
use super::codex_merge::{get, set, Entries};
use super::codex_owner_home::{self as home, Home, BRIDGE_SCRIPT};
use super::codex_owners::{tokens, EVENTS};
use super::codex_python_hook::{has_codex_harness, python_codex_hook_command};
use super::{Failure, Step};
use crate::codex_hook_bridge::decode_config_argument;
use crate::cursor_hook_command::{py_space, Syntax, FROZEN_LAUNCHERS};
use crate::pyjson::{self, PyVal};

const NATIVE_COMMAND: &str = "codex-hook-bridge";
const FROZEN_BRIDGE_ARG: &str = "--_hol-guard-codex-bridge";
const INTERCEPT_EVENTS: [&str; 2] = ["PreToolUse", "PermissionRequest"];
pub(super) const FALLBACK_REASONS: [&str; 5] = [
    "codex_hook_interpreter_path_mismatch",
    "codex_hook_manifest_packaged_files_stale",
    "codex_hook_manifest_package_version_stale",
    "codex_hook_manifest_registration_stale",
    "codex_hook_manifest_schema_unsupported",
];
const FALSE_UNINSTALLED: &str = "guard is not installed for this harness";
const REPAIR: &str = "Run `hol-guard install codex` or `hol-guard update`";
const TRUST_WARNING: &str = "Codex has not trusted the current HOL Guard hooks, so Codex skips them. Open Codex, run /hooks, and press t to trust them.";

pub(super) const FIELDS: [(&str, &[&str]); 6] = [
    ("live", &["command"]),
    (
        "owner",
        &["command", "ownership", "coordinate", "source_path"],
    ),
    ("matches", &["hooks"]),
    (
        "install",
        &["hooks", "managed", "cwd", "guard_home", "package_root"],
    ),
    ("overlay", &["hooks", "integrity"]),
    ("doctor", &["warnings", "hook_state", "base_status"]),
];

/// The fields an op here takes, `None` for an op that is not one of these.
pub(super) fn fields(op: &str) -> Option<Vec<&'static str>> {
    FIELDS
        .iter()
        .find(|(name, _)| *name == op)
        .map(|(_, keys)| keys.to_vec())
}

pub(super) fn run(op: &str, fields: &Map<String, Value>, syntax: &mut Syntax) -> Step<Value> {
    match op {
        "live" => {
            let command = text(fields, "command")?;
            Ok(json!({
                "live": live(command, syntax),
                "missing": missing_program(command, syntax),
                "launchable": launchable(command, syntax),
            }))
        }
        "owner" => {
            let (command, ownership) = (text(fields, "command")?, text(fields, "ownership")?);
            let place = (
                optional(fields, "coordinate")?,
                optional(fields, "source_path")?,
            );
            Ok(json!({ "conflict": conflict(command, ownership, place, syntax) }))
        }
        "matches" => {
            // A `hooks` value that is not a table routes nothing.
            let hooks = match pyjson::parse(text(fields, "hooks")?) {
                Ok(PyVal::Dict(entries)) => entries,
                Ok(_) => Vec::new(),
                Err(_) => return Err(Failure::Invalid),
            };
            let matches = event_matches(&hooks, syntax);
            Ok(json!({ "matches": matches, "intercept": intercept(&hooks, syntax) }))
        }
        "install" => install(fields, syntax),
        "overlay" => codex_hook_state::overlay(fields, syntax),
        "doctor" => doctor(fields),
        _ => Err(Failure::Invalid),
    }
}

fn optional<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<Option<&'a str>> {
    match fields.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(Failure::Invalid),
    }
}

/// `_native_bridge_payload`: the legacy Python bridge argv an older native
/// launcher delegated to.
fn native_payload(tokens: &[String]) -> Option<&[String]> {
    (tokens.len() > 3 && tokens[1] == NATIVE_COMMAND).then(|| &tokens[2..])
}

/// `_skip_leading_flags`.
fn skip_flags(tokens: &[String]) -> &[String] {
    let start = tokens
        .iter()
        .position(|token| !token.starts_with('-') || token == "-c")
        .unwrap_or(tokens.len());
    &tokens[start..]
}

/// `frozen_codex_bridge_tokens_are_live`.
fn frozen_bridge_live(tokens: &[String]) -> bool {
    let Some(index) = tokens.iter().position(|token| token == FROZEN_BRIDGE_ARG) else {
        return false;
    };
    let config = tokens
        .get(index + 1)
        .and_then(|value| decode_config_argument(value));
    config.is_some_and(|config| matches!(pyjson::parse(&config), Ok(PyVal::Dict(_))))
}

/// `_is_live_guard_codex_hook_command`.
pub(super) fn live(command: &str, syntax: &mut Syntax) -> bool {
    let tokens = tokens(syntax, command);
    live_tokens(&tokens, syntax)
}

fn live_tokens(tokens: &[String], syntax: &mut Syntax) -> bool {
    let Some(program) = tokens.first() else {
        return false;
    };
    if tokens.len() == 3 && tokens[1] == NATIVE_COMMAND {
        return true;
    }
    if let Some(payload) = native_payload(tokens) {
        // The current registration with arguments appended is still Guard's
        // handler, altered; only a legacy Python bridge argv is judged inside.
        return payload[0].trim_start_matches(py_space).starts_with('{')
            || live_tokens(payload, syntax);
    }
    let name = syntax.name(program);
    let lower = name.to_lowercase();
    let rest = &tokens[1..];
    let payload = skip_flags(rest);
    let runs_bridge = |syntax: &Syntax| {
        payload
            .first()
            .is_some_and(|script| syntax.name(script) == BRIDGE_SCRIPT)
    };
    if name == BRIDGE_SCRIPT || lower.contains("hol-guard-codex-hook") {
        return true;
    }
    if lower.starts_with("python") {
        if payload.first().map(String::as_str) == Some("-c") {
            let script = payload[1..].join(" ");
            let words: Vec<&str> = script
                .split(py_space)
                .filter(|word| !word.is_empty())
                .collect();
            return script.contains("codex_plugin_scanner.cli")
                && words.contains(&"guard")
                && words.contains(&"hook");
        }
        return runs_bridge(syntax);
    }
    if FROZEN_LAUNCHERS.contains(&lower.as_str()) {
        if runs_bridge(syntax) || frozen_bridge_live(rest) {
            return true;
        }
        let harness = tokens_of(syntax, &rest.join(" "));
        return rest.iter().any(|token| token == "hook") && has_codex_harness(&harness);
    }
    false
}

fn tokens_of(syntax: &mut Syntax, command: &str) -> Vec<Option<String>> {
    tokens(syntax, command).into_iter().map(Some).collect()
}

/// `_hook_program_candidates`.
fn program_candidates(tokens: &[String], syntax: &Syntax) -> Vec<String> {
    let mut candidates: Vec<String> = tokens.first().cloned().into_iter().collect();
    if let Some(payload) = native_payload(tokens) {
        candidates.extend(program_candidates(payload, syntax));
        return candidates;
    }
    let payload = skip_flags(tokens.get(1..).unwrap_or_default());
    candidates.extend(
        payload
            .first()
            .filter(|script| syntax.name(script) == BRIDGE_SCRIPT)
            .cloned(),
    );
    candidates
}

/// `missing_guard_hook_program`: the absolute launcher or bridge path a
/// Guard hook needs that no longer exists. Bare names resolve through PATH
/// at launch time and are not checked.
pub(super) fn missing_program(command: &str, syntax: &mut Syntax) -> Option<String> {
    if syntax.windows() != cfg!(windows) || !live(command, syntax) {
        return None;
    }
    let tokens = tokens(syntax, command);
    program_candidates(&tokens, syntax).into_iter().find(|candidate| {
        let path = Path::new(candidate);
        path.is_absolute()
            && matches!(
                fs::metadata(path),
                Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
            )
    })
}

/// `hook_command_launchable`: a Windows entry still in POSIX quoting never
/// launches.
fn launchable(command: &str, syntax: &mut Syntax) -> bool {
    let legacy = syntax.windows() && command.trim_start_matches(py_space).starts_with('\'');
    !legacy && syntax.split_hook(command).is_some()
}

/// `require_codex_hook_owner`: the refusal for a Guard handler no rule
/// claimed, or `None`.
pub(super) fn conflict(
    command: &str,
    ownership: &str,
    place: (Option<&str>, Option<&str>),
    syntax: &mut Syntax,
) -> Option<String> {
    let tokens = tokens(syntax, command);
    let python = tokens
        .first()
        .is_some_and(|program| syntax.name(program).to_lowercase().starts_with("python"));
    let guard_hook = if python {
        python_codex_hook_command(&tokens, syntax)
    } else {
        live(command, syntax)
    };
    if ownership != "unmanaged" || !guard_hook {
        return None;
    }
    Some(owner_message(
        command,
        missing_program(command, syntax),
        place,
    ))
}

/// `owner_conflict_message`: where the handler is, what it runs, that Guard
/// changed nothing, and the one edit that clears it.
fn owner_message(
    command: &str,
    missing: Option<String>,
    place: (Option<&str>, Option<&str>),
) -> String {
    let (coordinate, source) = (
        place.0.filter(|v| !v.is_empty()),
        place.1.filter(|v| !v.is_empty()),
    );
    let location = match (coordinate, source) {
        (Some(at), Some(source)) => format!(" at {at} in {source}"),
        (Some(at), None) => format!(" at {at}"),
        (None, Some(source)) => format!(" in {source}"),
        (None, None) => String::new(),
    };
    let remedy = format!(
        "Delete that handler from {}, then run `hol-guard install codex`; existing hooks have been preserved.",
        source.unwrap_or("your Codex hooks configuration")
    );
    if let Some(missing) = missing {
        return format!(
            "codex_hook_owner_conflict: A Codex Guard handler{location} runs {missing}, which no longer \
             exists, so Codex is not protected. It has no verified ownership binding, so Guard will not \
             remove it. {remedy}"
        );
    }
    format!(
        "codex_hook_owner_conflict: An existing Codex Guard handler{location} has no verified ownership \
         binding, so Guard installed nothing and left your configuration exactly as it was. Guard replaces a \
         handler only when it names this installation's Guard home and runs a program inside a root this \
         install controls; this one does not, so Guard cannot prove it wrote it. The handler \
         is: {command}. If it is yours, keep it and nothing more is needed. {remedy}"
    )
}

/// `_hook_entry_is_active`.
fn active(entry: &[(String, PyVal)]) -> bool {
    !matches!(get(entry, "enabled"), Some(PyVal::Bool(false)))
        && !matches!(get(entry, "disabled"), Some(PyVal::Bool(true)))
}

/// `_matcher_covers_shell`.
fn covers_shell(matcher: Option<&PyVal>) -> bool {
    match matcher {
        None | Some(PyVal::Null) => true,
        Some(PyVal::Str(matcher)) => {
            let matcher = matcher.trim_matches(py_space);
            matcher.is_empty() || matcher == "*" || matcher.contains("Bash")
        }
        _ => false,
    }
}

/// `_group_has_active_guard_handler`.
fn group_routes(group: &[(String, PyVal)], launch: bool, syntax: &mut Syntax) -> bool {
    if !active(group) {
        return false;
    }
    let mut routes = |command: Option<&PyVal>| {
        let Some(PyVal::Str(command)) = command else {
            return false;
        };
        live(command, syntax)
            && (!launch
                || (launchable(command, syntax) && missing_program(command, syntax).is_none()))
    };
    match get(group, "hooks") {
        Some(PyVal::List(handlers)) => handlers.iter().any(|handler| {
            handler
                .as_dict()
                .is_some_and(|entry| active(entry) && routes(get(entry, "command")))
        }),
        _ => routes(get(group, "command")),
    }
}

fn groups<'a>(hooks: &'a Entries, event: &str) -> &'a [PyVal] {
    match get(hooks, event) {
        Some(PyVal::List(groups)) => groups,
        _ => &[],
    }
}

/// `live_owned_codex_event_matches`.
pub(super) fn event_matches(hooks: &Entries, syntax: &mut Syntax) -> Map<String, Value> {
    EVENTS
        .iter()
        .map(|event| {
            let found = groups(hooks, event).iter().any(|group| {
                group
                    .as_dict()
                    .is_some_and(|group| group_routes(group, false, syntax))
            });
            ((*event).to_owned(), Value::Bool(found))
        })
        .collect()
}

/// `live_guard_codex_hooks_intercept`: a handler Codex can actually start,
/// covering the shell, on both intercept events.
pub(super) fn intercept(hooks: &Entries, syntax: &mut Syntax) -> bool {
    INTERCEPT_EVENTS.iter().all(|event| {
        groups(hooks, event).iter().any(|group| {
            group.as_dict().is_some_and(|group| {
                group_routes(group, true, syntax) && covers_shell(get(group, "matcher"))
            })
        })
    })
}

/// `install_managed_codex_hook_groups`: refuse while a Guard handler has no
/// proven owner, else append each managed group.
fn install(fields: &Map<String, Value>, syntax: &mut Syntax) -> Step<Value> {
    let mut hooks = dict(fields, "hooks")?;
    let managed = dict(fields, "managed")?;
    let owner = Home::parse(fields)?;
    for (event, _) in &managed {
        for (group_index, group) in groups(&hooks, event).iter().enumerate() {
            let Some(entries) = group.as_dict().filter(|entries| active(entries)) else {
                continue;
            };
            let handlers = match get(entries, "hooks") {
                Some(PyVal::List(handlers)) => handlers.clone(),
                _ => vec![group.clone()],
            };
            for (handler_index, handler) in handlers.iter().enumerate() {
                let Some(entry) = handler.as_dict().filter(|entry| active(entry)) else {
                    continue;
                };
                let Some(PyVal::Str(command)) = get(entry, "command") else {
                    continue;
                };
                let ownership = if home::binds(command, &owner, syntax) {
                    "self_install_binding"
                } else {
                    "unmanaged"
                };
                let at = format!("{event}/group[{group_index}]/handler[{handler_index}]");
                if let Some(message) = conflict(command, ownership, (Some(&at), None), syntax) {
                    return Ok(json!({ "conflict": message }));
                }
            }
        }
    }
    for (event, group) in managed {
        let mut existing = groups(&hooks, &event).to_vec();
        existing.push(group);
        set(&mut hooks, &event, PyVal::List(existing));
    }
    Ok(json!({ "hooks": compact(&PyVal::Dict(hooks), false) }))
}

fn state_flag(state: &Map<String, Value>, key: &str) -> bool {
    state.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The hook manifest check passed: the state's `integrity_status` is `valid`.
fn integrity_valid(state: &Map<String, Value>) -> bool {
    state.get("integrity_status").and_then(Value::as_str) == Some("valid")
}

/// `finalize_codex_doctor_warnings` then `finalize_codex_doctor_setup_status`
/// and the leftover-config adjustment (`doctor_status`).
fn doctor(fields: &Map<String, Value>) -> Step<Value> {
    let state = fields
        .get("hook_state")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let installed = state_flag(state, "managed_hook_installed");
    let mut warnings = strings(fields.get("warnings"))?;
    if state_flag(state, "config_present") {
        if !state_flag(state, "codex_hooks_enabled") {
            warnings.push(format!(
                "Codex config was found, but native hooks are disabled. {REPAIR} to repair protection."
            ));
        }
        if !installed {
            warnings.push(format!(
                "Codex config was found, but Guard's managed Codex hooks are missing. {REPAIR} to repair protection."
            ));
        } else if !integrity_valid(state) {
            warnings.push(format!(
                "Codex hooks are installed but do not match this Guard CLI. {REPAIR} to rebind them."
            ));
        }
    }
    if installed {
        warnings.retain(|warning| !warning.to_lowercase().contains(FALSE_UNINSTALLED));
    }
    let joined = warnings.join(" ").to_lowercase();
    let setup_failure =
        joined.contains("command is not available") || joined.contains("native hooks are disabled");
    let base = fields
        .get("base_status")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let status = if installed {
        if state_flag(state, "protection_active") && !setup_failure {
            "active"
        } else {
            "broken"
        }
    } else {
        match base.unwrap_or("partial") {
            "active" => "broken",
            other => other,
        }
    };
    let mut finish = Map::new();
    finish.insert("warnings".to_owned(), json!(warnings));
    finish.insert("status".to_owned(), json!(status));
    finish.insert("base_status".to_owned(), json!(base));
    let mut status = super::codex::doctor_status(&finish)?["status"].clone();
    // Codex skips hooks it has not trusted, so they are never called active.
    if state_flag(state, "hook_trust_stale") {
        warnings.push(TRUST_WARNING.to_owned());
        if status == "active" {
            status = json!("partial");
        }
    }
    Ok(json!({ "warnings": warnings, "status": status }))
}

#[cfg(test)]
#[path = "codex_live_hooks_tests.rs"]
mod tests;
