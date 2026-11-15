//! Claude Code: Guard's hook entries in `~/.claude/settings.json`, the
//! SessionStart refresh that rewrites them after an upgrade, and the
//! diagnostics that notice them gone.
//!
//! Python answers `{"reply": {"facts": null}}` with what only the Guard
//! process knows (see `claude_argv`), merges it into the request and asks
//! again. It keeps the shim, the daemon start the SessionStart hook runs, the
//! `claude --help` probe and the file publication.

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::claude_argv::{self as argv, Facts};
use super::claude_settings as settings;
use super::files::{self, Change, Doc, Object};
use super::{
    common, detection, kimi, path_answer, path_text, resolved_executable, which, Ctx, Failure,
    Spec, Step,
};
use crate::claude_hook_config::missing_events;
use crate::claude_session_start_contract::{contract, HookGroupsContract};
use crate::pyjson::PyVal;

const LABEL: &str = "Claude Code";
const NOT_JSON: &str = "Claude Code settings are not valid JSON.";
const NOT_OBJECT: &str = "Claude Code settings must be a JSON object before installation.";
const INSTALL_NOTE: &str = "Guard hook entries added to ~/.claude/settings.json";
const UNINSTALL_NOTE: &str = "Guard hook entries removed from ~/.claude/settings.json";
const SESSION_START_ERROR: &str =
    "claude_session_start_argv_invalid: reinstall the managed Claude hooks with \
     `hol-guard install claude`";
const UNINSTALL_EVENTS: [&str; 7] = [
    "SessionStart",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "UserPromptSubmit",
    "Notification",
    "Stop",
];

/// `claude_managed_settings_path`: hooks are always installed globally.
fn settings_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".claude").join("settings.json")
}

fn policy_path(ctx: &Ctx) -> PathBuf {
    match &ctx.workspace {
        Some(workspace) => workspace.join(".claude").join("settings.local.json"),
        None => settings_path(ctx),
    }
}

/// The local install `claude migrate-installer` leaves outside PATH.
fn candidate(ctx: &Ctx) -> PathBuf {
    ctx.user_home.join(".claude").join("local").join("claude")
}

fn hook_contract() -> Step<HookGroupsContract> {
    contract().map_err(|_| Failure::Invalid)
}

/// `_json_payload`: an unreadable or non-object file reads as `{}`.
fn read_lenient(ctx: &Ctx, path: &std::path::Path) -> Step<Object> {
    let Ok(bytes) = std::fs::read(ctx.absolute(path)) else {
        return Ok(Object::default());
    };
    let text = kimi::utf8(bytes, "Claude Code settings")?;
    Ok(match Object::parse(&text) {
        Some(Ok(object)) => object,
        _ => Object::default(),
    })
}

/// The settings' `hooks` object, when it is one.
fn hooks_of(payload: &Object) -> Option<Doc> {
    match payload.entries.iter().find(|(key, _)| key == "hooks") {
        Some((_, PyVal::Dict(entries))) => Some(Doc(entries.clone())),
        _ => None,
    }
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let request = Value::Object(ctx.detection_request(spec.harness));
    let found = crate::claude_code_detect::detect(&request).map(|mut answer| {
        // Claude's detection reports no warnings of its own.
        if let Some(answer) = answer.as_object_mut() {
            answer.remove("warnings");
        }
        answer
    });
    let available = which::resolve_command(ctx, spec.executable, &[candidate(ctx)]).is_some()
        || which::user_directory_command(ctx, spec.executable, &ctx.home, &[]).is_some();
    detection(spec, found, available)
}

/// `mark_missing_guard_hooks`: an "active" setup whose settings lost Guard's
/// entries is broken, since the launcher shim alone makes Guard look managed.
fn diagnostics(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    if fields.get("setup_status").and_then(Value::as_str) != Some("active") {
        return Ok(json!({ "update": "{}" }));
    }
    let contract = hook_contract()?;
    let path = settings_path(ctx);
    let payload = read_lenient(ctx, &path)?;
    let missing = missing_events(&contract, &settings::wire_object(&payload.entries))
        .map_err(|_| Failure::Refusal("Claude hook handler type is unhashable".to_owned()))?;
    if missing.is_empty() {
        return Ok(json!({ "update": "{}" }));
    }
    let mut warnings = fields
        .get("warnings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    warnings.push(json!(format!(
        "Managed Claude Code hooks are missing from {} ({}). Run `hol-guard repair` or \
         `hol-guard install claude-code` to restore protection.",
        path_text(&path),
        missing.join(", ")
    )));
    let update = json!({ "warnings": warnings, "setup_status": "broken" });
    Ok(json!({ "update": update.to_string() }))
}

/// The SessionStart and daemon hook argv, then every managed group synced.
fn synced(ctx: &Ctx, facts: &Facts, contract: &HookGroupsContract, hooks: &mut Doc) -> Step<()> {
    let session = argv::session_start_argv(ctx, facts, contract)?;
    let daemon = argv::daemon_argv(ctx, facts, contract)?;
    settings::sync(contract, hooks, &session, &daemon)
}

fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let contract = hook_contract()?;
    let path = settings_path(ctx);
    files::within_root(ctx, &ctx.home, &path, LABEL)?;
    let before = files::snapshot(ctx, &path)?;
    let mut payload = match &before {
        None => Object::default(),
        Some(bytes) => match Object::parse(&kimi::utf8(bytes.clone(), "Claude Code settings")?) {
            None => return Err(Failure::Refusal(NOT_JSON.to_owned())),
            Some(Err(())) => return Err(Failure::Refusal(NOT_OBJECT.to_owned())),
            Some(Ok(object)) => object,
        },
    };
    let facts = argv::facts(fields)?;
    let mut hooks = hooks_of(&payload).unwrap_or_default();
    synced(ctx, &facts, &contract, &mut hooks)?;
    payload.set("hooks", hooks.value());
    let after = payload.render()?.into_bytes();
    let mode = match before {
        Some(_) => files::mode(ctx, &path).ok_or_else(|| Failure::Os(path_text(&path)))?,
        None => 0o644,
    };
    let change = Change::at(ctx, &path, before, Some(after), mode);
    let mut notes = vec![files::text(INSTALL_NOTE)];
    if let Some(workspace) = &ctx.workspace {
        notes.push(files::text(format!(
            "Hooks are installed globally (not in {}/.claude); the workspace only scopes the \
             hook URL and Guard policy.",
            path_text(workspace)
        )));
    }
    let manifest = files::adapter_result(spec.harness, true, &path, &shim, notes);
    Ok(json!({
        "files": [change.wire()],
        "manifest": files::render(&manifest.value())?,
    }))
}

fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let contract = hook_contract()?;
    let path = settings_path(ctx);
    files::within_root(ctx, &ctx.home, &path, LABEL)?;
    let mut payload = read_lenient(ctx, &path)?;
    let mut writes = Vec::new();
    if let Some(mut hooks) = hooks_of(&payload) {
        settings::prune_events(&contract, &mut hooks, &UNINSTALL_EVENTS)?;
        settings::remove_unsupported(&contract, &mut hooks)?;
        payload.set("hooks", hooks.value());
        writes.push(json!({
            "path": path_text(&path),
            "text": payload.render()?,
            "parents": true,
        }));
    }
    Ok(json!({
        "writes": writes,
        "deletes": [],
        "finish": { "notes": [UNINSTALL_NOTE] },
    }))
}

/// `refresh_runtime_hook_urls`: rewrite Guard's entries with this build's
/// argv. `text` is `null` when the settings hold no hooks object.
fn refresh(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let contract = hook_contract()?;
    let path = settings_path(ctx);
    files::within_root(ctx, &ctx.home, &path, LABEL)?;
    let mut payload = read_lenient(ctx, &path)?;
    let Some(mut hooks) = hooks_of(&payload) else {
        return Ok(json!({ "path": path_text(&path), "text": null }));
    };
    let facts = argv::facts(fields)?;
    synced(ctx, &facts, &contract, &mut hooks)?;
    payload.set("hooks", hooks.value());
    Ok(json!({ "path": path_text(&path), "text": payload.render()? }))
}

/// One of the hook argv vectors, for the callers that still build it alone.
fn hook_argv(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let which = fields
        .get("which")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let contract = hook_contract()?;
    let facts = argv::facts(fields)?;
    let argv = match which {
        "hook" => argv::hook_argv(ctx, &facts)?,
        "daemon" => argv::daemon_argv(ctx, &facts, &contract)?,
        "session_start" => argv::session_start_argv(ctx, &facts, &contract)?,
        "python_session_start" => argv::python_session_start_argv(ctx, &facts, &contract)?,
        _ => return Err(Failure::Invalid),
    };
    Ok(json!({ "argv": argv }))
}

/// `_run_session_start_from_argv`'s path vector: the Guard home, the home,
/// then the workspace when the hooks were installed for one.
fn session_start(fields: &Map<String, Value>) -> Step<Value> {
    let argv = fields
        .get("argv")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|value| value.as_str().ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    if !(2..=3).contains(&argv.len())
        || argv
            .iter()
            .any(|value| value.is_empty() || value.contains('\0'))
    {
        return Err(Failure::Refusal(SESSION_START_ERROR.to_owned()));
    }
    Ok(json!({
        "guard_home": argv[0],
        "home": argv[1],
        "workspace": argv.get(2),
        "context": hook_contract()?.session_start_context,
    }))
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(&policy_path(ctx)),
        "resolved_executable" => resolved_executable(spec, ctx, &[candidate(ctx)]),
        "detect" => detect(spec, ctx),
        "diagnostics" => diagnostics(ctx, fields),
        "prepare_install" => prepare_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(ctx),
        "finish_uninstall" => files::finished(spec.harness, &settings_path(ctx), fields),
        "refresh" => refresh(ctx, fields),
        "argv" => hook_argv(ctx, fields),
        "session_start" => session_start(fields),
        _ => common(spec, op, ctx),
    }
}
