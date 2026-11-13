//! Grok's install and uninstall plans: the two hook files, Guard's settings
//! in `.grok/config.toml`, the retired legacy block in `managed_config.toml`,
//! their backups and the install state. `grok_user_config` merges and removes
//! the TOML settings; this module snapshots the files and builds the plan.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, path_value, render, text, Change, Doc};
use super::grok::{
    backup_path, config_path, grok_home, hooks_dir, legacy_path, observe_hook, pretool_hook,
    state_path, PRETOOL_FILE, PROMPT_FILE,
};
use super::kimi::{hook_command, utf8};
use super::{path_text, Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

const LABEL: &str = "Grok";
const STATE_NOT_OBJECT: &str = "Grok managed state must be a JSON object.";
const USER_CONFIG_MALFORMED: &str = "Grok user config answer is malformed";
const LEGACY_MALFORMED: &str = "Grok legacy settings answer is malformed";
const STATE_KEYS: [&str; 5] = [
    "added_deny_rules",
    "added_hook_events",
    "created_keys",
    "hook_command",
    "prior_compat_hooks",
];
const MISSING_OWNERSHIP_NOTE: &str = "Guard settings may remain in .grok/config.toml because \
                                      ownership records are missing; review them manually.";

/// `parse_install_state`: the recorded state, `{}` when there is none.
fn install_state(bytes: Option<&[u8]>) -> Step<Vec<(String, PyVal)>> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let refused = || Failure::Refusal(STATE_NOT_OBJECT.to_owned());
    let raw = std::str::from_utf8(bytes).map_err(|_| refused())?;
    match crate::pyjson::parse(raw) {
        Ok(PyVal::Dict(entries)) => Ok(entries),
        _ => Err(refused()),
    }
}

fn state_field<'a>(state: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    state
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// The recorded `user_config_settings`, when it is an object.
fn owned_settings(state: &[(String, PyVal)]) -> Option<Value> {
    match state_field(state, "user_config_settings") {
        Some(settings @ PyVal::Dict(_)) => settings.to_json(),
        _ => None,
    }
}

/// `grok_user_config`, raising its refusal as Python's `ValueError`.
fn user_config(request: Value) -> Step<Map<String, Value>> {
    let answer = crate::grok_user_config_op::dispatch(&request).map_err(|_| Failure::Invalid)?;
    let Value::Object(answer) = answer else {
        return Err(Failure::Invalid);
    };
    match answer.get("error") {
        Some(Value::String(message)) if answer.len() == 1 => Err(Failure::Refusal(message.clone())),
        Some(_) => Err(Failure::Refusal(USER_CONFIG_MALFORMED.to_owned())),
        None => Ok(answer),
    }
}

/// `remove_legacy_settings`: Guard's block out of the legacy managed config,
/// with the compatibility hooks it replaced restored in recorded order.
fn legacy_settings(raw: Option<&[u8]>, state: &[(String, PyVal)]) -> Step<Option<Vec<u8>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let pairs: Vec<Value> = match state_field(state, "prior_compat_hooks") {
        Some(PyVal::Dict(entries)) => entries
            .iter()
            .map(|(key, value)| json!([key, value.to_json()]))
            .collect(),
        _ => Vec::new(),
    };
    let request = json!({
        "text": utf8(raw.to_vec(), "Grok legacy settings")?,
        "prior_compat_hooks": pairs,
    });
    let answer = crate::grok_legacy_settings::dispatch(&request).map_err(|_| Failure::Invalid)?;
    match answer.as_object() {
        Some(fields) if fields.len() == 1 => fields
            .get("text")
            .and_then(Value::as_str)
            .map(|text| Some(text.as_bytes().to_vec()))
            .ok_or_else(|| Failure::Refusal(LEGACY_MALFORMED.to_owned())),
        _ => Err(Failure::Refusal(LEGACY_MALFORMED.to_owned())),
    }
}

fn hook_paths(ctx: &Ctx) -> (PathBuf, PathBuf) {
    let hooks = hooks_dir(ctx);
    (hooks.join(PRETOOL_FILE), hooks.join(PROMPT_FILE))
}

fn guard_settings_paths(ctx: &Ctx) -> Step<(PathBuf, PathBuf)> {
    let (config, legacy) = (config_path(ctx), legacy_path(ctx));
    files::within_root(ctx, &grok_home(ctx), &config, LABEL)?;
    files::within_root(ctx, &grok_home(ctx), &legacy, LABEL)?;
    Ok((config, legacy))
}

/// The recorded install state, as Python's dict holds it.
type State = Vec<(String, PyVal)>;

/// The config text and recorded settings both phases of a merge read.
fn merge_inputs(ctx: &Ctx, config: &Path) -> Step<(String, Value, State)> {
    let existing = match files::snapshot(ctx, config)? {
        Some(bytes) => utf8(bytes, "Grok config")?,
        None => String::new(),
    };
    let state = install_state(files::snapshot(ctx, &state_path(ctx))?.as_deref())?;
    let previous = owned_settings(&state).unwrap_or_else(|| json!({}));
    Ok((existing, previous, state))
}

/// Generated hook clients the user config still names; Python keeps the ones
/// whose client no longer exists and sends them back as `retired_commands`.
pub(super) fn hook_candidates(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let (config, _) = guard_settings_paths(ctx)?;
    let (existing, previous, _) = merge_inputs(ctx, &config)?;
    let answer = user_config(json!({
        "existing_text": existing,
        "previous_state": previous,
        "mode": "candidates",
    }))?;
    match answer.get("commands") {
        Some(Value::Array(commands)) if commands.iter().all(Value::is_string) => Ok(json!({
            "hook_command": hook_command(ctx, fields)?,
            "commands": commands,
        })),
        _ => Err(Failure::Refusal(USER_CONFIG_MALFORMED.to_owned())),
    }
}

/// `mode` of an existing file, else the default.
fn existing_mode(ctx: &Ctx, path: &Path, before: Option<&Vec<u8>>, default: u32) -> Step<u32> {
    match before {
        Some(_) => files::mode(ctx, path).ok_or(Failure::Invalid),
        None => Ok(default),
    }
}

fn hook_json(value: &PyVal) -> Step<Vec<u8>> {
    Ok(format!("{}\n", render(value)?).into_bytes())
}

pub(super) fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let (config, legacy) = guard_settings_paths(ctx)?;
    let command = hook_command(ctx, fields)?;
    let retired = fields
        .get("retired_commands")
        .and_then(Value::as_array)
        .filter(|commands| commands.iter().all(Value::is_string))
        .ok_or(Failure::Invalid)?;
    let (pretool, prompt) = hook_paths(ctx);
    let state = state_path(ctx);
    let paths = [
        config.clone(),
        pretool.clone(),
        prompt.clone(),
        state.clone(),
        legacy,
    ];
    let snapshots = paths
        .iter()
        .map(|path| files::snapshot(ctx, path))
        .collect::<Step<Vec<_>>>()?;
    let (existing, previous, recorded) = merge_inputs(ctx, &config)?;
    let merged = user_config(json!({
        "existing_text": existing,
        "previous_state": previous,
        "hook_command": command,
        "mode": "merge",
        "retired_commands": retired,
    }))?;
    let owned = match merged.get("state") {
        Some(Value::Object(owned))
            if owned.len() == STATE_KEYS.len()
                && STATE_KEYS.iter().all(|key| owned.contains_key(*key)) =>
        {
            crate::pyjson::parse(&Value::Object(owned.clone()).to_string())
                .map_err(|_| Failure::Invalid)?
        }
        _ => return Err(Failure::Refusal(USER_CONFIG_MALFORMED.to_owned())),
    };
    let merged_text = merged
        .get("merged")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::Refusal(USER_CONFIG_MALFORMED.to_owned()))?;
    let mut record = Doc::default();
    record
        .set("managed_config_path", path_value(&config))
        .set("pretool_hook_path", path_value(&pretool))
        .set("prompt_hook_path", path_value(&prompt))
        .set("user_config_settings", owned);
    let after = [
        Some(merged_text.as_bytes().to_vec()),
        Some(hook_json(&pretool_hook(&command))?),
        Some(hook_json(&observe_hook(&command))?),
        Some(hook_json(&record.value())?),
        legacy_settings(snapshots[4].as_deref(), &recorded)?,
    ];
    let mut changes = Vec::new();
    for (path, source) in paths.iter().zip(&snapshots).take(3) {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let backup = backup_path(ctx, &name.unwrap_or_default());
        let before = files::snapshot(ctx, &backup)?;
        let mode = existing_mode(ctx, &backup, before.as_ref(), 0o644)?;
        let after_mode = match (&before, source) {
            (None, Some(_)) => files::mode(ctx, path).ok_or(Failure::Invalid)?,
            _ => mode,
        };
        let restored = before.clone().or_else(|| source.clone());
        let mut change = Change::at(ctx, &backup, before, restored, mode);
        change.after_mode = after_mode;
        changes.push(change);
    }
    for ((path, before), after) in paths.iter().zip(snapshots).zip(after) {
        let mode = existing_mode(ctx, path, before.as_ref(), 0o644)?;
        changes.push(Change::at(ctx, path, before, after, mode));
    }
    let mut notes: Vec<PyVal> = [
        "Guard catch-all PreToolUse hook installed in .grok/hooks/hol-guard-pretooluse.json",
        "Guard prompt screening and lifecycle observation hooks installed",
        "Guard permission rules and backup hooks installed in .grok/config.toml",
    ]
    .into_iter()
    .map(text)
    .collect();
    notes.extend(files::shim_notes(&shim));
    let mut manifest = Doc::default();
    manifest
        .set("harness", text(spec.harness))
        .set("active", PyVal::Bool(true))
        .spread(&shim)
        .set("config_path", path_value(&config))
        .set("managed_config_path", path_value(&config))
        .set("managed_hooks_path", path_value(&pretool))
        .set("pretool_hook_path", path_value(&pretool))
        .set("prompt_hook_path", path_value(&prompt))
        .set(
            "protection_artifact_paths",
            PyVal::List(vec![
                path_value(&config),
                path_value(&pretool),
                path_value(&prompt),
            ]),
        )
        .set("notes", PyVal::List(notes));
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": render(&manifest.value())?,
    }))
}

/// `str.rstrip()`: Python's whitespace includes the separators U+001C-U+001F.
fn python_rstrip(value: &str) -> &str {
    value.trim_end_matches(|character: char| {
        character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
    })
}

/// `uninstall_settings` and the hook restores: Guard's settings out of both
/// configs, each hook file back from its backup or removed, then the state.
pub(super) fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let state_file = state_path(ctx);
    let state = if ctx.absolute(&state_file).is_file() {
        let bytes = std::fs::read(ctx.absolute(&state_file))
            .map_err(|error| Failure::Os(error.to_string()))?;
        install_state(Some(&bytes))?
    } else {
        Vec::new()
    };
    let read = |path: &Path| {
        std::fs::read(ctx.absolute(path)).map_err(|error| Failure::Os(error.to_string()))
    };
    let config = config_path(ctx);
    let owned = owned_settings(&state);
    let config_present = ctx.absolute(&config).is_file();
    let mut notes = Vec::new();
    let mut writes = Vec::new();
    match owned {
        None if config_present => notes.push(MISSING_OWNERSHIP_NOTE),
        Some(owned) if config_present => {
            files::within_root(ctx, &grok_home(ctx), &config, LABEL)?;
            let answer = user_config(json!({
                "existing_text": utf8(read(&config)?, "Grok config")?,
                "mode": "remove",
                "previous_state": owned,
            }))?;
            let restored = answer
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| Failure::Refusal(USER_CONFIG_MALFORMED.to_owned()))?;
            let restored = format!("{}\n", python_rstrip(restored));
            writes.push(json!({"path": path_text(&config), "text": restored, "raw": true}));
        }
        _ => {}
    }
    let legacy = legacy_path(ctx);
    if ctx.absolute(&legacy).is_file() {
        files::within_root(ctx, &grok_home(ctx), &legacy, LABEL)?;
        let before = read(&legacy)?;
        if let Some(after) = legacy_settings(Some(&before), &state)? {
            if after != before {
                let after = utf8(after, "Grok legacy settings")?;
                writes.push(json!({"path": path_text(&legacy), "text": after, "raw": true}));
            }
        }
    }
    let mut copies = Vec::new();
    let mut deletes = Vec::new();
    let (pretool, prompt) = hook_paths(ctx);
    for (hook, name) in [(pretool, PRETOOL_FILE), (prompt, PROMPT_FILE)] {
        let backup = backup_path(ctx, name);
        if ctx.absolute(&backup).is_file() {
            copies.push(json!({"from": path_text(&backup), "to": path_text(&hook)}));
        } else if ctx.absolute(&hook).is_file() {
            deletes.push(path_text(&hook));
        }
    }
    if ctx.absolute(&state_file).is_file() {
        deletes.push(path_text(&state_file));
    }
    let mut finish = vec![
        "Guard hook files and launcher removed.",
        "User .grok/config.toml, auth, skills, plugins, and sessions were preserved.",
    ];
    finish.extend(notes);
    Ok(json!({
        "writes": writes,
        "copies": copies,
        "deletes": deletes,
        "finish": {"notes": finish},
    }))
}
