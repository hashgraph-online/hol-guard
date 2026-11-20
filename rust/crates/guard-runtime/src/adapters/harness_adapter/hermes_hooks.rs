//! Hermes's `hooks.pre_tool_call` entry in config.yaml and the
//! `shell-hooks-allowlist.json` approval beside it. Hermes only intercepts
//! tools through that entry, so the managed `pretool-hook.json` is unused
//! until it exists. The `hermes_hook_config` kind decides which entries and
//! approvals Guard owns; this module reads and rewrites the documents.

use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, text, Change, Doc, Object};
use super::{path_text, Ctx, Failure, Step};
use crate::hermes_inspect::{inspect_text_file, CONFIG_MAX_BYTES};
use crate::pyjson::{in_surrogate_plane, PyVal};

const PRETOOL_EVENT: &str = "pre_tool_call";
const GUARD_HOOK_ID: &str = "hol-guard-pretool";
const ALLOWLIST_NAME: &str = "shell-hooks-allowlist.json";
const ENTRY_FIELDS: [&str; 5] = ["id", "command", "matcher", "fail_closed", "failClosed"];
const APPROVAL_FIELDS: [&str; 2] = ["event", "command"];
const MALFORMED_ALLOWLIST: &str =
    "Hermes shell-hooks-allowlist.json is malformed; repair the file \
                                   so Guard can allowlist its pre_tool_call command.";
const MISSING_HOOK_COMMAND: &str =
    "Hermes Guard hook command is missing; runtime protection was not registered.";
const UNSAFE_ALLOWLIST: &str = "Hermes shell-hooks-allowlist.json must be a regular file directly \
                                under the selected Hermes home.";
const HOOKS_NOT_MAPPING: &str =
    "Hermes hooks config is not a mapping; runtime protection was not registered.";

fn hook_config(request: Value) -> Step<Value> {
    crate::hermes_hook_config::dispatch(&request).map_err(|_| Failure::Invalid)
}

/// `_wire`: each item as the kind reads it, only the fields ownership is
/// decided on. Text holding a lone surrogate never reaches the kind.
fn wire(items: &[PyVal], fields: &[&str], mapped: bool) -> Value {
    let wired = items.iter().map(|item| {
        let Some(entries) = item.as_dict() else {
            return Value::Null;
        };
        let mut projected = Map::new();
        for field in fields {
            match entries
                .iter()
                .find(|(key, _)| key == field)
                .map(|(_, value)| value)
            {
                Some(PyVal::Str(value)) if !(mapped && value.chars().any(in_surrogate_plane)) => {
                    projected.insert((*field).to_owned(), json!(value));
                }
                Some(PyVal::Bool(flag)) => {
                    projected.insert((*field).to_owned(), json!(flag));
                }
                _ => {}
            }
        }
        Value::Object(projected)
    });
    Value::Array(wired.collect())
}

/// `_kept`: the items the answer keeps, in strictly ascending order.
fn kept(items: &[PyVal], indices: Option<&Value>) -> Step<Vec<PyVal>> {
    let indices = indices.and_then(Value::as_array).ok_or(Failure::Invalid)?;
    let mut out = Vec::with_capacity(indices.len());
    let mut last: Option<usize> = None;
    for index in indices {
        let index = index.as_u64().and_then(|index| usize::try_from(index).ok());
        let index = index
            .filter(|index| *index < items.len())
            .ok_or(Failure::Invalid)?;
        if last.is_some_and(|last| last >= index) {
            return Err(Failure::Invalid);
        }
        last = Some(index);
        out.push(items[index].clone());
    }
    Ok(out)
}

fn entries(hooks: &[(String, PyVal)]) -> Vec<PyVal> {
    match hooks.iter().find(|(key, _)| key == PRETOOL_EVENT) {
        Some((_, PyVal::List(items))) => items.clone(),
        _ => Vec::new(),
    }
}

/// `_pretool_plan`: entries to keep and the commands of the Guard entries dropped.
fn pretool_plan(
    ctx: &Ctx,
    items: &[PyVal],
    expected: Option<&str>,
) -> Step<(Vec<PyVal>, Vec<String>)> {
    let cwd = expected
        .and(ctx.cwd.as_deref())
        .map_or(Value::Null, |cwd| json!(path_text(cwd)));
    let answer = hook_config(json!({
        "op": "pretool_plan",
        "entries": wire(items, &ENTRY_FIELDS, false),
        "expected_command": expected,
        "cwd": cwd,
    }))?;
    let removed = answer
        .get("removed")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|command| command.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    Ok((kept(items, answer.get("keep"))?, removed))
}

fn approvals(payload: &Object) -> Vec<PyVal> {
    match payload.entries.iter().find(|(key, _)| key == "approvals") {
        Some((_, PyVal::List(items))) => items.clone(),
        _ => Vec::new(),
    }
}

/// `_allowlist_plan`, written back into `payload`.
fn allowlist_plan(payload: &mut Object, command: &str, retire: &[String], mode: &str) -> Step<()> {
    let items = approvals(payload);
    let answer = hook_config(json!({
        "op": "allowlist_plan",
        "approvals": wire(&items, &APPROVAL_FIELDS, payload.mapped()),
        "command": command,
        "retire": retire,
        "mode": mode,
    }))?;
    let append = answer
        .get("append")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)?;
    let mut kept = kept(&items, answer.get("keep"))?;
    if append {
        let mut approval = Doc::default();
        approval
            .set("event", text(PRETOOL_EVENT))
            .set("command", text(command));
        kept.push(approval.value());
    }
    payload.set("approvals", PyVal::List(kept));
    Ok(())
}

/// `hermes_allowlist_path`: the fixed slot under the resolved Hermes home.
pub(super) fn allowlist_path(ctx: &Ctx, hermes_home: &Path) -> PathBuf {
    let mut components = hermes_home.components();
    let expanded = match components.next() {
        Some(Component::Normal(first)) if first == "~" => ctx.user_home.join(components.as_path()),
        _ => hermes_home.to_path_buf(),
    };
    ctx.resolved(&expanded).join(ALLOWLIST_NAME)
}

fn unsafe_destination(ctx: &Ctx, path: &Path) -> bool {
    let path = ctx.absolute(path);
    path.is_symlink() || (path.exists() && !path.is_file())
}

/// `_read_allowlist`: the payload with a list of approvals, or `None`.
fn read_allowlist(ctx: &Ctx, path: &Path) -> Option<Object> {
    let path = ctx.absolute(path);
    if path.is_symlink() {
        return None;
    }
    if !path.exists() {
        let mut empty = Object::default();
        empty.set("approvals", PyVal::List(Vec::new()));
        return Some(empty);
    }
    let scope = path.parent().unwrap_or(&path);
    let inspection = inspect_text_file(&path, Some(scope), Some(CONFIG_MAX_BYTES));
    let content = inspection.content.filter(|_| inspection.complete)?;
    let mut payload = Object::parse(&content)?.ok()?;
    match payload.entries.iter().find(|(key, _)| key == "approvals") {
        None | Some((_, PyVal::Null)) => payload.set("approvals", PyVal::List(Vec::new())),
        Some((_, PyVal::List(_))) => {}
        Some(_) => return None,
    }
    Some(payload)
}

fn allowlist_change(ctx: &Ctx, path: &Path, payload: &Object) -> Step<Change> {
    let before = files::snapshot(ctx, path)?;
    let before_mode = match before {
        Some(_) => files::mode(ctx, path).ok_or(Failure::Invalid)?,
        None => 0o600,
    };
    Ok(Change {
        path: path.to_path_buf(),
        before,
        after: Some(format!("{}\n", payload.render()?).into_bytes()),
        before_mode,
        after_mode: 0o600,
        no_follow: true,
    })
}

/// `sync_guard_runtime_hooks`: Guard's entry merged into `config`, and the
/// allowlist change that approves only Guard's command.
pub(super) fn sync(
    ctx: &Ctx,
    config: &mut Doc,
    argv: &[PyVal],
    hermes_home: &Path,
) -> Step<Change> {
    let parts: Vec<&str> = argv.iter().filter_map(PyVal::as_str).collect();
    if parts.is_empty() {
        return Err(Failure::Refusal(MISSING_HOOK_COMMAND.to_owned()));
    }
    let mut hooks = match config.0.iter().find(|(key, _)| key == "hooks") {
        None | Some((_, PyVal::Null)) => Vec::new(),
        Some((_, PyVal::Dict(hooks))) => hooks.clone(),
        Some(_) => return Err(Failure::Refusal(HOOKS_NOT_MAPPING.to_owned())),
    };
    let expected = crate::copilot_hook_config::shlex_join(&parts);
    let (mut preserved, removed) = pretool_plan(ctx, &entries(&hooks), Some(&expected))?;
    let mut entry = Doc::default();
    entry
        .set("id", text(GUARD_HOOK_ID))
        .set("matcher", text(".*"))
        .set("command", text(expected.clone()))
        .set(
            "timeout",
            PyVal::Int(super::hermes::HOOK_HOST_TIMEOUT_SECONDS.to_string()),
        )
        .set("fail_closed", PyVal::Bool(true));
    preserved.push(entry.value());
    let mut doc = Doc(std::mem::take(&mut hooks));
    doc.set(PRETOOL_EVENT, PyVal::List(preserved));
    config.set("hooks", doc.value());

    let path = allowlist_path(ctx, hermes_home);
    if unsafe_destination(ctx, &path) {
        return Err(Failure::Refusal(UNSAFE_ALLOWLIST.to_owned()));
    }
    let mut payload = read_allowlist(ctx, &path)
        .ok_or_else(|| Failure::Refusal(MALFORMED_ALLOWLIST.to_owned()))?;
    allowlist_plan(&mut payload, &expected, &removed, "merge")?;
    allowlist_change(ctx, &path, &payload)
}

/// `unsync_guard_runtime_hooks`: Guard's entries dropped from `config`, and
/// the allowlist text with their approvals removed, when it changes.
pub(super) fn unsync(
    ctx: &Ctx,
    config: &mut Doc,
    hermes_home: &Path,
) -> Step<Option<(PathBuf, String)>> {
    let Some(PyVal::Dict(hooks)) = config
        .0
        .iter()
        .find(|(key, _)| key == "hooks")
        .map(|(_, hooks)| hooks)
    else {
        return Ok(None);
    };
    let mut hooks = hooks.clone();
    let (preserved, removed) = pretool_plan(ctx, &entries(&hooks), None)?;
    if preserved.is_empty() {
        hooks.retain(|(key, _)| key != PRETOOL_EVENT);
        if hooks.is_empty() {
            config.0.retain(|(key, _)| key != "hooks");
        } else {
            config.set("hooks", PyVal::Dict(hooks));
        }
    } else {
        let mut doc = Doc(hooks);
        doc.set(PRETOOL_EVENT, PyVal::List(preserved));
        config.set("hooks", doc.value());
    }
    let path = allowlist_path(ctx, hermes_home);
    let mut payload: Option<Object> = None;
    for command in &removed {
        if unsafe_destination(ctx, &path) {
            return Err(Failure::Refusal(UNSAFE_ALLOWLIST.to_owned()));
        }
        if !ctx.absolute(&path).is_file() {
            continue;
        }
        let current = match payload.take() {
            Some(current) => Some(current),
            None => read_allowlist(ctx, &path),
        };
        let Some(mut current) = current else {
            continue;
        };
        allowlist_plan(&mut current, command, &[], "remove")?;
        payload = Some(current);
    }
    payload
        .map(|payload| Ok((path, format!("{}\n", payload.render()?))))
        .transpose()
}

/// `hermes_runtime_hook_registered` for the config.yaml at `config`.
pub(super) fn registered(ctx: &Ctx, config: &Path) -> bool {
    let absolute = ctx.absolute(config);
    if !absolute.is_file() {
        return false;
    }
    let Ok(inspection) =
        crate::hermes_inspect::inspect_config(&absolute, crate::hermes_inspect::Syntax::Yaml)
    else {
        return false;
    };
    let Some(payload) = inspection.payload.filter(|_| inspection.file.complete) else {
        return false;
    };
    let Some(PyVal::Dict(hooks)) = payload
        .iter()
        .find(|(key, _)| key == "hooks")
        .map(|(_, hooks)| hooks)
    else {
        return false;
    };
    let items = entries(hooks);
    if items.is_empty() {
        return false;
    }
    let home = config.parent().unwrap_or(config);
    let approvals = match read_allowlist(ctx, &allowlist_path(ctx, home)) {
        None => json!(false),
        Some(payload) => wire(&approvals(&payload), &APPROVAL_FIELDS, payload.mapped()),
    };
    hook_config(json!({
        "op": "registered",
        "entries": wire(&items, &ENTRY_FIELDS, false),
        "expected_command": null,
        "approvals": approvals,
    }))
    .ok()
    .and_then(|answer| answer.get("registered").and_then(Value::as_bool))
    .unwrap_or(false)
}
