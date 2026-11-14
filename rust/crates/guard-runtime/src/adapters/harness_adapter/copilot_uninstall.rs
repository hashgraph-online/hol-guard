//! Copilot's uninstall: restore each MCP config Guard backed up and drop
//! Guard's hook entries, written here because the lifecycle locks must cover
//! those writes, then the inactive manifest once Python removed the shim.

use std::path::PathBuf;

use serde_json::{json, Map, Value};

use super::copilot::{
    config_path, hook_path, inline_hooks, parse_object, plan_hooks, strict_object,
};
use super::copilot_install::{paths_manifest, rendered, rendered_object};
use super::copilot_state as state;
use super::files::{self, Doc, Object};
use super::{path_text, Ctx, Failure, Step};
use crate::pyjson::PyVal;

fn os_error(error: std::io::Error) -> Failure {
    Failure::Os(error.to_string())
}

/// `uninstall`: restore each recorded config, drop Guard's hook entries once
/// no state remains, and rewrite the hook files, all under the locks.
pub(super) fn uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let _scope = state::scope(ctx)?;
    let recorded = state::uninstall_targets(ctx, state::state_entries(ctx)?);
    let mut lock_paths = state::lock_paths(ctx);
    lock_paths.extend(recorded.iter().map(|entry| entry.target.clone()));
    let _targets = state::target_locks(ctx, &lock_paths)?;
    let config = config_path(ctx);
    let unreadable = || {
        Failure::Runtime(format!(
            "Guard refused to overwrite unreadable Copilot config at {}",
            path_text(&config)
        ))
    };
    let mut config_payload = if ctx.absolute(&config).is_file() {
        let bytes = std::fs::read(ctx.absolute(&config)).map_err(|_| unreadable())?;
        let text = super::kimi::utf8(bytes, "The Copilot config")?;
        parse_object(&text).ok_or_else(unreadable)?
    } else {
        Object::default()
    };
    let mut hooks = inline_hooks(&mut config_payload);
    let hook = hook_path(ctx).filter(|hook| ctx.absolute(hook).is_file());
    let workspace_payload = match &hook {
        Some(hook) => {
            let bytes = std::fs::read(ctx.absolute(hook)).ok();
            let text = bytes
                .map(|bytes| super::kimi::utf8(bytes, "The Copilot hook file"))
                .transpose()?;
            Some(text.map_or_else(Object::default, |text| strict_object(&text)))
        }
        None => None,
    };
    let config_argv = fields.get("config_argv").ok_or(Failure::Invalid)?;
    let workspace_argv = fields.get("workspace_argv").unwrap_or(&Value::Null);
    let (config_plan, workspace_plan) = plan_hooks(
        fields,
        (hooks.as_slice(), config_argv),
        workspace_payload
            .as_ref()
            .map(|payload| (payload, workspace_argv)),
    )?;
    for entry in &recorded {
        if !ctx.absolute(&entry.backup).is_file() {
            continue;
        }
        if state::restore(ctx, &entry.backup, &entry.target)? {
            std::fs::remove_file(ctx.absolute(&entry.backup)).map_err(os_error)?;
            if ctx.absolute(&entry.state).is_file() {
                std::fs::remove_file(ctx.absolute(&entry.state)).map_err(os_error)?;
            }
        }
    }
    if state::state_entries(ctx)?.is_empty() {
        config_plan.uninstall(&mut hooks);
        if hooks.is_empty() {
            config_payload.entries.retain(|(key, _)| key != "hooks");
        } else {
            config_payload.set("hooks", PyVal::Dict(hooks));
        }
    } else {
        config_payload.set("hooks", PyVal::Dict(hooks));
    }
    state::write_authorized(ctx, &config, &rendered_object(&config_payload)?)?;
    if let (Some(hook), Some((plan, mut normalized))) = (&hook, workspace_plan) {
        let mut hooks = normalized[1].1.as_dict().unwrap_or(&[]).to_vec();
        plan.uninstall(&mut hooks);
        if hooks.is_empty() {
            std::fs::remove_file(ctx.absolute(hook)).map_err(os_error)?;
        } else {
            normalized[1].1 = PyVal::Dict(hooks);
            state::write_authorized(ctx, hook, &rendered(&PyVal::Dict(normalized))?)?;
        }
    }
    let list = |paths: Vec<&PathBuf>| {
        paths
            .into_iter()
            .map(|path| json!(path_text(path)))
            .collect::<Vec<_>>()
    };
    Ok(json!({ "finish": {
        "managed_config_paths": list(recorded.iter().map(|entry| &entry.target).collect()),
        "backup_paths": list(recorded.iter().map(|entry| &entry.backup).collect()),
        "state_paths": list(recorded.iter().map(|entry| &entry.state).collect()),
    }}))
}

/// `finish_uninstall`: the inactive manifest once Python removed the shim.
pub(super) fn finish_uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let finish = fields.get("finish").ok_or(Failure::Invalid)?;
    let list = |key: &str| -> Step<Vec<PyVal>> {
        finish[key]
            .as_array()
            .ok_or(Failure::Invalid)?
            .iter()
            .map(|path| path.as_str().map(files::text).ok_or(Failure::Invalid))
            .collect()
    };
    let mut doc = Doc::default();
    doc.set("harness", files::text(super::copilot::HARNESS))
        .set("active", PyVal::Bool(false))
        .set("config_path", files::path_value(&config_path(ctx)))
        .spread(&shim);
    paths_manifest(
        &mut doc,
        list("managed_config_paths")?,
        list("backup_paths")?,
        list("state_paths")?,
    );
    let mut notes: Vec<PyVal> = [
        "Guard hook entries removed from ~/.copilot/config.json for Copilot CLI.",
        "Guard workspace hook entries removed from .github/hooks/hol-guard-copilot.json for VS Code Copilot.",
        "Guard restored the prior Copilot MCP config for the active Copilot surfaces.",
    ]
    .into_iter()
    .map(files::text)
    .collect();
    notes.extend(files::shim_notes(&shim));
    doc.set("notes", PyVal::List(notes));
    files::manifest_answer(doc)
}
