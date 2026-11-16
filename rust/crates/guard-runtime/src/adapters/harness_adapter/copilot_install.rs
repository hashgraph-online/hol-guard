//! Copilot's install and uninstall plans, under the lifecycle locks.
//!
//! `install_detection` answers the detection Python derives the managed
//! servers from, a digest of every file it read, and the proxy argv of each
//! Guard entry an MCP config already holds, so Python can relaunch it.
//! `prepare_install` refuses when the digest moved and plans the backup,
//! config and signed state of each MCP config, the CLI config's inline hooks
//! and the workspace hook file.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::copilot::{
    config_path, detect_sources, digest_path, global_mcp_path, hook_dir_files, hook_entry,
    hook_path, inline_hooks, parse_object, plan_hooks, scope_for, sources, target_mcp_paths,
    workspace_mcp_paths,
};
use super::copilot_mcp::{apply_plan, managed_servers, parsed_field, plan_servers, plan_targets};
use super::copilot_state::{self as state, Held};
use super::copilot_uninstall;
use super::files::{self, Change, Doc, Object};
use super::{path_text, Ctx, Failure, Spec, Step};
use crate::pyjson::{self, PyVal};

const KEY_FILE: &str = "adapter-state.key";

pub(super) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "install_detection" => match rebind_refusal(ctx, fields)? {
            Some(reason) => transition_error(reason),
            None => install_detection(spec, ctx),
        },
        "prepare_install" => match rebind_refusal(ctx, fields)? {
            Some(reason) => transition_error(reason),
            None => prepare_install(ctx, fields),
        },
        "uninstall" => copilot_uninstall::uninstall(ctx, fields),
        "finish_uninstall" => copilot_uninstall::finish_uninstall(ctx, fields),
        _ => Err(Failure::Invalid),
    }
}

/// The scope lock, then each config's lock.
pub(super) fn install_locks(ctx: &Ctx) -> Step<(Held, Vec<Held>)> {
    let scope = state::scope(ctx)?;
    Ok((scope, state::target_locks(ctx, &state::lock_paths(ctx))?))
}

/// Every file an install reads, with the bytes it held, and their digest.
struct Snapshot {
    contents: Vec<(PathBuf, Option<Vec<u8>>)>,
    digest: String,
}

impl Snapshot {
    fn take(ctx: &Ctx) -> Step<Self> {
        let mut paths = vec![config_path(ctx), global_mcp_path(ctx)];
        paths.extend(workspace_mcp_paths(ctx));
        paths.extend(hook_path(ctx));
        paths.extend(hook_dir_files(ctx));
        let mut contents: Vec<(PathBuf, Option<Vec<u8>>)> = Vec::new();
        let mut hasher = Sha256::new();
        for path in paths {
            if contents.iter().any(|(known, _)| *known == path) {
                continue;
            }
            let data = files::snapshot(ctx, &path)?;
            hasher.update(path_text(&path).as_bytes());
            hasher.update([0]);
            match &data {
                None => hasher.update([0]),
                Some(bytes) => {
                    hasher.update([1]);
                    hasher.update((bytes.len() as u64).to_le_bytes());
                    hasher.update(bytes);
                }
            }
            contents.push((path, data));
        }
        Ok(Self {
            contents,
            digest: hex::encode(hasher.finalize()),
        })
    }

    fn get(&self, path: &Path) -> Option<&[u8]> {
        self.contents
            .iter()
            .find(|(known, _)| known == path)
            .and_then(|(_, data)| data.as_deref())
    }

    fn text(&self, path: &Path, label: &str) -> Step<Option<String>> {
        self.get(path)
            .map(|bytes| super::kimi::utf8(bytes.to_vec(), label))
            .transpose()
    }

    /// The parsed JSON object a captured file holds, `{}` otherwise.
    fn object(&self, path: &Path, label: &str) -> Step<Object> {
        Ok(self
            .text(path, label)?
            .and_then(|text| parse_object(&text))
            .unwrap_or_default())
    }

    /// The `.github/hooks` files as the captured set lists them.
    fn hook_listing(&self, ctx: &Ctx) -> Vec<PathBuf> {
        let Some(hook) = hook_path(ctx) else {
            return Vec::new();
        };
        let mut listing: Vec<PathBuf> = self
            .contents
            .iter()
            .map(|(path, _)| path.clone())
            .filter(|path| {
                path.parent() == hook.parent() && path.extension().is_some_and(|ext| ext == "json")
            })
            .collect();
        listing.sort();
        listing
    }
}

/// `install_detection`: what Python derives the managed servers from.
fn install_detection(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let _locks = install_locks(ctx)?;
    let snapshot = Snapshot::take(ctx)?;
    let listing = snapshot.hook_listing(ctx);
    let mut answer = detect_sources(spec, ctx, &sources(ctx, &listing), Some(&snapshot.contents))?;
    let targets = target_mcp_paths(ctx)
        .into_iter()
        .map(|path| {
            Ok((
                path.clone(),
                snapshot.object(&path, "The Copilot MCP config")?,
            ))
        })
        .collect::<Step<Vec<_>>>()?;
    let (plans, _) = plan_targets(ctx, &targets, &[])?;
    let mut refresh = Vec::new();
    for ((_, payload), plan) in targets.iter().zip(&plans) {
        let servers = plan_servers(plan, payload)?;
        let mut rows = Vec::new();
        for row in plan["refresh"].as_array().ok_or(Failure::Invalid)? {
            let index = row[0]
                .as_u64()
                .map(|index| index as usize)
                .ok_or(Failure::Invalid)?;
            let config = servers
                .get(index)
                .and_then(|(_, config)| config.as_dict())
                .ok_or(Failure::Invalid)?;
            let env = ["env", "environment"]
                .iter()
                .find_map(|key| {
                    config
                        .iter()
                        .find(|(name, _)| name == key)
                        .filter(|(_, value)| value.as_dict().is_some())
                })
                .map_or(Some(json!({})), |(_, env)| env.to_json())
                .ok_or(Failure::Invalid)?;
            rows.push(json!([row[1], env]));
        }
        refresh.push(Value::Array(rows));
    }
    answer["digest"] = json!(snapshot.digest);
    answer["refresh"] = Value::Array(refresh);
    Ok(answer)
}

pub(super) fn rendered(value: &PyVal) -> Step<Vec<u8>> {
    Ok(format!("{}\n", files::render(value)?).into_bytes())
}

pub(super) fn rendered_object(payload: &Object) -> Step<Vec<u8>> {
    Ok(format!("{}\n", payload.render()?).into_bytes())
}

fn json_value(value: &Value) -> Step<PyVal> {
    pyjson::parse(&value.to_string()).map_err(|_| Failure::Invalid)
}

/// A planned file at its resolved path, written without following a link.
fn change(ctx: &Ctx, path: &Path, before: Option<Vec<u8>>, after: Vec<u8>) -> Change {
    let mode = before
        .as_ref()
        .and_then(|_| files::mode(ctx, path))
        .unwrap_or(0o600);
    let mut change = Change::at(ctx, path, before, Some(after), mode);
    change.no_follow = true;
    change
}

fn transition_error(reason: &str) -> Step<Value> {
    Ok(json!({ "transition_error": reason }))
}

fn create_key(fields: &Map<String, Value>) -> Step<bool> {
    fields
        .get("create_key")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)
}

/// A rebind keeps the installation's authority: without an enrolled key it
/// stops before any lock or file exists, as an installer must enroll first.
fn rebind_refusal(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Option<&'static str>> {
    if fields.get("create_key").is_none() || create_key(fields)? {
        return Ok(None);
    }
    let key = ctx.absolute(&ctx.guard_home.join("managed").join(KEY_FILE));
    if std::fs::symlink_metadata(&key).is_err() {
        return Ok(Some("adapter_preparation_authority_missing"));
    }
    let target = &target_mcp_paths(ctx)[0];
    let backup = digest_path(ctx, target, "backup");
    if state::state_payload(ctx, target, &backup, "global", false).is_err() {
        return Ok(Some("adapter_preparation_authority_invalid"));
    }
    Ok(None)
}

/// `prepare_install`: every file of the install, planned under the locks.
fn prepare_install(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let create_key = create_key(fields)?;
    let _locks = install_locks(ctx)?;
    let targets = target_mcp_paths(ctx);
    let snapshot = Snapshot::take(ctx)?;
    if fields.get("digest").and_then(Value::as_str) != Some(snapshot.digest.as_str()) {
        return Err(Failure::Integrity("target_changed"));
    }
    let config = config_path(ctx);
    files::within_root(ctx, &ctx.home, &config, "Copilot config")?;
    let mut config_payload = snapshot.object(&config, "The Copilot config")?;
    let mut hooks = inline_hooks(&mut config_payload);
    let hook = hook_path(ctx);
    let workspace_payload = match (&hook, &ctx.workspace) {
        (Some(hook), Some(workspace)) => {
            files::within_root(ctx, workspace, hook, "Copilot hook")?;
            Some(snapshot.object(hook, "The Copilot hook file")?)
        }
        _ => None,
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
    let managed = managed_servers(fields)?;
    let root = ctx.workspace.clone().unwrap_or_else(|| ctx.home.clone());
    let mut gathered = Vec::new();
    for target in &targets {
        files::within_root(ctx, &root, target, "Copilot MCP")?;
        let (backup, state_path) = (
            digest_path(ctx, target, "backup"),
            digest_path(ctx, target, "state"),
        );
        files::within_root(ctx, &ctx.guard_home, &backup, "Copilot backup")?;
        files::within_root(ctx, &ctx.guard_home, &state_path, "Copilot state")?;
        gathered.push((
            target.clone(),
            snapshot.object(target, "The Copilot MCP config")?,
        ));
    }
    let (plans, notes) = plan_targets(ctx, &gathered, &managed)?;
    let refresh = parsed_field(fields, "refresh")?;
    let refresh = refresh
        .as_list()
        .filter(|rows| rows.len() == targets.len())
        .ok_or(Failure::Invalid)?;
    for ((_, payload), (plan, launches)) in gathered.iter_mut().zip(plans.iter().zip(refresh)) {
        apply_plan(
            plan,
            payload,
            &managed,
            launches.as_list().ok_or(Failure::Invalid)?,
        )?;
    }
    let mut changes = Vec::new();
    let (mut backups, mut states) = (Vec::new(), Vec::new());
    for (target, payload) in &gathered {
        let (backup, state_path) = (
            digest_path(ctx, target, "backup"),
            digest_path(ctx, target, "state"),
        );
        let (backup_before, state_before) = (
            files::snapshot(ctx, &backup)?,
            files::snapshot(ctx, &state_path)?,
        );
        let state_read = state_before
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        let backup_after = if state::backup_reuse(ctx, target, &backup, &state_read)? {
            backup_before.clone().unwrap_or_default()
        } else {
            let original = snapshot.text(target, "The Copilot MCP config")?;
            let mut envelope = Doc::default();
            envelope
                .set("existed", PyVal::Bool(original.is_some()))
                .set("content", original.map_or(PyVal::Null, files::text));
            rendered(&envelope.value())?
        };
        let signed = state::state_payload(ctx, target, &backup, scope_for(ctx, target), create_key)
            .map_err(|reason| Failure::Os(reason.to_owned()))?;
        changes.push(change(ctx, &backup, backup_before, backup_after));
        changes.push(change(
            ctx,
            target,
            snapshot.get(target).map(<[u8]>::to_vec),
            rendered_object(payload)?,
        ));
        changes.push(change(
            ctx,
            &state_path,
            state_before,
            rendered(&json_value(&signed)?)?,
        ));
        backups.push(files::path_value(&backup));
        states.push(files::path_value(&state_path));
    }
    let hook_env = parsed_field(fields, "hook_env")?;
    config_plan.install(&mut hooks, &hook_entry(ctx, &config_plan, &hook_env));
    config_payload.set("hooks", PyVal::Dict(hooks));
    changes.push(change(
        ctx,
        &config,
        snapshot.get(&config).map(<[u8]>::to_vec),
        rendered_object(&config_payload)?,
    ));
    if let (Some(hook), Some((plan, mut normalized))) = (&hook, workspace_plan) {
        let mut hooks = normalized[1].1.as_dict().unwrap_or(&[]).to_vec();
        plan.install(&mut hooks, &hook_entry(ctx, &plan, &hook_env));
        normalized[1].1 = PyVal::Dict(hooks);
        changes.push(change(
            ctx,
            hook,
            snapshot.get(hook).map(<[u8]>::to_vec),
            rendered(&PyVal::Dict(normalized))?,
        ));
    }
    for (path, data) in &snapshot.contents {
        if !changes
            .iter()
            .any(|planned| planned.path == ctx.resolved(path))
        {
            let mode = data
                .as_ref()
                .and_then(|_| files::mode(ctx, path))
                .unwrap_or(0o600);
            changes.push(Change::at(ctx, path, data.clone(), data.clone(), mode));
        }
    }
    for (index, planned) in changes.iter().enumerate() {
        if changes[..index]
            .iter()
            .any(|earlier| earlier.path == planned.path && earlier.wire() != planned.wire())
        {
            return transition_error("adapter_preparation_generation_conflict");
        }
    }
    let mut seen: Vec<PathBuf> = Vec::new();
    changes.retain(|planned| {
        let fresh = !seen.contains(&planned.path);
        seen.push(planned.path.clone());
        fresh
    });
    let shim = files::shim_manifest(fields)?;
    let mut all_notes = notes;
    all_notes.extend(files::shim_notes(&shim));
    let skipped = parsed_field(fields, "skipped")?;
    let mut doc = Doc::default();
    doc.set("harness", files::text(super::copilot::HARNESS))
        .set("active", PyVal::Bool(true))
        .set("config_path", files::path_value(&config))
        .spread(&shim);
    paths_manifest(
        &mut doc,
        targets.iter().map(|path| files::path_value(path)).collect(),
        backups,
        states,
    );
    doc.set(
        "managed_servers",
        PyVal::List(
            managed
                .iter()
                .map(|row| files::text(row.0.clone()))
                .collect(),
        ),
    )
    .set("skipped_servers", skipped)
    .set("notes", PyVal::List(all_notes));
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": files::render(&doc.value())?,
    }))
}

/// The primary and full lists of the configs, backups and states.
pub(super) fn paths_manifest(
    doc: &mut Doc,
    targets: Vec<PyVal>,
    backups: Vec<PyVal>,
    states: Vec<PyVal>,
) {
    let first = |list: &[PyVal]| list.first().cloned().unwrap_or_else(|| files::text(""));
    doc.set("managed_config_path", first(&targets))
        .set("managed_config_paths", PyVal::List(targets))
        .set("backup_path", first(&backups))
        .set("backup_paths", PyVal::List(backups))
        .set("state_path", first(&states))
        .set("state_paths", PyVal::List(states));
}
