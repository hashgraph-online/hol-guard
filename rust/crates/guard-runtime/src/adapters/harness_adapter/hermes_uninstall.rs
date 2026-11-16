//! `prepare_uninstall` and `finish_uninstall` for Hermes: the bundle files
//! to delete and the `config.yaml` and allowlist text with Guard's entries
//! taken out and the user's previous `guard` section put back.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, shim_notes, text};
use super::hermes::{self, HARNESS};
use super::{hermes_config, hermes_hooks, path_text, Ctx, Failure, Step};
use crate::adapter_state_integrity_op::state_field;
use crate::hermes_inspect::{inspect_config, Syntax};
use crate::pyjson::PyVal;

const MANAGED_LABEL: &str = "Hermes managed";
const REMOVED_NOTE: &str =
    "Guard removed the managed Hermes overlay bundle and cleaned Guard-managed entries from config.yaml.";

/// `authenticated_adapter_path`: the stored absolute path, resolved, when the
/// whole manifest authenticates.
fn authenticated_path(ctx: &Ctx, manifest: &Value, field: &str) -> Option<PathBuf> {
    let stored = PathBuf::from(state_field(
        &hermes::key_home(ctx),
        HARNESS,
        manifest,
        field,
    )?);
    stored.is_absolute().then(|| ctx.resolved(&stored))
}

/// `validated_hermes_config_path`: the authenticated `config.yaml`, or for an
/// unauthenticated manifest the current one when it stays in a home.
fn config_path(ctx: &Ctx, manifest: &Map<String, Value>, authenticated: bool) -> Option<PathBuf> {
    let home = hermes::hermes_home(ctx);
    if authenticated {
        let resolved = manifest
            .get("hermes_config_yaml_resolved_path")
            .and_then(Value::as_str)
            .filter(|path| !path.contains('\0'))?;
        let payload = Value::Object(manifest.clone());
        let candidate = authenticated_path(ctx, &payload, "hermes_config_yaml_path")?;
        let named = candidate
            .file_name()
            .is_some_and(|name| name == "config.yaml");
        return (path_text(&candidate) == resolved && named).then_some(candidate);
    }
    let candidate = home.join("config.yaml");
    let allowed = [&ctx.home, &home]
        .into_iter()
        .any(|root| files::within_root(ctx, root, &candidate, "Hermes config").is_ok());
    allowed.then_some(candidate)
}

/// `hermes_cleanup_values`: what an authentic manifest recorded, otherwise
/// what the config shows Guard generated.
fn cleanup_values(
    ctx: &Ctx,
    manifest_bytes: Option<&PyVal>,
    authenticated: bool,
    config: &Path,
) -> (Vec<String>, Option<PyVal>) {
    if !authenticated {
        return hermes_config::legacy_cleanup(ctx, config);
    }
    let field = |key: &str| manifest_bytes.and_then(|manifest| manifest.get(key));
    let names = field("managed_server_names")
        .and_then(PyVal::as_list)
        .map(|names| {
            names
                .iter()
                .filter_map(PyVal::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let previous = field("previous_guard_section")
        .filter(|section| section.as_dict().is_some())
        .cloned();
    (names, previous)
}

/// `_remove_guard_from_hermes_config_yaml`, as the texts to write.
fn rewrite(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    config: &Path,
    managed: &[String],
    previous: Option<PyVal>,
) -> Step<Vec<Value>> {
    if !ctx.absolute(config).exists() {
        return Ok(Vec::new());
    }
    let Ok(inspection) = inspect_config(&ctx.absolute(config), Syntax::Yaml) else {
        return Ok(Vec::new());
    };
    let Some(payload) = inspection.payload.filter(|_| inspection.file.complete) else {
        return Ok(Vec::new());
    };
    let mut raw = files::Doc(payload);
    let servers = raw
        .0
        .iter()
        .find(|(key, _)| key == "mcp_servers")
        .map(|(_, servers)| servers.clone());
    if let Some(PyVal::Dict(servers)) = servers {
        let names: Vec<&str> = servers.iter().map(|(name, _)| name.as_str()).collect();
        let answer = crate::hermes_install_plan::dispatch(
            &json!({"op": "servers", "names": names, "managed": managed, "overlay": []}),
        )
        .map_err(|_| Failure::Invalid)?;
        let mut kept = files::Doc::default();
        for index in answer
            .get("keep")
            .and_then(Value::as_array)
            .ok_or(Failure::Invalid)?
        {
            let index = index
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .ok_or(Failure::Invalid)?;
            let (name, config) = servers.get(index).ok_or(Failure::Invalid)?;
            kept.set(name, config.clone());
        }
        raw.set("mcp_servers", kept.value());
    }
    let home = config.parent().unwrap_or(config);
    let allowlist = hermes_hooks::unsync(ctx, &mut raw, home)?;
    match previous {
        Some(previous) => {
            raw.set("guard", previous);
        }
        None => raw.0.retain(|(key, _)| key != "guard"),
    }
    let rendered = hermes::yaml(fields, &raw.value())?;
    let mut writes = Vec::new();
    if let Some((path, text)) = allowlist {
        writes.push(json!({"path": path_text(&path), "text": text, "no_follow": true}));
    }
    let target = hermes::authorized(ctx, config);
    writes.push(json!({"path": path_text(&target), "text": rendered, "no_follow": true}));
    Ok(writes)
}

pub(super) fn prepare(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let root = hermes::managed_root(ctx);
    let (manifest, ordered) = hermes::manifest(ctx)?;
    let authenticated = hermes::verified(ctx, &manifest);
    let config = config_path(ctx, &manifest, authenticated);
    let (manifest_path, overlay_path, pretool_path) = hermes::bundle(ctx);
    let mut deletes = Vec::new();
    for path in [&overlay_path, &pretool_path, &manifest_path] {
        files::within_root(ctx, &root, path, MANAGED_LABEL)?;
        if ctx.absolute(path).exists() {
            deletes.push(path_text(path));
        }
    }
    let writes = match &config {
        None => Vec::new(),
        Some(config) => {
            let (managed, previous) = cleanup_values(ctx, ordered.as_ref(), authenticated, config);
            rewrite(ctx, fields, config, &managed, previous)?
        }
    };
    for name in ["managed-servers.json", "previous-guard-section.json"] {
        let path = root.join(name);
        if ctx.absolute(&path).exists() {
            deletes.push(path_text(&path));
        }
    }
    Ok(json!({"writes": writes, "deletes": deletes, "finish": {}}))
}

pub(super) fn finish(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let removed = fields
        .get("removed")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|path| path.as_str().map(text).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    let mut notes = vec![text(REMOVED_NOTE)];
    notes.extend(shim_notes(&shim));
    let mut doc = hermes::result_head(
        false,
        &hermes::managed_root(ctx).join("mcp-overlay.json"),
        &shim,
    );
    doc.set("removed_paths", PyVal::List(removed))
        .set("notes", PyVal::List(notes));
    files::manifest_answer(doc)
}
