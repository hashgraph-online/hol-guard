//! The OpenCode adapter: its config paths, detection, uninstall plan and
//! manifests, and the runtime probe commands.
//!
//! OpenCode reads the global root config, an `OPENCODE_CONFIG` path and the
//! workspace's own config. Install always targets the global root config and
//! records a backup and a state file under the Guard home, keyed by the
//! resolved target path, so uninstall can put the user's config back. The
//! install plan lives in `opencode_install`; the update refresh and
//! protection checks in `opencode_checks`.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::files::{self, path_value, text, Doc};
use super::{detection, path_answer, path_text, Ctx, Failure, Spec, Step};
use crate::aibom_paths::py_path;
use crate::copilot_detect::{strip_jsonc, universal_newlines};
use crate::opencode_plugin_render::{dumps, dumps_unmapping};
use crate::pyjson::{self, PyVal, SurrogateMapped};

pub(super) const CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];
pub(super) const COMPANION_PREFIX: &str = "hol-guard::";
pub(super) const PROXY: &str = "opencode-mcp-proxy";
const PLUGIN_FILE: &str = "hol-guard-pretool.ts";
pub(super) const RUNTIME_ENV_VAR: &str = "OPENCODE_CONFIG_CONTENT";

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(&match &ctx.workspace {
            Some(workspace) => workspace.join(CONFIG_NAMES[0]),
            None => global_dir(ctx).join(CONFIG_NAMES[0]),
        }),
        "detect" => detect(spec, ctx),
        "install_detection" => super::opencode_install::install_detection(spec, ctx),
        "prepare_install" => super::opencode_install::prepare_install(ctx, fields),
        "prepare_uninstall" => prepare_uninstall(ctx),
        "finish_uninstall" => finish_uninstall(ctx, fields),
        "runtime_probe" => Ok(runtime_probe(spec, ctx)),
        "plugin_refresh" => super::opencode_checks::plugin_refresh(ctx, fields),
        "protection" => super::opencode_checks::protection(ctx, fields),
        "refresh_scan" => super::opencode_checks::refresh_scan(ctx),
        "refresh_apply" => super::opencode_checks::refresh_apply(ctx, fields),
        _ => super::common(spec, op, ctx),
    }
}

pub(super) fn global_dir(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".config").join("opencode")
}

/// `configured_config_path` / `configured_config_dir`: the variable, expanded
/// and anchored at the workspace or the working directory.
pub(super) fn configured(ctx: &Ctx, name: &str) -> Option<PathBuf> {
    let raw = ctx.env(name).filter(|raw| !raw.is_empty())?;
    let candidate = py_path(&path_text(&super::kimi::expand_user(ctx, raw)));
    if candidate.is_absolute() {
        return Some(candidate);
    }
    match (&ctx.workspace, &ctx.cwd) {
        (Some(workspace), _) => Some(workspace.join(candidate)),
        (None, Some(cwd)) => Some(cwd.join(candidate)),
        (None, None) => Some(candidate),
    }
}

/// `config_paths`: the global root configs, `OPENCODE_CONFIG`, then the
/// workspace configs, each once.
pub(super) fn config_paths(ctx: &Ctx) -> Vec<PathBuf> {
    let global = global_dir(ctx);
    let mut paths: Vec<PathBuf> = CONFIG_NAMES.iter().map(|name| global.join(name)).collect();
    paths.extend(configured(ctx, "OPENCODE_CONFIG"));
    if let Some(workspace) = &ctx.workspace {
        paths.extend(CONFIG_NAMES.iter().map(|name| workspace.join(name)));
    }
    let mut seen: Vec<String> = Vec::new();
    paths.retain(|path| {
        let key = path_text(path);
        let fresh = !seen.contains(&key);
        seen.push(key);
        fresh
    });
    paths
}

pub(super) fn scope_for(ctx: &Ctx, path: &Path) -> &'static str {
    match &ctx.workspace {
        Some(workspace) if path.starts_with(workspace) => "project",
        _ => "global",
    }
}

/// `_managed_install_config_path`: the global root config install targets.
pub(super) fn managed_config_path(ctx: &Ctx) -> PathBuf {
    let global = global_dir(ctx);
    CONFIG_NAMES
        .iter()
        .map(|name| global.join(name))
        .find(|path| ctx.absolute(path).is_file())
        .unwrap_or_else(|| global.join(CONFIG_NAMES[0]))
}

fn managed_dir(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("managed").join("opencode")
}

/// The backup or state file for `target`, named by its resolved path.
pub(super) fn digest_path(ctx: &Ctx, target: &Path, kind: &str) -> PathBuf {
    let digest = hex::encode(Sha256::digest(path_text(&ctx.resolved(target)).as_bytes()));
    managed_dir(ctx).join(format!("{}.{kind}.json", &digest[..12]))
}

pub(super) fn overlay_path(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("opencode").join("runtime-config.json")
}

pub(super) fn managed_plugin(ctx: &Ctx) -> PathBuf {
    ctx.guard_home
        .join("opencode")
        .join("plugins")
        .join(PLUGIN_FILE)
}

pub(super) fn global_plugin(ctx: &Ctx) -> PathBuf {
    global_dir(ctx).join("plugins").join(PLUGIN_FILE)
}

fn object(text: &str) -> Option<SurrogateMapped> {
    pyjson::parse_mapping_lone_surrogates(text)
        .ok()
        .filter(|parsed| matches!(parsed.value, PyVal::Dict(_)))
}

/// `_load_json_or_jsonc_text`: the config object, with comments stripped
/// first from a `.jsonc` file and as a retry from any other.
pub(super) fn load_text(path: &Path, text: &str) -> Option<SurrogateMapped> {
    let comments = text.contains("//") || text.contains("/*");
    let jsonc = path.extension().is_some_and(|ext| ext == "jsonc");
    if jsonc && comments {
        return object(&strip_jsonc(text));
    }
    if let Some(parsed) = object(text) {
        return Some(parsed);
    }
    if !comments {
        return None;
    }
    let stripped = strip_jsonc(text);
    (stripped != text).then(|| object(&stripped)).flatten()
}

/// `_load_json_or_jsonc(path)`: a fresh read in text mode.
pub(super) fn read_config(ctx: &Ctx, path: &Path) -> Option<SurrogateMapped> {
    let text = std::fs::read_to_string(ctx.absolute(path)).ok()?;
    load_text(path, &universal_newlines(text))
}

/// `json.dumps(payload)` of a parsed config.
pub(super) fn wire_payload(parsed: &SurrogateMapped) -> String {
    if parsed.mapped {
        dumps_unmapping(&parsed.value)
    } else {
        dumps(&parsed.value)
    }
}

/// The `opencode_detect` request for these `(path, scope, payload)` configs.
pub(super) fn detect_request(ctx: &Ctx, configs: &[(PathBuf, &str, String)], skip: bool) -> Value {
    let mut request = ctx.detection_request("opencode");
    let configs: Vec<Value> = configs
        .iter()
        .map(|(path, scope, payload)| {
            json!({ "path": path_text(path), "scope": scope, "payload": payload })
        })
        .collect();
    request.insert("configs".into(), json!(configs));
    request.insert("skip_verified_mcp_companions".into(), json!(skip));
    request.insert(
        "config_dir".into(),
        configured(ctx, "OPENCODE_CONFIG_DIR").map_or(Value::Null, |dir| json!(path_text(&dir))),
    );
    Value::Object(request)
}

pub(super) fn command_available(spec: &Spec, ctx: &Ctx) -> bool {
    super::which::command_available(ctx, spec.executable, Some(&ctx.home), &[])
}

/// `detect`: every readable, non-empty config as written. Python adds the
/// MCP skill firewall facts when the answer says `firewall`.
fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let configs: Vec<(PathBuf, &str, String)> = config_paths(ctx)
        .into_iter()
        .filter_map(|path| {
            let parsed = read_config(ctx, &path)?;
            let empty = parsed.value.as_dict().is_some_and(<[_]>::is_empty);
            if empty || (parsed.mapped && parsed.collision) {
                return None;
            }
            let payload = wire_payload(&parsed);
            Some((path.clone(), scope_for(ctx, &path), payload))
        })
        .collect();
    let found = crate::opencode_detect::detect(&detect_request(ctx, &configs, true));
    let mut answer = detection(spec, found, command_available(spec, ctx))?;
    answer["firewall"] = json!(true);
    Ok(answer)
}

fn runtime_probe(spec: &Spec, ctx: &Ctx) -> Value {
    if super::which::which(ctx, spec.executable).is_none() {
        return json!({ "commands": null });
    }
    let command = |sub: &str| json!([spec.executable, "debug", sub]);
    json!({ "commands": [["paths", command("paths")], ["config", command("config")]] })
}

/// One state file's string fields, as `load_string_state_payload` reads them.
fn state_fields(ctx: &Ctx, path: &Path) -> Vec<(String, String)> {
    let path = ctx.absolute(path);
    if !path.is_file() {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let Ok(PyVal::Dict(entries)) = pyjson::parse(&universal_newlines(text)) else {
        return Vec::new();
    };
    [
        "managed_config_path",
        "backup_path",
        "scope",
        "workspace_dir",
    ]
    .iter()
    .filter_map(|key| {
        let value = entries
            .iter()
            .rev()
            .find(|(name, _)| name == key)?
            .1
            .as_str()?;
        Some(((*key).to_owned(), value.to_owned()))
    })
    .collect()
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// `_state_entry`: the state recorded for this install, preferring the one
/// naming the managed target, then the only one for this workspace or the
/// only global one.
fn state_entry(ctx: &Ctx) -> (PathBuf, Vec<(String, String)>) {
    let target = managed_config_path(ctx);
    let preferred = digest_path(ctx, &target, "state");
    let mut names: Vec<PathBuf> = std::fs::read_dir(ctx.absolute(&managed_dir(ctx)))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".state.json"))
                .map(|entry| managed_dir(ctx).join(entry.file_name()))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let entries: Vec<(PathBuf, Vec<(String, String)>)> = names
        .into_iter()
        .map(|path| {
            let fields = state_fields(ctx, &path);
            (path, fields)
        })
        .filter(|(_, fields)| !fields.is_empty())
        .collect();
    let target_text = path_text(&target);
    if let Some(entry) = entries
        .iter()
        .find(|(_, fields)| field(fields, "managed_config_path") == Some(target_text.as_str()))
    {
        return entry.clone();
    }
    let (key, wanted) = match &ctx.workspace {
        Some(workspace) => ("workspace_dir", path_text(&ctx.resolved(workspace))),
        None => ("scope", "global".to_owned()),
    };
    let matching: Vec<_> = entries
        .into_iter()
        .filter(|(_, fields)| field(fields, key) == Some(wanted.as_str()))
        .collect();
    match <[_; 1]>::try_from(matching) {
        Ok([entry]) => entry,
        Err(_) => (preferred, Vec::new()),
    }
}

/// The saved config a backup envelope holds, as `restore_from_backup` reads it.
fn backup_plan(ctx: &Ctx, backup: &Path, target: &Path) -> Step<(Value, Option<String>)> {
    let envelope = match std::fs::read(ctx.absolute(backup)) {
        Err(_) => None,
        Ok(bytes) => {
            let text = super::kimi::utf8(bytes, "The OpenCode backup")?;
            match pyjson::parse_mapping_lone_surrogates(&universal_newlines(text)) {
                Ok(SurrogateMapped {
                    value: PyVal::Dict(entries),
                    mapped,
                    ..
                }) => Some((entries, mapped)),
                _ => None,
            }
        }
    };
    let content = envelope.as_ref().and_then(|(entries, mapped)| {
        let content = entries.iter().rev().find(|(key, _)| key == "content")?;
        content.1.as_str().map(|text| (text.to_owned(), *mapped))
    });
    let facts = envelope.as_ref().map(|(entries, _)| {
        let existed = entries
            .iter()
            .rev()
            .find(|(key, _)| key == "existed")
            .is_some_and(|(_, value)| matches!(value, PyVal::Bool(true)));
        json!({ "existed": existed, "has_content": content.is_some() })
    });
    let request = json!({
        "envelope": facts,
        "target_exists": ctx.absolute(target).is_file(),
    });
    let plan = crate::harness_backup_restore::dispatch(&request).map_err(|_| Failure::Invalid)?;
    if plan["action"] == "write"
        && content
            .as_ref()
            .is_some_and(|(text, mapped)| *mapped && text.chars().any(pyjson::in_surrogate_plane))
    {
        return Err(Failure::Refusal(
            "The OpenCode backup holds text that cannot be written as UTF-8.".into(),
        ));
    }
    Ok((plan, content.map(|(text, _)| text)))
}

/// `prepare_uninstall`: restore the backed-up config, then remove the
/// backup, the state and the pretool plugins.
fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let (state, fields) = state_entry(ctx);
    let target = field(&fields, "managed_config_path")
        .map_or_else(|| managed_config_path(ctx), PathBuf::from);
    let backup = field(&fields, "backup_path")
        .map_or_else(|| digest_path(ctx, &target, "backup"), PathBuf::from);
    let mut writes = Vec::new();
    let mut deletes = Vec::new();
    if ctx.absolute(&backup).is_file() {
        let (plan, content) = backup_plan(ctx, &backup, &target)?;
        match (plan["action"].as_str(), content) {
            (Some("write"), Some(text)) => writes.push(json!({
                "path": path_text(&target), "text": text, "mode": null, "parents": true,
            })),
            (Some("unlink"), _) => deletes.push(path_text(&target)),
            _ => {}
        }
        if plan["restored"] == true {
            deletes.push(path_text(&backup));
            if ctx.absolute(&state).is_file() {
                deletes.push(path_text(&state));
            }
        }
    }
    let plugins: Vec<String> = [global_plugin(ctx), managed_plugin(ctx)]
        .iter()
        .filter(|path| ctx.absolute(path).is_file())
        .map(|path| path_text(path))
        .collect();
    deletes.extend(plugins.iter().cloned());
    Ok(json!({
        "writes": writes,
        "deletes": deletes,
        "finish": {
            "plugins": plugins,
            "config_path": path_text(&target),
            "backup_path": path_text(&backup),
            "state_path": path_text(&state),
        },
    }))
}

fn finish_text<'a>(finish: &'a Value, key: &str) -> Step<&'a str> {
    finish[key].as_str().ok_or(Failure::Invalid)
}

fn finish_uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let finish = fields.get("finish").ok_or(Failure::Invalid)?;
    let plugins = finish["plugins"]
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|path| path.as_str().map(text).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    let target = finish_text(finish, "config_path")?;
    let mut notes = files::shim_notes(&shim);
    notes.push(text(
        "Guard removed the OpenCode pretool plugin from the global plugin directory.",
    ));
    notes.push(text(
        "Guard leaves the OpenCode runtime overlay on disk for auditability, but it is ignored \
         unless you launch through Guard.",
    ));
    let mut doc = Doc::default();
    doc.set("harness", text("opencode"))
        .set("active", PyVal::Bool(false))
        .set("config_path", text(target))
        .spread(&shim)
        .set("removed_plugin_paths", PyVal::List(plugins))
        .set("managed_config_path", text(target))
        .set("backup_path", text(finish_text(finish, "backup_path")?))
        .set("state_path", text(finish_text(finish, "state_path")?))
        .set("runtime_config_path", path_value(&overlay_path(ctx)))
        .set("runtime_env_var", text(RUNTIME_ENV_VAR))
        .set("notes", PyVal::List(notes));
    files::manifest_answer(doc)
}
