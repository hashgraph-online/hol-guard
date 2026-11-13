//! OpenCode checks outside install: whether the pretool plugin is current,
//! the protection checks `hol-guard doctor` reports, and the launcher
//! refresh `hol-guard update` runs over every config.
//!
//! The refresh rewrites only the `command` of each verified `hol-guard::`
//! companion whose Guard CLI prefix moved. Python computes the new argv
//! from the proxy arguments `refresh_scan` returns and holds the config lock
//! across both steps; `refresh_apply` scans again, makes the edits and
//! writes each changed config back in place, rolling back on failure.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, text, Doc};
use super::opencode::{
    config_paths, global_plugin, managed_config_path, managed_plugin, overlay_path, read_config,
    wire_payload, COMPANION_PREFIX, PROXY,
};
use super::{path_text, Ctx, Failure, Step};
use crate::copilot_detect::universal_newlines;
use crate::pyjson::{self, PyVal};

const MAX_CONFIG_BYTES: u64 = 1_000_000;
const CHANGED: &str = "OpenCode config changed during launcher refresh";
const INVALID_WARNING: &str =
    "An invalid OpenCode config was left unchanged; other configs were checked.";

fn render_plugin(fields: &Map<String, Value>) -> Step<String> {
    let plugin = fields.get("plugin").ok_or(Failure::Invalid)?;
    crate::opencode_plugin_render::render(plugin)
        .map_err(|error| {
            Failure::Refusal(format!(
                "Guard could not render the OpenCode plugin: {error}"
            ))
        })?
        .get("source")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::Refusal("Guard could not render the OpenCode plugin.".into()))
}

/// The text of an installed plugin, `""` when it is absent.
fn installed_text(ctx: &Ctx, path: &Path) -> Step<String> {
    match std::fs::read(ctx.absolute(path)) {
        Ok(bytes) => Ok(String::from_utf8(bytes)
            .map(universal_newlines)
            .unwrap_or_default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(Failure::Os(format!("{error}: '{}'", path_text(path)))),
    }
}

/// `plugin_refresh`: the plugin this Guard renders and whether both installed
/// copies already hold it.
pub(super) fn plugin_refresh(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let source = render_plugin(fields)?;
    let global = installed_text(ctx, &global_plugin(ctx))?;
    let managed = installed_text(ctx, &managed_plugin(ctx))?;
    Ok(json!({
        "current": global == source && managed == source,
        "source": source,
        "paths": [path_text(&managed_plugin(ctx)), path_text(&global_plugin(ctx))],
    }))
}

/// The `mcp` object of a readable config.
fn mcp_entries(ctx: &Ctx, path: &Path) -> Option<Vec<(String, PyVal)>> {
    if !ctx.absolute(path).is_file() {
        return None;
    }
    let parsed = read_config(ctx, path)?;
    parsed.value.get("mcp")?.as_dict().map(<[_]>::to_vec)
}

fn has_mcp(ctx: &Ctx, path: &Path) -> bool {
    mcp_entries(ctx, path).is_some_and(|mcp| !mcp.is_empty())
}

fn uses_proxy(command: Option<&PyVal>) -> bool {
    match command {
        Some(PyVal::List(parts)) => parts.iter().any(|part| {
            part.scalar_text()
                .unwrap_or_else(|| pyjson_text(part))
                .contains(PROXY)
        }),
        Some(PyVal::Str(command)) => command.contains(PROXY),
        _ => false,
    }
}

/// `str()` of a nested value, close enough to find the proxy name in it.
fn pyjson_text(value: &PyVal) -> String {
    crate::opencode_plugin_render::dumps(value)
}

/// `opencode_config_uses_guard_proxy`.
fn config_uses_proxy(ctx: &Ctx, path: &Path) -> bool {
    let Some(mcp) = mcp_entries(ctx, path) else {
        return false;
    };
    let servers: Vec<&(String, PyVal)> = mcp
        .iter()
        .filter(|(_, server)| matches!(server, PyVal::Dict(_)))
        .collect();
    let (companions, natives): (Vec<_>, Vec<_>) = servers
        .into_iter()
        .partition(|(name, _)| name.starts_with(COMPANION_PREFIX));
    if natives.is_empty() {
        return companions
            .iter()
            .any(|(_, server)| uses_proxy(server.get("command")));
    }
    natives.iter().all(|(name, server)| {
        uses_proxy(server.get("command"))
            || companions
                .iter()
                .find(|(companion, _)| *companion == format!("{COMPANION_PREFIX}{name}"))
                .is_some_and(|(_, companion)| uses_proxy(companion.get("command")))
    })
}

/// `_opencode_protection_checks`, given the store's managed flag and the
/// detection's config paths.
pub(super) fn protection(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let active = fields
        .get("managed_active")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)?;
    let detected = fields
        .get("config_paths")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    let config = managed_config_path(ctx);
    let shim = ctx.guard_home.join("bin").join("guard-opencode");
    let plugin = global_plugin(ctx);
    let mut loaded: Vec<PathBuf> = detected
        .iter()
        .filter_map(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| ctx.absolute(path).is_file())
        .collect();
    if loaded.is_empty() && ctx.absolute(&config).is_file() {
        loaded.push(config.clone());
    }
    let with_mcp: Vec<&PathBuf> = loaded.iter().filter(|path| has_mcp(ctx, path)).collect();
    let mut proxied =
        !with_mcp.is_empty() && with_mcp.iter().all(|path| config_uses_proxy(ctx, path));
    if !with_mcp.is_empty() && !proxied {
        let overlay = std::fs::read_to_string(ctx.absolute(&overlay_path(ctx)))
            .ok()
            .and_then(|overlay| pyjson::parse(&universal_newlines(overlay)).ok());
        let runtime = overlay
            .as_ref()
            .and_then(|overlay| overlay.get("mcp"))
            .and_then(PyVal::as_dict)
            .filter(|mcp| !mcp.is_empty());
        if let Some(runtime) = runtime {
            proxied = with_mcp.iter().all(|path| {
                mcp_entries(ctx, path)
                    .unwrap_or_default()
                    .iter()
                    .all(|(name, _)| {
                        name.starts_with(COMPANION_PREFIX)
                            || runtime.iter().any(|(key, _)| key == name)
                    })
            });
        }
    }
    let plugin_installed = ctx.absolute(&plugin).is_file();
    let shim_installed = ctx.absolute(&shim).is_file();
    let mut warnings = Vec::new();
    if !active {
        warnings.push(text(
            "Run `hol-guard install opencode` to activate Guard-managed OpenCode protection.",
        ));
    }
    if !plugin_installed {
        warnings.push(text(
            "OpenCode pretool plugin is missing from ~/.config/opencode/plugins/. Re-run `hol-guard \
             install opencode`.",
        ));
    }
    if !ctx.absolute(&config).is_file() {
        warnings.push(text(
            "OpenCode root config is missing at ~/.config/opencode/opencode.json. Re-run `hol-guard \
             install opencode`.",
        ));
    }
    if !with_mcp.is_empty() && !proxied {
        warnings.push(text(
            "OpenCode MCP servers are not routed through hol-guard companion servers or the runtime \
             overlay. Re-run `hol-guard install opencode`.",
        ));
    }
    if !shim_installed {
        warnings.push(text(format!(
            "guard-opencode launcher shim is missing. Add {} to PATH or launch with `hol-guard run \
             opencode` for pre-launch checks.",
            path_text(&ctx.guard_home.join("bin"))
        )));
    }
    let ready = warnings.is_empty();
    let mut checks = Doc::default();
    checks
        .set("pretool_plugin_installed", PyVal::Bool(plugin_installed))
        .set("mcp_proxy_configured", PyVal::Bool(proxied))
        .set("launch_shim_installed", PyVal::Bool(shim_installed))
        .set("managed_install_active", PyVal::Bool(active))
        .set("warnings", PyVal::List(warnings))
        .set("ready", PyVal::Bool(ready));
    Ok(json!({ "checks": files::render(&checks.value())? }))
}

/// One config the refresh may rewrite.
struct Scanned {
    path: PathBuf,
    before: Vec<u8>,
    text: String,
    mode: u32,
    /// `(name, current command, proxy args)` of each refreshable companion.
    companions: Vec<(String, Option<PyVal>, Vec<String>)>,
}

/// `_command_parts(entry)[1]`.
fn command_args(entry: &PyVal) -> Vec<String> {
    let strings = |items: &[PyVal]| -> Vec<String> {
        items
            .iter()
            .filter_map(PyVal::as_str)
            .map(str::to_owned)
            .collect()
    };
    match entry.get("command") {
        Some(PyVal::List(items)) => strings(items).into_iter().skip(1).collect(),
        Some(PyVal::Str(_)) => entry
            .get("args")
            .and_then(PyVal::as_list)
            .map(strings)
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

#[cfg(unix)]
fn owner_and_mode(meta: &std::fs::Metadata) -> (bool, u32) {
    use std::os::unix::fs::MetadataExt;
    let euid = nix::unistd::geteuid().as_raw();
    (meta.uid() == euid, meta.mode() & 0o7777)
}

#[cfg(not(unix))]
fn owner_and_mode(meta: &std::fs::Metadata) -> (bool, u32) {
    (
        true,
        if meta.permissions().readonly() {
            0o444
        } else {
            0o666
        },
    )
}

fn scan(ctx: &Ctx, warnings: &mut Vec<String>) -> Step<Vec<Scanned>> {
    let mut scanned = Vec::new();
    for path in config_paths(ctx) {
        let absolute = ctx.absolute(&path);
        let Ok(meta) = std::fs::symlink_metadata(&absolute) else {
            continue;
        };
        if meta.file_type().is_symlink() && !absolute.exists() {
            continue;
        }
        if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
            return Err(Failure::Refusal(
                "OpenCode config is not a bounded regular file".into(),
            ));
        }
        let (owned, mode) = owner_and_mode(&meta);
        if !owned {
            return Err(Failure::Refusal(
                "OpenCode config is owned by another user".into(),
            ));
        }
        let before = std::fs::read(&absolute).map_err(|error| Failure::Os(error.to_string()))?;
        let parsed = String::from_utf8(before.clone()).ok().and_then(|text| {
            let normalized = guard_command::jsonc::normalize_jsonc(&text).ok()?;
            let parsed = pyjson::parse_mapping_lone_surrogates(&normalized).ok()?;
            Some((text, parsed))
        });
        let Some((text, parsed)) = parsed else {
            warnings.push(INVALID_WARNING.to_owned());
            continue;
        };
        let Some(mcp) = parsed.value.as_dict().map(|_| parsed.value.get("mcp")) else {
            return Err(Failure::Refusal("OpenCode config must be an object".into()));
        };
        let Some(mcp) = mcp.and_then(PyVal::as_dict) else {
            continue;
        };
        let answer = super::opencode_install::normalize(
            ctx,
            &path,
            wire_payload(&parsed),
            Some("refreshable"),
        )?;
        let unreadable = || {
            Failure::Refusal(format!(
                "Could not read the OpenCode config at {}.",
                path_text(&path)
            ))
        };
        let names = match answer.as_object() {
            Some(fields) if fields.len() == 1 => fields.get("names").and_then(Value::as_str),
            _ => None,
        }
        .and_then(|names| pyjson::parse(names).ok())
        .ok_or_else(unreadable)?;
        let names = names.as_list().ok_or_else(unreadable)?;
        let mut companions = Vec::new();
        for name in names {
            let name = name.as_str().ok_or_else(unreadable)?;
            let Some(entry) = mcp
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, entry)| entry)
            else {
                continue;
            };
            if !matches!(entry, PyVal::Dict(_)) {
                continue;
            }
            let args = command_args(entry);
            let start = args
                .iter()
                .position(|arg| arg == PROXY)
                .ok_or_else(|| Failure::Refusal("tuple.index(x): x not in tuple".into()))?;
            companions.push((
                name.to_owned(),
                entry.get("command").cloned(),
                args[start..].to_vec(),
            ));
        }
        scanned.push(Scanned {
            path,
            before,
            text,
            mode,
            companions,
        });
    }
    Ok(scanned)
}

fn before_digest(before: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(before))
}

/// `refresh_scan`: each refreshable companion, the proxy arguments its new
/// command is built from and a digest of the config it was read from.
pub(super) fn refresh_scan(ctx: &Ctx) -> Step<Value> {
    let mut warnings = Vec::new();
    let candidates: Vec<Value> = scan(ctx, &mut warnings)?
        .iter()
        .flat_map(|config| {
            let digest = before_digest(&config.before);
            config.companions.iter().map(move |(name, _, args)| {
                json!({
                    "path": path_text(&config.path),
                    "name": name,
                    "proxy_args": args,
                    "digest": digest,
                })
            })
        })
        .collect();
    Ok(json!({ "candidates": candidates, "warnings": warnings }))
}

fn write_existing(ctx: &Ctx, path: &Path, before: &[u8], after: &[u8], mode: u32) -> Step<()> {
    let path = ctx.absolute(path);
    let unchanged =
        || !path.is_symlink() && std::fs::read(&path).is_ok_and(|bytes| bytes == before);
    if !unchanged() {
        return Err(Failure::Refusal(CHANGED.into()));
    }
    let parent = path.parent().ok_or(Failure::Invalid)?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let os = |error: std::io::Error| Failure::Os(error.to_string());
    let mut staged = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(os)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .map_err(os)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    staged.write_all(after).map_err(os)?;
    staged.flush().map_err(os)?;
    staged.as_file().sync_all().map_err(os)?;
    if !unchanged() {
        return Err(Failure::Refusal(CHANGED.into()));
    }
    staged.persist(&path).map_err(|error| os(error.error))?;
    Ok(())
}

/// `refresh_apply`: rewrite each companion whose command moved, given the
/// new commands Python built, and answer how many were refreshed.
pub(super) fn refresh_apply(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let raw = fields
        .get("commands")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let PyVal::List(commands) = pyjson::parse(raw).map_err(|_| Failure::Invalid)? else {
        return Err(Failure::Invalid);
    };
    let lookup = |path: &Path, name: &str| {
        commands.iter().find(|entry| {
            entry.get("path").and_then(PyVal::as_str) == Some(path_text(path).as_str())
                && entry.get("name").and_then(PyVal::as_str) == Some(name)
        })
    };
    let mut refreshed = 0usize;
    let mut writes = Vec::new();
    for config in scan(ctx, &mut Vec::new())? {
        let mut text = config.text.clone();
        let mut changed = false;
        let digest = before_digest(&config.before);
        for (name, current, _) in &config.companions {
            let entry = lookup(&config.path, name).ok_or(Failure::Integrity("target_changed"))?;
            // The config moved after the scan Python built these commands from.
            if entry.get("digest").and_then(PyVal::as_str) != Some(digest.as_str()) {
                return Err(Failure::Refusal(CHANGED.into()));
            }
            let command = entry.get("command").ok_or(Failure::Invalid)?;
            if current.as_ref() == Some(command) {
                continue;
            }
            let wire = command.to_json().ok_or(Failure::Invalid)?;
            let answer = crate::opencode_command_replace::dispatch(&json!({
                "text": text, "name": name, "command": wire,
            }))
            .map_err(|_| Failure::Refusal("OpenCode launcher refresh failed".into()))?;
            text = match (answer.get("text"), answer.get("reason")) {
                (Some(Value::String(replaced)), _) => replaced.clone(),
                (_, Some(Value::String(reason))) => return Err(Failure::Refusal(reason.clone())),
                _ => return Err(Failure::Refusal("OpenCode launcher refresh failed".into())),
            };
            refreshed += 1;
            changed = true;
        }
        if changed {
            writes.push((config.path, config.before, text.into_bytes(), config.mode));
        }
    }
    let mut applied: Vec<&(PathBuf, Vec<u8>, Vec<u8>, u32)> = Vec::new();
    for write in &writes {
        let (path, before, after, mode) = write;
        if let Err(error) = write_existing(ctx, path, before, after, *mode) {
            for (path, before, after, mode) in applied.iter().rev() {
                write_existing(ctx, path, after, before, *mode)?;
            }
            return Err(error);
        }
        applied.push(write);
    }
    Ok(json!({ "refreshed": refreshed }))
}
