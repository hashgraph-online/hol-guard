//! Cline's MCP settings: the candidates, the proxy plan, the rewrite with its
//! restorable backup, the proxy state and the restore.
//!
//! Python builds each proxy launcher entry from the planned servers, so the
//! install is two asks: `mcp_scan` plans every settings file under the home
//! and `mcp_apply` rewrites the ones that still hold the bytes it planned.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::cline::{data_dir, managed_root, runtime, state_text, write_file};
use super::kimi::expand_user;
use super::{path_text, Ctx, Failure, Step};
use crate::hook_env_stamp::{dumps, set_member, write_string};
use crate::pyjson::{self, PyVal};

const SETTINGS: &str = "cline_mcp_settings.json";
const EXTENSION: [&str; 5] = [
    "Code",
    "User",
    "globalStorage",
    "saoudrizwan.claude-dev",
    "settings",
];
const PLAN_FAILED: &str = "Could not plan the Cline MCP proxy install.";
const FILE_MODE: u32 = 0o644;
/// Backups hold the original settings text, server secrets included.
const BACKUP_MODE: u32 = 0o600;

fn backup_root(ctx: &Ctx) -> PathBuf {
    managed_root(ctx).join("mcp-backups")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Current and legacy settings paths, first spelling wins.
pub(super) fn candidates(ctx: &Ctx) -> Step<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if let Some(explicit) = ctx
        .env("CLINE_MCP_SETTINGS_PATH")
        .map(crate::context_digest::python_strip)
        .filter(|value| !value.is_empty())
    {
        paths.push(ctx.absolute(&expand_user(ctx, explicit)));
    }
    let cline = data_dir(ctx)?;
    paths.push(cline.join("data").join("settings").join(SETTINGS));
    paths.push(cline.join("settings").join(SETTINGS));
    for base in [
        ctx.home.join("Library").join("Application Support"),
        ctx.home.join(".config"),
        ctx.home.join("AppData").join("Roaming"),
    ] {
        paths.push(
            EXTENSION
                .iter()
                .fold(base, |path, part| path.join(part))
                .join(SETTINGS),
        );
    }
    let mut unique: Vec<PathBuf> = Vec::new();
    for path in paths {
        if !unique
            .iter()
            .any(|seen| path_text(seen) == path_text(&path))
        {
            unique.push(path);
        }
    }
    Ok(unique)
}

/// The settings object of one file, or `None` when Python's `_json_object`
/// would answer `{}`.
fn settings(text: &str) -> Step<Option<Vec<(String, PyVal)>>> {
    let Ok(parsed) = pyjson::parse_mapping_lone_surrogates(text) else {
        return Ok(None);
    };
    match parsed.value {
        PyVal::Dict(entries) if entries.is_empty() => Ok(None),
        // A lone surrogate cannot be written back as Python spelled it.
        PyVal::Dict(_) if parsed.mapped || parsed.collision => Err(runtime(PLAN_FAILED)),
        PyVal::Dict(entries) => Ok(Some(entries)),
        _ => Ok(None),
    }
}

fn plan(text: &str) -> Step<Value> {
    let answer = crate::cline_install_plan::dispatch(&json!({"op": "mcp_proxy", "settings": text}))
        .map_err(|_| runtime(PLAN_FAILED))?;
    let plan = answer
        .get("plan")
        .and_then(Value::as_str)
        .and_then(|plan| serde_json::from_str::<Value>(plan).ok())
        .ok_or_else(|| runtime(PLAN_FAILED))?;
    if !matches!(
        plan.get("key").and_then(Value::as_str),
        Some("mcpServers" | "mcp")
    ) {
        return Err(runtime(PLAN_FAILED));
    }
    Ok(plan)
}

/// Every settings file under the home with servers to plan:
/// `{path, digest, key, managed, remote}`.
pub(super) fn scan(ctx: &Ctx) -> Step<Value> {
    let home = ctx.resolved(&ctx.home);
    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for path in candidates(ctx)? {
        let resolved = ctx.resolved(&path);
        // Two spellings of one file plan it once, so the rewrite sees its digest.
        if !path.is_file() || !resolved.starts_with(&home) || !seen.insert(resolved) {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes.clone()) else {
            continue;
        };
        if settings(&text)?.is_none() {
            continue;
        }
        let plan = plan(&text)?;
        found.push(json!({
            "path": path_text(&path),
            "digest": sha256_hex(&bytes),
            "key": plan["key"],
            "managed": plan["managed"],
            "remote": plan["remote"],
        }));
    }
    Ok(json!({ "candidates": found }))
}

/// `json.dumps(value, sort_keys=True)`: the default `", "` and `": "`.
fn spaced(value: &PyVal, out: &mut String) {
    match value {
        PyVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                spaced(item, out);
            }
            out.push(']');
        }
        PyVal::Dict(entries) => {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by(|left, right| left.0.cmp(&right.0));
            out.push('{');
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_string(key, true, false, out);
                out.push_str(": ");
                spaced(item, out);
            }
            out.push('}');
        }
        scalar => dumps(scalar, true, false, out),
    }
}

fn backup_text(entries: Vec<(String, PyVal)>) -> String {
    let mut text = String::new();
    spaced(&PyVal::Dict(entries), &mut text);
    text.push('\n');
    text
}

fn backup_path(ctx: &Ctx, path: &Path) -> PathBuf {
    let digest = sha256_hex(path_text(&ctx.resolved(path)).as_bytes());
    backup_root(ctx).join(format!("{}.json", &digest[..16]))
}

fn rewrite(ctx: &Ctx, entry: &Value, replacements: Vec<(String, PyVal)>) -> Step<String> {
    let path = PathBuf::from(entry["path"].as_str().ok_or(Failure::Invalid)?);
    let key = entry["key"].as_str().ok_or(Failure::Invalid)?;
    let original = fs::read(&path).map_err(|error| Failure::Os(error.to_string()))?;
    if entry["digest"].as_str() != Some(sha256_hex(&original).as_str()) {
        return Err(Failure::Integrity("target_changed"));
    }
    let text = String::from_utf8(original.clone()).map_err(|_| runtime(PLAN_FAILED))?;
    let mut payload = settings(&text)?.ok_or(Failure::Integrity("target_changed"))?;
    let backup = backup_path(ctx, &path);
    if !backup.exists() {
        let record = vec![
            ("schema_version".to_owned(), PyVal::Int("1".to_owned())),
            ("config_path".to_owned(), PyVal::Str(path_text(&path))),
            (
                "original_sha256".to_owned(),
                PyVal::Str(sha256_hex(&original)),
            ),
            ("original_text".to_owned(), PyVal::Str(text)),
            ("managed_sha256".to_owned(), PyVal::Null),
        ];
        write_file(&backup, backup_text(record).as_bytes(), BACKUP_MODE)?;
    }
    let mut servers = match payload.iter().find(|(name, _)| name == key) {
        Some((_, PyVal::Dict(servers))) => servers.clone(),
        _ => Vec::new(),
    };
    for (name, server) in replacements {
        set_member(&mut servers, &name, server);
    }
    set_member(&mut payload, key, PyVal::Dict(servers));
    let mut managed = super::files::render(&PyVal::Dict(payload))?;
    managed.push('\n');
    let mode = super::files::mode(ctx, &path).unwrap_or(FILE_MODE);
    write_file(&path, managed.as_bytes(), mode)?;
    let mut record = match state_text(&backup).map(|text| pyjson::parse(&text)) {
        Some(Ok(PyVal::Dict(record))) => record,
        _ => Vec::new(),
    };
    set_member(
        &mut record,
        "managed_sha256",
        PyVal::Str(sha256_hex(managed.as_bytes())),
    );
    write_file(&backup, backup_text(record).as_bytes(), BACKUP_MODE)?;
    Ok(path_text(&path))
}

fn names(value: &Value) -> Step<Vec<String>> {
    value
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|name| name.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

fn sorted_unique(mut names: Vec<String>) -> Vec<String> {
    names.sort();
    names.dedup();
    names
}

/// Rewrite each planned file with Python's proxy entries for its servers.
pub(super) fn apply(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let entries: Value = fields
        .get("entries")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or(Failure::Invalid)?;
    let mut changed = Vec::new();
    let mut managed = Vec::new();
    let mut remote = Vec::new();
    for entry in entries.as_array().ok_or(Failure::Invalid)? {
        remote.extend(names(&entry["remote"])?);
        let text = entry["replacements"].as_str().ok_or(Failure::Invalid)?;
        let Ok(PyVal::Dict(replacements)) = pyjson::parse(text) else {
            return Err(Failure::Invalid);
        };
        if replacements.is_empty() {
            continue;
        }
        managed.extend(replacements.iter().map(|(name, _)| name.clone()));
        changed.push(rewrite(ctx, entry, replacements)?);
    }
    Ok(json!({
        "changed_config_paths": changed,
        "managed_servers": sorted_unique(managed),
        "skipped_remote_servers": sorted_unique(remote),
        "backup_root": path_text(&backup_root(ctx)),
    }))
}

fn backups(ctx: &Ctx) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(backup_root(ctx)) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|suffix| suffix == "json"))
        .collect();
    found.sort();
    found
}

fn record(path: &Path) -> Map<String, Value> {
    match state_text(path).map(|text| serde_json::from_str::<Value>(&text)) {
        Some(Ok(Value::Object(record))) => record,
        _ => Map::new(),
    }
}

fn current_sha(path: &Path) -> Option<String> {
    path.is_file()
        .then(|| fs::read(path).ok())
        .flatten()
        .map(|bytes| sha256_hex(&bytes))
}

pub(super) fn state(ctx: &Ctx) -> Value {
    let mut configs = Vec::new();
    let mut ready = true;
    for backup in backups(ctx) {
        let record = record(&backup);
        let config = record.get("config_path").cloned().unwrap_or(Value::Null);
        let current = config
            .as_str()
            .and_then(|path| current_sha(Path::new(path)));
        let managed = record.get("managed_sha256").and_then(Value::as_str);
        let matched = managed.is_some() && current.as_deref() == managed;
        ready &= matched;
        configs.push(json!({"config_path": config, "managed_integrity_ok": matched}));
    }
    json!({"configured": !configs.is_empty(), "ready": ready, "configs": configs})
}

/// Put back every original Guard still owns; a file changed since is kept.
pub(super) fn restore(ctx: &Ctx) -> Step<Value> {
    let mut restored = Vec::new();
    let mut retained = Vec::new();
    for backup in backups(ctx) {
        let record = record(&backup);
        let (Some(config), Some(original)) = (
            record.get("config_path").and_then(Value::as_str),
            record.get("original_text").and_then(Value::as_str),
        ) else {
            retained.push(path_text(&backup));
            continue;
        };
        let path = Path::new(config);
        if path.is_file() {
            let managed = record.get("managed_sha256").and_then(Value::as_str);
            let Ok(bytes) = fs::read(path) else {
                retained.push(config.to_owned());
                continue;
            };
            if managed != Some(sha256_hex(&bytes).as_str()) {
                retained.push(config.to_owned());
                continue;
            }
        }
        let mode = super::files::mode(ctx, path).unwrap_or(FILE_MODE);
        write_file(path, original.as_bytes(), mode)?;
        restored.push(config.to_owned());
        fs::remove_file(&backup).map_err(|error| Failure::Os(error.to_string()))?;
    }
    if retained.is_empty() {
        let _ = fs::remove_dir(backup_root(ctx));
    }
    Ok(json!({
        "restored": restored,
        "retained_modified": retained,
        "complete": retained.is_empty(),
    }))
}
