//! Copilot's lifecycle locks and the authenticated state that binds each MCP
//! config Guard rewrote to the backup of what it held before.
//!
//! The locks serialize Guard operations that share one Guard home: a scope
//! lock around state discovery, then one lock per config in a stable order.
//! Editors and Copilot itself never take them.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde_json::{json, Map, Value};

use super::copilot::{digest_path, managed_dir, normcase, sha12, target_mcp_paths, HARNESS};
use super::files;
use super::{path_text, Ctx, Failure, Step};
use crate::adapter_state_integrity_op::{sign_state, state_field, state_verified};
use crate::aibom_paths::resolves_within_root;

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_POLL: Duration = Duration::from_millis(50);

fn os(message: &str) -> Failure {
    Failure::Os(message.to_owned())
}

fn lock_directory(ctx: &Ctx) -> Step<PathBuf> {
    let directory = managed_dir(ctx);
    files::within_root(ctx, &ctx.guard_home, &directory, "Copilot lifecycle lock")?;
    fs::create_dir_all(ctx.absolute(&directory)).map_err(|error| Failure::Os(error.to_string()))?;
    files::within_root(ctx, &ctx.guard_home, &directory, "Copilot lifecycle lock")?;
    let metadata = fs::symlink_metadata(ctx.absolute(&directory))
        .map_err(|_| os("Unable to validate the Copilot lifecycle lock directory."))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(os(
            "Copilot lifecycle lock directory is not a regular directory",
        ));
    }
    Ok(directory)
}

/// `normcase(str(target.resolve()))`, the key a lifecycle lock is named by.
fn canonical(ctx: &Ctx, target: &Path) -> String {
    normcase(&ctx.resolved(target))
}

#[cfg(unix)]
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (0, metadata.len())
}

fn lock_identity(path: &Path) -> Step<Option<(u64, u64)>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(os("Unable to inspect the Copilot lifecycle lock.")),
    };
    if metadata.file_type().is_symlink() {
        return Err(os("Copilot lifecycle lock must not be a symbolic link"));
    }
    if !metadata.is_file() {
        return Err(os("Copilot lifecycle lock is not a regular file"));
    }
    Ok(Some(identity(&metadata)))
}

fn open_lock(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

/// One held lifecycle lock; dropping it releases the lock.
pub(super) struct Held(#[allow(dead_code)] File);

/// `copilot_lifecycle_lock`: serialize one lifecycle path across processes.
pub(super) fn lock(ctx: &Ctx, target: &Path) -> Step<Held> {
    let name = format!("{}.lifecycle.lock", sha12(&canonical(ctx, target)));
    let path = ctx.absolute(&lock_directory(ctx)?.join(name));
    let prior = lock_identity(&path)?;
    let file = open_lock(&path).map_err(|error| Failure::Os(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| Failure::Os(error.to_string()))?;
    if !metadata.is_file() {
        return Err(os("Copilot lifecycle lock is not a regular file"));
    }
    let current = lock_identity(&path)?;
    if current != Some(identity(&metadata)) || prior.is_some_and(|prior| Some(prior) != current) {
        return Err(os("Copilot lifecycle lock changed while opening"));
    }
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let contended = fs2::lock_contended_error().raw_os_error();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(Held(file)),
            Err(error) if error.raw_os_error() == contended => {}
            Err(_) => return Err(os("Unable to acquire the Copilot lifecycle lock.")),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(os("Timed out waiting for the Copilot lifecycle lock."));
        }
        std::thread::sleep(LOCK_POLL.min(deadline - now));
    }
}

/// `copilot_lifecycle_scope`: serialize state discovery for one Guard home.
pub(super) fn scope(ctx: &Ctx) -> Step<Held> {
    lock(ctx, &managed_dir(ctx).join(".lifecycle.scope"))
}

/// `copilot_lifecycle_target_locks`: one lock per canonical path, in order.
pub(super) fn target_locks(ctx: &Ctx, targets: &[PathBuf]) -> Step<Vec<Held>> {
    let ordered: BTreeMap<String, &PathBuf> = targets
        .iter()
        .map(|target| (canonical(ctx, target), target))
        .collect();
    ordered.values().map(|target| lock(ctx, target)).collect()
}

/// The MCP configs, the CLI config and the workspace hook file.
pub(super) fn lock_paths(ctx: &Ctx) -> Vec<PathBuf> {
    let mut paths = target_mcp_paths(ctx);
    paths.push(super::copilot::config_path(ctx));
    paths.extend(super::copilot::hook_path(ctx));
    paths
}

fn key_home(ctx: &Ctx) -> PathBuf {
    ctx.absolute(&ctx.guard_home)
}

/// `authenticated_adapter_path`: the stored path, resolved, when the whole
/// payload authenticates.
fn authenticated_path(ctx: &Ctx, payload: &Value, field: &str) -> Option<PathBuf> {
    let value = state_field(&key_home(ctx), HARNESS, payload, field)?;
    let stored = PathBuf::from(value);
    stored.is_absolute().then(|| ctx.resolved(&stored))
}

/// `_json_payload`: the file's JSON object, `{}` otherwise.
fn json_payload(ctx: &Ctx, path: &Path) -> Value {
    fs::read(ctx.absolute(path))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn lifecycle_state(request: &Value) -> Step<Value> {
    crate::copilot_lifecycle_state::dispatch(request)
        .map_err(|_| Failure::Runtime("native_adapter_state_integrity_unavailable".to_owned()))
}

/// `copilot_state_authorizes_backup_reuse` for the state read as `payload`.
pub(super) fn backup_reuse(ctx: &Ctx, target: &Path, backup: &Path, payload: &Value) -> Step<bool> {
    let recorded: Vec<Option<String>> = ["managed_config_path", "backup_path"]
        .iter()
        .map(|field| authenticated_path(ctx, payload, field).map(|path| normcase(&path)))
        .collect();
    let request = json!({
        "action": "backup_reuse",
        "recorded": recorded,
        "expected": [normcase(&ctx.resolved(target)), normcase(&ctx.resolved(backup))],
        "backup": path_text(&ctx.absolute(backup)),
    });
    match lifecycle_state(&request)?["decision"].as_str() {
        Some("reuse") => Ok(true),
        Some("replace") => Ok(false),
        Some("refuse") => Err(Failure::Runtime(
            "Guard refused to overwrite an unreadable Copilot backup.".to_owned(),
        )),
        _ => Err(Failure::Refusal(
            "Copilot backup reuse answer is malformed".to_owned(),
        )),
    }
}

/// `copilot_state_payload`: the signed state binding `target` to `backup`.
pub(super) fn state_payload(
    ctx: &Ctx,
    target: &Path,
    backup: &Path,
    scope: &str,
    create_key: bool,
) -> Result<Value, &'static str> {
    let mut payload = Map::new();
    payload.insert(
        "managed_config_path".into(),
        json!(path_text(&ctx.resolved(target))),
    );
    payload.insert(
        "backup_path".into(),
        json!(path_text(&ctx.resolved(backup))),
    );
    payload.insert("scope".into(), json!(scope));
    payload.insert(
        "workspace_dir".into(),
        ctx.workspace.as_ref().map_or(Value::Null, |workspace| {
            json!(path_text(&ctx.resolved(workspace)))
        }),
    );
    sign_state(&key_home(ctx), HARNESS, payload, create_key)
}

/// One authenticated state file and the config and backup it binds.
pub(super) struct Entry {
    pub(super) state: PathBuf,
    pub(super) target: PathBuf,
    pub(super) backup: PathBuf,
    payload: Value,
}

/// `_state_targets`: each config a state file may name, with its source,
/// spellings and the root it must stay in.
fn state_targets(ctx: &Ctx, payload: &Value) -> Vec<(&'static str, Vec<String>, PathBuf, PathBuf)> {
    let global = super::copilot::global_mcp_path(ctx);
    let spellings = vec![path_text(&global), path_text(&ctx.resolved(&global))];
    let mut targets = vec![("global", spellings, global, ctx.home.clone())];
    let mut bases: Vec<(&'static str, PathBuf, PathBuf)> = Vec::new();
    if let Some(recorded) = authenticated_path(ctx, payload, "workspace_dir") {
        bases.push(("recorded", recorded.clone(), recorded));
    }
    if let Some(current) = &ctx.workspace {
        bases.push(("current", current.clone(), current.clone()));
        let resolved = ctx.resolved(current);
        if &resolved != current {
            bases.push(("current", resolved, current.clone()));
        }
    }
    for (source, base, root) in bases {
        for target in [
            base.join(".mcp.json"),
            base.join(".vscode").join("mcp.json"),
        ] {
            targets.push((source, vec![path_text(&target)], target, root.clone()));
        }
    }
    targets
}

fn within(ctx: &Ctx, root: &Path, path: &Path) -> bool {
    resolves_within_root(&ctx.absolute(root), &ctx.absolute(path), false)
}

/// `validated_copilot_state_entries`.
pub(super) fn state_entries(ctx: &Ctx) -> Step<Vec<Entry>> {
    let directory = managed_dir(ctx);
    files::within_root(ctx, &ctx.guard_home, &directory, "Copilot state")?;
    let mut paths: Vec<PathBuf> = fs::read_dir(ctx.absolute(&directory))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| directory.join(entry.file_name()))
                .filter(|path| path_text(path).ends_with(".state.json"))
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    let mut found = Vec::new();
    let mut requests = Vec::new();
    for state in paths {
        let payload = json_payload(ctx, &state);
        if !state_verified(&key_home(ctx), HARNESS, &payload) {
            continue;
        }
        let mut candidates = Vec::new();
        let mut named = Vec::new();
        for (source, spellings, target, root) in state_targets(ctx, &payload) {
            let (state_for, backup) = (
                digest_path(ctx, &target, "state"),
                digest_path(ctx, &target, "backup"),
            );
            let owned = [&state_for, &backup]
                .iter()
                .all(|path| within(ctx, &ctx.guard_home, path));
            candidates.push(json!({
                "source": source,
                "keys": spellings,
                "contained": within(ctx, &root, &target),
                "paths": {
                    "owned": owned,
                    "state": normcase(&ctx.resolved(&state_for)),
                    "backup": [path_text(&backup), path_text(&ctx.resolved(&backup))],
                },
            }));
            named.push((target, backup));
        }
        let fields = ["managed_config_path", "backup_path"]
            .map(|key| payload.get(key).cloned().unwrap_or(Value::Null));
        requests.push(json!({
            "state": normcase(&ctx.resolved(&state)),
            "fields": fields,
            "candidates": candidates,
        }));
        found.push((state, payload, named));
    }
    if found.is_empty() {
        return Ok(Vec::new());
    }
    let answer = lifecycle_state(&json!({ "action": "state_entries", "entries": requests }))?;
    let malformed = || Failure::Refusal("Copilot state entries answer is malformed".to_owned());
    let verdicts = answer["entries"]
        .as_array()
        .filter(|list| list.len() == found.len())
        .ok_or_else(malformed)?;
    let mut entries = Vec::new();
    for ((state, payload, mut named), verdict) in found.into_iter().zip(verdicts) {
        if verdict.is_null() {
            continue;
        }
        let index = verdict
            .as_u64()
            .map(|index| index as usize)
            .filter(|index| *index < named.len())
            .ok_or_else(malformed)?;
        let (target, backup) = named.swap_remove(index);
        entries.push(Entry {
            state,
            target,
            backup,
            payload,
        });
    }
    Ok(entries)
}

/// `_uninstall_targets`: the entries for the current configs, else the
/// current workspace's, else every entry when there is no workspace.
pub(super) fn uninstall_targets(ctx: &Ctx, entries: Vec<Entry>) -> Vec<Entry> {
    let current: Vec<String> = target_mcp_paths(ctx)
        .iter()
        .map(|path| path_text(&ctx.resolved(path)))
        .collect();
    let (exact, rest): (Vec<Entry>, Vec<Entry>) = entries
        .into_iter()
        .partition(|entry| current.contains(&path_text(&ctx.resolved(&entry.target))));
    if !exact.is_empty() {
        return exact;
    }
    let Some(workspace) = &ctx.workspace else {
        return rest;
    };
    let workspace = path_text(&ctx.resolved(workspace));
    rest.into_iter()
        .filter(|entry| {
            entry.payload.get("workspace_dir").and_then(Value::as_str) == Some(workspace.as_str())
        })
        .collect()
}

/// `write_text_at_authorized_path`: replace `path` atomically beneath its
/// resolved parent, never following a final link.
pub(super) fn write_authorized(ctx: &Ctx, path: &Path, bytes: &[u8]) -> Step<()> {
    let path = ctx.absolute(path);
    let failure = |error: std::io::Error| Failure::Os(error.to_string());
    let parent = path
        .parent()
        .ok_or_else(|| os("Copilot path has no parent directory"))?;
    fs::create_dir_all(parent).map_err(failure)?;
    let name = path
        .file_name()
        .ok_or_else(|| os("Copilot path has no file name"))?;
    let target = fs::canonicalize(parent).map_err(failure)?.join(name);
    super::authorized_write::write_beneath_parent(&target, bytes).map_err(failure)
}

/// `restore_from_backup`: put back what the backup holds; whether it did.
pub(super) fn restore(ctx: &Ctx, backup: &Path, target: &Path) -> Step<bool> {
    let (plan, content) = files::backup_plan(ctx, backup, target, "The Copilot backup")?;
    match (plan["action"].as_str(), content) {
        (Some("write"), Some(content)) => write_authorized(ctx, target, content.as_bytes())?,
        (Some("unlink"), _) => {
            fs::remove_file(ctx.absolute(target))
                .map_err(|error| Failure::Os(error.to_string()))?;
        }
        _ => {}
    }
    Ok(plan["restored"].as_bool() == Some(true))
}
