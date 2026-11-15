//! Cline's native hooks: the install, the integrity and live-proof state and
//! the bounded synthetic canary.
//!
//! The canary runs Guard's own PreToolUse launcher, so Python runs it: an op
//! that needs it answers `{"canary": {"argv", "input"}}` and Python asks again
//! with `canary: {"returncode", "stdout", "error"}`. The launcher, worker and
//! proof files and the state record are read and written here.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::cline::{managed_root, paths, runtime, state_text, write_file, Need, Read};
use super::{path_text, Ctx, Failure, Step};
use crate::hook_env_stamp::write_string;

pub(super) const MARKER: &str = "HOL_GUARD_MANAGED_CLINE_HOOK_V1";
const SCHEMA: u64 = 1;
const EVENTS: [&str; 6] = [
    "PreToolUse",
    "PostToolUse",
    "UserPromptSubmit",
    "TaskStart",
    "TaskError",
    "SessionShutdown",
];
const PROOF_EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];
const LAUNCHER_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o644;

fn state_path(ctx: &Ctx) -> PathBuf {
    managed_root(ctx).join("native-hooks-state.json")
}

fn proof_path(ctx: &Ctx, event: &str) -> PathBuf {
    managed_root(ctx)
        .join("proofs")
        .join(format!("native-{}.json", event.to_lowercase()))
}

fn worker_path(ctx: &Ctx, event: &str) -> PathBuf {
    managed_root(ctx)
        .join("hook-workers")
        .join(format!("{event}.json"))
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// A regular file, not a symlink, whose UTF-8 text carries `marker`.
pub(super) fn managed(path: &Path, marker: &str) -> bool {
    path.is_file()
        && !is_symlink(path)
        && fs::read_to_string(path).is_ok_and(|text| text.contains(marker))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The recorded state, or an empty object when it is missing or not one.
fn load_state(text: Option<&str>) -> Map<String, Value> {
    match text.map(serde_json::from_str::<Value>) {
        Some(Ok(Value::Object(state))) => state,
        _ => Map::new(),
    }
}

/// The recorded string paths of one group, or `None` when it is not an object.
fn recorded(state: &Map<String, Value>, key: &str) -> Value {
    match state.get(key) {
        Some(Value::Object(group)) => Value::Object(
            group
                .iter()
                .filter(|(_, path)| path.is_string())
                .map(|(event, path)| (event.clone(), path.clone()))
                .collect(),
        ),
        _ => Value::Null,
    }
}

/// The launcher and worker paths recorded at install that still bind to
/// their slots, as `cline_paths` binds them.
fn bound(ctx: &Ctx, state: &Map<String, Value>) -> Step<(Map<String, Value>, Map<String, Value>)> {
    let (launchers, workers) = (recorded(state, "paths"), recorded(state, "workers"));
    if launchers.is_null() && workers.is_null() {
        return Ok((Map::new(), Map::new()));
    }
    let root = state.get("root").filter(|root| root.is_string());
    let mut extra = Map::new();
    extra.insert("paths".into(), launchers);
    extra.insert("workers".into(), workers);
    extra.insert("root".into(), root.cloned().unwrap_or(Value::Null));
    let answer = paths(ctx, "state_paths", extra)?;
    let group = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_object)
            .cloned()
            .ok_or(Failure::Invalid)
    };
    Ok((group("paths")?, group("workers")?))
}

fn bound_path(group: &Map<String, Value>, event: &str) -> Option<PathBuf> {
    group.get(event).and_then(Value::as_str).map(PathBuf::from)
}

fn observed(path: Option<PathBuf>) -> Value {
    let Some(path) = path else {
        return Value::Null;
    };
    match fs::read(&path) {
        Ok(bytes) => json!({"sha256": sha256_hex(&bytes), "managed": managed(&path, MARKER)}),
        Err(_) => Value::Null,
    }
}

/// The argv that runs one hook without resolving an interpreter from `PATH`.
fn hook_command(path: &Path) -> Vec<String> {
    let script = path
        .extension()
        .and_then(|suffix| suffix.to_str())
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case("ps1"));
    if !script {
        return vec![path_text(path)];
    }
    match crate::windows_trusted_directories::windows_powershell() {
        Some(shell) => vec![shell, "-NoProfile".into(), "-File".into(), path_text(path)],
        None => Vec::new(),
    }
}

/// `json.dumps` of the synthetic read the canary sends.
fn canary_input(ctx: &Ctx) -> String {
    let root = path_text(ctx.workspace.as_deref().unwrap_or(&ctx.home));
    let mut input = String::from(
        "{\"hookName\": \"PreToolUse\", \"taskId\": \"hol-guard-cline-canary\", \"workspaceRoots\": [",
    );
    write_string(&root, true, false, &mut input);
    input.push_str(
        "], \"preToolUse\": {\"toolName\": \"read_files\", \"parameters\": {\"paths\": \"[]\"}}}",
    );
    input
}

fn refused(reason: &str) -> Value {
    json!({"ok": false, "reason": reason})
}

/// The verdict on one canary run: it exited 0 and answered an object whose
/// `cancel` is a boolean.
pub(super) fn judged(run: &Value) -> Step<Value> {
    let run = run.as_object().ok_or(Failure::Invalid)?;
    if let Some(error) = run.get("error").and_then(Value::as_str) {
        return Ok(refused(error));
    }
    let stdout = run.get("stdout").and_then(Value::as_str).unwrap_or("");
    let Ok(output) = serde_json::from_str::<Value>(crate::context_digest::python_strip(stdout))
    else {
        return Ok(refused("JSONDecodeError"));
    };
    let exited = run.get("returncode").and_then(Value::as_i64) == Some(0);
    let cancel = output.get("cancel").is_some_and(Value::is_boolean);
    Ok(json!({ "ok": exited && output.is_object() && cancel }))
}

/// The canary verdict over the bound PreToolUse launcher, asking Python to
/// run it when no run came with the request.
fn canary(ctx: &Ctx, launchers: &Map<String, Value>, run: Option<&Value>) -> Read<Value> {
    let Some(path) = bound_path(launchers, "PreToolUse").filter(|path| managed(path, MARKER))
    else {
        return Ok(refused("pretool_hook_missing"));
    };
    let argv = hook_command(&path);
    if argv.is_empty() {
        return Ok(refused("hook_interpreter_not_available"));
    }
    match run {
        Some(run) => Ok(judged(run)?),
        None => Err(Need::Canary(
            json!({"argv": argv, "input": canary_input(ctx)}),
        )),
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// The installed, integrity and live-proof state; with `run` given or asked
/// for, the canary decides `ready` over intact files.
pub(super) fn state(ctx: &Ctx, check: bool, run: Option<&Value>) -> Read<Value> {
    let text = state_text(&state_path(ctx));
    let recorded = load_state(text.as_deref());
    let (launchers, workers) = bound(ctx, &recorded)?;
    let per_event = |group: &Map<String, Value>| -> Map<String, Value> {
        EVENTS
            .iter()
            .map(|event| ((*event).to_owned(), observed(bound_path(group, event))))
            .collect()
    };
    let proofs: Map<String, Value> = PROOF_EVENTS
        .iter()
        .map(|event| {
            let text = state_text(&proof_path(ctx, event));
            ((*event).to_owned(), text.map_or(Value::Null, Value::from))
        })
        .collect();
    let request = json!({
        "op": "state",
        "now": now(),
        "state_text": text,
        "launchers": per_event(&launchers),
        "workers": per_event(&workers),
        "proofs": proofs,
    });
    let answer = crate::cline_hook_files::dispatch(&request).map_err(|_| Failure::Invalid)?;
    let mut verdict = answer.get("state").cloned().ok_or(Failure::Invalid)?;
    if check && answer.get("canary") == Some(&Value::Bool(true)) {
        let ok = canary(ctx, &launchers, run)?.get("ok") == Some(&Value::Bool(true));
        let ready = verdict.get("ready") == Some(&Value::Bool(true));
        verdict["synthetic_canary_ok"] = json!(ok);
        verdict["ready"] = json!(ready && ok);
    }
    Ok(verdict)
}

/// Remove the managed hooks still bound to their slots.
pub(super) fn uninstall(ctx: &Ctx) -> Step<Value> {
    paths(ctx, "uninstall", Map::new())
}

fn string_list(value: Option<&Value>) -> Step<Vec<String>> {
    value
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|part| part.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

/// Cline's slot for one event, refusing to replace a user hook.
fn claim(root: &Path, slot: &str, event: &str) -> Step<PathBuf> {
    if matches!(slot, "" | "." | "..") || slot.contains(['/', '\\']) {
        return Err(Failure::Invalid);
    }
    let path = root.join(slot);
    if path.exists() && !managed(&path, MARKER) {
        return Err(runtime(format!(
            "Cline already has a user-owned {event} hook in {}; Guard will not overwrite it",
            root.display()
        )));
    }
    Ok(path)
}

fn checked(ctx: &Ctx, path: &Path) -> Step<()> {
    let mut extra = Map::new();
    extra.insert("path".into(), json!(path_text(path)));
    paths(ctx, "check", extra).map(|_| ())
}

/// Write every event's worker and launcher, then the state record; the
/// manifest carries everything but the canary verdict, and the probe is the
/// canary Python runs or the verdict when it cannot run.
pub(super) fn install(ctx: &Ctx, facts: &Map<String, Value>) -> Read<Value> {
    if facts.get("python") != Some(&Value::Bool(true)) {
        return Err(
            runtime("Cline native hooks require a standalone Python Guard runtime.").into(),
        );
    }
    let Some(bridge) = facts.get("runtime").and_then(Value::as_str) else {
        return Err(runtime("Cline native hooks require the HOL Guard native runtime.").into());
    };
    let guard_cli = string_list(facts.get("hook_argv"))?;
    let roots = paths(ctx, "roots", Map::new())?;
    let root = roots
        .get("hook_roots")
        .and_then(Value::as_array)
        .and_then(|roots| roots.first())
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(Failure::Invalid)?;
    let events: Map<String, Value> = EVENTS
        .iter()
        .map(|event| {
            let paths = json!({
                "worker": path_text(&worker_path(ctx, event)),
                "proof": path_text(&proof_path(ctx, event)),
            });
            ((*event).to_owned(), paths)
        })
        .collect();
    let request = json!({
        "op": "render",
        "windows": ctx.windows,
        "runtime": bridge,
        "guard_cli": guard_cli,
        "adapter_state": path_text(&managed_root(ctx).join("adapter-state.json")),
        "events": events,
    });
    let rendered = crate::cline_hook_files::dispatch(&request)
        .map_err(|error| Failure::Runtime(format!("Cline native hook files failed: {error}")))?;
    let mut launchers = Map::new();
    let mut digests = Map::new();
    let mut workers = Map::new();
    let mut worker_digests = Map::new();
    let field = |event: &str, key: &str| {
        rendered["files"][event]
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(Failure::Invalid)
    };
    // Claim every slot before writing any, so a user hook in a later slot
    // leaves no earlier launcher behind without its state record.
    let mut slots = Vec::new();
    for event in EVENTS {
        let slot = claim(&root, &field(event, "slot")?, event)?;
        let worker = worker_path(ctx, event);
        checked(ctx, &slot)?;
        checked(ctx, &worker)?;
        slots.push((event, slot, worker));
    }
    for (event, slot, worker) in slots {
        let field = |key: &str| field(event, key);
        write_file(&worker, field("worker")?.as_bytes(), FILE_MODE)?;
        let legacy = worker.with_extension("py");
        if managed(&legacy, MARKER) {
            fs::remove_file(&legacy).map_err(|error| Failure::Os(error.to_string()))?;
        }
        let mode = if ctx.windows {
            FILE_MODE
        } else {
            LAUNCHER_MODE
        };
        write_file(&slot, field("launcher")?.as_bytes(), mode)?;
        launchers.insert(event.to_owned(), json!(path_text(&slot)));
        digests.insert(event.to_owned(), json!(field("launcher_sha256")?));
        workers.insert(event.to_owned(), json!(path_text(&worker)));
        worker_digests.insert(event.to_owned(), json!(field("worker_sha256")?));
    }
    let identity = facts.get("identity").cloned().unwrap_or(Value::Null);
    let record = json!({
        "schema_version": SCHEMA,
        "transport": "hooks",
        "root": path_text(&root),
        "paths": launchers,
        "sha256": digests,
        "workers": workers,
        "worker_sha256": worker_digests,
        "guard_cli_identity": identity,
    });
    let text = serde_json::to_string_pretty(&record).map_err(|_| Failure::Invalid)? + "\n";
    write_file(&state_path(ctx), text.as_bytes(), FILE_MODE)?;
    let probe = match canary(ctx, &bound(ctx, &record_map(record.clone()))?.0, None) {
        Ok(verdict) => json!({ "result": verdict }),
        Err(Need::Canary(request)) => json!({ "canary": request }),
        Err(need) => return Err(need),
    };
    Ok(json!({
        "manifest": {
            "transport": "hooks",
            "managed_hooks_root": path_text(&root),
            "managed_hook_paths": record["paths"],
            "managed_hook_workers": record["workers"],
            "managed_hook_sha256": record["sha256"],
            "guard_cli_identity": record["guard_cli_identity"],
            "post_tool_output_mediation": "observation-only",
        },
        "probe": probe,
    }))
}

fn record_map(record: Value) -> Map<String, Value> {
    match record {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}
