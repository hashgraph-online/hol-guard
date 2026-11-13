//! Cline's managed AgentPlugin: the install, the integrity and live-proof
//! state, the syntax-probe preconditions and the uninstall.
//!
//! Python runs `node --check` over the path the install answers; nothing here
//! executes the plugin.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::cline::{managed_root, paths, runtime, state_text, write_file};
use super::cline_hooks::managed;
use super::{path_text, Ctx, Failure, Step};

const MARKER: &str = "HOL_GUARD_MANAGED_CLINE_PLUGIN_V1";
const PACKAGE_NAME: &str = "hol-guard-cline-plugin";
const SCHEMA: u64 = 1;
const PROOF_MAX_AGE_SECONDS: f64 = 7.0 * 24.0 * 60.0 * 60.0;
const PROOFS: [&str; 3] = ["loaded", "pretool", "posttool"];
const FILE_MODE: u32 = 0o644;
const PACKAGE_JSON: &str = "{\n  \"name\": \"hol-guard-cline-plugin\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"cline\": {\n    \"plugins\": [\n      {\n        \"paths\": [\n          \"./index.js\"\n        ],\n        \"capabilities\": [\n          \"hooks\"\n        ]\n      }\n    ]\n  }\n}\n";

fn state_path(ctx: &Ctx) -> PathBuf {
    managed_root(ctx).join("plugin-state.json")
}

fn proof_path(ctx: &Ctx, name: &str) -> PathBuf {
    managed_root(ctx)
        .join("proofs")
        .join(format!("plugin-{name}.json"))
}

fn load_state(ctx: &Ctx) -> Map<String, Value> {
    match state_text(&state_path(ctx)).map(|text| serde_json::from_str::<Value>(&text)) {
        Some(Ok(Value::Object(state))) => state,
        _ => Map::new(),
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// The checked plugin root under Cline's data directory.
pub(super) fn root(ctx: &Ctx) -> Step<PathBuf> {
    let answer = paths(ctx, "plugin_root", Map::new())?;
    answer
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(Failure::Invalid)
}

fn string_list(value: &Value) -> Step<Value> {
    let parts = value.as_array().ok_or(Failure::Invalid)?;
    if parts.iter().all(Value::is_string) {
        Ok(value.clone())
    } else {
        Err(Failure::Invalid)
    }
}

/// Write the plugin and its state; the probe is the file Python checks with
/// Node, or the verdict when the state cannot name it.
pub(super) fn install(ctx: &Ctx, facts: &Map<String, Value>) -> Step<Value> {
    let root = root(ctx)?;
    let index = root.join("index.js");
    let package = root.join("package.json");
    if is_symlink(&root) || is_symlink(&index) || is_symlink(&package) {
        return Err(runtime(
            "Guard refused a symlinked Cline plugin destination",
        ));
    }
    if index.exists() && !managed(&index, MARKER) {
        return Err(runtime(format!(
            "Cline plugin path is user-owned; Guard will not overwrite {}",
            index.display()
        )));
    }
    if package.exists() && !owned_package(&package) {
        return Err(runtime(format!(
            "Cline plugin path is user-owned; Guard will not overwrite {}",
            package.display()
        )));
    }
    for name in PROOFS {
        let _ = fs::remove_file(proof_path(ctx, name));
    }
    let guard_cli = string_list(facts.get("guard_cli").ok_or(Failure::Invalid)?)?;
    let hook_argv = match facts.get("hook_argv") {
        None | Some(Value::Null) => {
            let mut argv = guard_cli.as_array().cloned().unwrap_or_default();
            argv.extend([json!("--harness"), json!("cline"), json!("--json")]);
            Value::Array(argv)
        }
        Some(argv) => string_list(argv)?,
    };
    let request = json!({
        "guard_cli": guard_cli,
        "hook_argv": hook_argv,
        "adapter_state": path_text(&managed_root(ctx).join("adapter-state.json")),
        "proof_loaded": path_text(&proof_path(ctx, "loaded")),
        "proof_pretool": path_text(&proof_path(ctx, "pretool")),
        "proof_posttool": path_text(&proof_path(ctx, "posttool")),
    });
    let rendered = crate::cline_plugin_render::render(&request)
        .map_err(|error| runtime(format!("Cline plugin render failed: {error}")))?;
    let source = rendered
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| runtime("Cline plugin render answer is malformed"))?;
    write_file(&index, source.as_bytes(), FILE_MODE)?;
    write_file(&package, PACKAGE_JSON.as_bytes(), FILE_MODE)?;
    let digest = hex::encode(Sha256::digest(source.as_bytes()));
    let identity = facts.get("identity").cloned().unwrap_or(Value::Null);
    let record = json!({
        "schema_version": SCHEMA,
        "transport": "plugin",
        "root": path_text(&root),
        "index_path": path_text(&index),
        "package_path": path_text(&package),
        "index_sha256": digest,
        "guard_cli_identity": identity,
    });
    let text = serde_json::to_string_pretty(&record).map_err(|_| Failure::Invalid)? + "\n";
    write_file(&state_path(ctx), text.as_bytes(), FILE_MODE)?;
    Ok(json!({
        "manifest": {
            "transport": "plugin",
            "managed_plugin_path": path_text(&index),
            "managed_plugin_package": path_text(&package),
            "plugin_sha256": digest,
            "guard_cli_identity": identity,
            "post_tool_output_mediation": "replaceable",
        },
        "probe": syntax_probe(ctx),
    }))
}

/// `{"node_check": path}` once the recorded index is the checked root's, or
/// the verdict that stops the probe first.
fn syntax_probe(ctx: &Ctx) -> Value {
    let Some(recorded) = load_state(ctx)
        .get("index_path")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return json!({"result": {"ok": false, "reason": "plugin_state_missing"}});
    };
    let Ok(root) = root(ctx) else {
        return json!({"result": {"ok": false, "reason": "plugin_path_unsafe"}});
    };
    let index = path_text(&root.join("index.js"));
    if recorded != index {
        return json!({"result": {"ok": false, "reason": "plugin_state_path_mismatch"}});
    }
    json!({ "node_check": index })
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

fn proof_state(ctx: &Ctx, name: &str) -> Value {
    let parsed = state_text(&proof_path(ctx, name))
        .and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let Some(payload) = parsed else {
        return json!({"present": false, "fresh": false, "live": false});
    };
    let timestamp = payload
        .get("timestamp")
        .filter(|value| value.is_number())
        .and_then(Value::as_f64);
    let fresh = timestamp.is_some_and(|stamp| now() - stamp <= PROOF_MAX_AGE_SECONDS);
    json!({
        "present": true,
        "fresh": fresh,
        "live": fresh && payload.get("source") == Some(&json!("cline-plugin")),
        "proof": name,
        "outcome": payload.get("outcome").cloned().unwrap_or(Value::Null),
    })
}

fn proven(proof: &Value, outcome: &str) -> bool {
    proof["live"] == json!(true) && proof["outcome"] == json!(outcome)
}

pub(super) fn state(ctx: &Ctx) -> Value {
    let recorded = load_state(ctx);
    let index = recorded
        .get("index_path")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let installed = index.as_deref().is_some_and(Path::is_file);
    let integrity_ok = match (&index, recorded.get("index_sha256").and_then(Value::as_str)) {
        (Some(path), Some(expected)) if installed => {
            managed(path, MARKER)
                && fs::read(path).is_ok_and(|bytes| hex::encode(Sha256::digest(bytes)) == expected)
        }
        _ => false,
    };
    let package = recorded
        .get("package_path")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    // Cline loads the plugin through its package manifest.
    let integrity_ok = integrity_ok && package.as_deref().is_some_and(owned_package);
    let loaded = proof_state(ctx, "loaded");
    let pretool = proof_state(ctx, "pretool");
    let posttool = proof_state(ctx, "posttool");
    let blocking = proven(&pretool, "blocked");
    let replacement = proven(&posttool, "replaced");
    let ready = integrity_ok && proven(&loaded, "loaded") && blocking && replacement;
    json!({
        "installed": installed,
        "integrity_ok": integrity_ok,
        "loaded_proof": loaded,
        "live_pretool_proof": pretool,
        "live_posttool_proof": posttool,
        "pretool_blocking_proven": blocking,
        "posttool_replacement_proven": replacement,
        "post_tool_output_mediation": "replaceable",
        "ready": ready,
    })
}

fn owned_package(path: &Path) -> bool {
    path.is_file()
        && state_text(path)
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .is_some_and(|payload| payload.get("name") == Some(&json!(PACKAGE_NAME)))
}

fn removed(path: &Path) -> Step<()> {
    fs::remove_file(path).map_err(|error| Failure::Os(error.to_string()))
}

/// Remove the managed plugin, keeping an index the user changed since install.
pub(super) fn uninstall(ctx: &Ctx) -> Step<Value> {
    let recorded = load_state(ctx);
    let mut gone = Vec::new();
    let mut retained = Vec::new();
    if let Some(index) = recorded.get("index_path").and_then(Value::as_str) {
        let index = Path::new(index);
        if index.exists() {
            let expected = recorded.get("index_sha256").and_then(Value::as_str);
            let unchanged = fs::read(index)
                .is_ok_and(|bytes| Some(hex::encode(Sha256::digest(bytes)).as_str()) == expected);
            if managed(index, MARKER) && unchanged {
                removed(index)?;
                gone.push(path_text(index));
            } else {
                retained.push(path_text(index));
            }
        }
    }
    if retained.is_empty() {
        if let Some(package) = recorded.get("package_path").and_then(Value::as_str) {
            let package = Path::new(package);
            if owned_package(package) {
                removed(package)?;
                gone.push(path_text(package));
            }
        }
    }
    let root = root(ctx)?;
    if retained.is_empty() && root.is_dir() {
        let _ = fs::remove_dir(&root);
    }
    let state = state_path(ctx);
    if retained.is_empty() && state.is_file() {
        removed(&state)?;
    }
    Ok(json!({
        "transport": "plugin",
        "removed": gone,
        "retained_modified_or_unowned": retained,
        "complete": retained.is_empty(),
    }))
}
