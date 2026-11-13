//! OpenClaw: a Guard-managed overlay bundle under `guard_home/openclaw` that
//! the OpenClaw gateway reads for channel posture and its pre-tool hook. The
//! user's own OpenClaw config is only read.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::cloud_identity;
use super::files::{self, path_value, shim_notes, text, Change, Doc};
use super::{common, detection, path_answer, path_text, which, Ctx, Failure, Spec, Step};
use crate::pyjson::PyVal;

const HOOK_INTERNAL_TIMEOUT_SECONDS: u64 = 3;
const HOOK_HOST_TIMEOUT_SECONDS: i64 = 5;
const INSTALLED_NOTE: &str =
    "Guard generated an OpenClaw overlay bundle for gateway posture and pre-tool protection.";
const REMOVED_NOTE: &str =
    "Guard removed the managed OpenClaw overlay bundle and kept user OpenClaw config untouched.";
const MANAGED_KEYS: [&str; 3] = [
    "managed_manifest_path",
    "managed_overlay_path",
    "pretool_hook_path",
];

fn config_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".openclaw").join("openclaw.json")
}

fn managed_root(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("openclaw")
}

fn int(value: usize) -> PyVal {
    PyVal::Int(value.to_string())
}

/// `_json_payload(path)`: the object, or `{}` for anything else.
fn json_payload(ctx: &Ctx, path: &Path) -> Map<String, Value> {
    std::fs::read(ctx.absolute(path))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default()
}

/// `_openclaw_manifest`: the manifest after its root check.
fn manifest(ctx: &Ctx) -> Step<Map<String, Value>> {
    let path = managed_root(ctx).join("manifest.json");
    files::within_root(ctx, &ctx.guard_home, &path, "OpenClaw manifest")?;
    Ok(json_payload(ctx, &path))
}

/// `_validated_managed_paths`: the overlay and hook paths when the manifest
/// names exactly the managed ones.
fn validated_paths(ctx: &Ctx, manifest: &Map<String, Value>) -> Option<(PathBuf, PathBuf)> {
    let root = managed_root(ctx);
    let overlay = root.join("overlay.json");
    let pretool = root.join("pretool-hook.json");
    let named = |key: &str| {
        manifest
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.contains('\0'))
    };
    let (overlay_value, pretool_value) =
        (named("managed_overlay_path")?, named("pretool_hook_path")?);
    files::within_root(ctx, &ctx.guard_home, &root, "OpenClaw managed").ok()?;
    files::within_root(ctx, &root, &overlay, "OpenClaw overlay").ok()?;
    files::within_root(ctx, &root, &pretool, "OpenClaw hook").ok()?;
    (overlay_value == path_text(&overlay) && pretool_value == path_text(&pretool))
        .then_some((overlay, pretool))
}

fn hook_args(ctx: &Ctx) -> Vec<String> {
    let mut args: Vec<String> = ["guard", "hook", "--guard-home"]
        .iter()
        .map(|part| (*part).to_owned())
        .collect();
    args.push(path_text(&ctx.guard_home));
    args.extend([
        "--harness".into(),
        "openclaw".into(),
        "--home".into(),
        path_text(&ctx.home),
    ]);
    if let Some(workspace) = &ctx.workspace {
        args.extend(["--workspace".into(), path_text(workspace)]);
    }
    args.push("--json".into());
    args
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let mut request = ctx.detection_request(spec.harness);
    request.insert("config_path".into(), json!(path_text(&config_path(ctx))));
    request.insert("user_home".into(), json!(path_text(&ctx.user_home)));
    let found = crate::openclaw_detect::detect(&Value::Object(request));
    let available = which::command_available(ctx, spec.executable, Some(&ctx.home), &[]);
    let mut answer = detection(spec, found, available)?;
    // The Python adapter never surfaced OpenClaw's detection warnings.
    answer["warnings"] = json!([]);
    Ok(answer)
}

fn hook_argv(fields: &Map<String, Value>) -> Step<Vec<PyVal>> {
    let argv = fields
        .get("hook_argv")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    if argv.is_empty() {
        return Err(Failure::Invalid);
    }
    argv.iter()
        .map(|part| part.as_str().map(text).ok_or(Failure::Invalid))
        .collect()
}

fn install_state(ctx: &Ctx, manifest_empty: bool, overlay: &Path, pretool: &Path) -> Step<PyVal> {
    let answer = crate::hermes_install_plan::dispatch(&json!({
        "op": "install_state",
        "manifest_empty": manifest_empty,
        "overlay_exists": ctx.absolute(overlay).exists(),
        "pretool_exists": ctx.absolute(pretool).exists(),
    }))
    .map_err(|_| Failure::Invalid)?;
    answer
        .get("state")
        .and_then(Value::as_str)
        .map(text)
        .ok_or(Failure::Invalid)
}

/// The detection's config paths and artifact ids, as the overlay lists them.
fn detected(answer: &Value) -> Step<(Vec<PyVal>, Vec<PyVal>)> {
    let paths = answer["config_paths"]
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|path| path.as_str().map(text).ok_or(Failure::Invalid))
        .collect::<Step<_>>()?;
    let ids = answer["artifacts"]
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|artifact| {
            artifact["artifact_id"]
                .as_str()
                .map(text)
                .ok_or(Failure::Invalid)
        })
        .collect::<Step<_>>()?;
    Ok((paths, ids))
}

fn prepare_install(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let shim = files::shim_manifest(fields)?;
    let argv = hook_argv(fields)?;
    let root = managed_root(ctx);
    let manifest_path = root.join("manifest.json");
    let overlay_path = root.join("overlay.json");
    let pretool_path = root.join("pretool-hook.json");
    let targets = [&overlay_path, &pretool_path, &manifest_path];
    let normalized = targets
        .iter()
        .map(|path| files::output_path(ctx, path))
        .collect::<Step<Vec<_>>>()?;
    let before = normalized
        .iter()
        .map(|path| files::snapshot(ctx, path))
        .collect::<Step<Vec<_>>>()?;
    let manifest_empty = match &before[2] {
        None => true,
        Some(bytes) => match serde_json::from_slice::<Value>(bytes) {
            Ok(Value::Object(existing)) => existing.is_empty(),
            _ => {
                return Err(Failure::Refusal(
                    "OpenClaw managed manifest must be a JSON object.".into(),
                ))
            }
        },
    };
    let state = install_state(ctx, manifest_empty, &overlay_path, &pretool_path)?;
    let (config_paths, artifact_ids) = detected(&detect(spec, ctx)?)?;
    let artifact_count = int(artifact_ids.len());
    let identity = cloud_identity::hints(ctx, spec.harness);

    let mut notes = vec![text(INSTALLED_NOTE)];
    notes.extend(shim_notes(&shim));
    let capabilities = ["same_channel", "pretool", "channel_posture", "mcp_proxy"]
        .iter()
        .map(|name| ((*name).to_owned(), PyVal::Bool(true)))
        .collect();
    let mut manifest = Doc::default();
    manifest
        .set("harness", text(spec.harness))
        .set("active", PyVal::Bool(true))
        .set("config_path", path_value(&overlay_path))
        .spread(&shim)
        .set("install_state", state)
        .set("managed_root", path_value(&root))
        .set("managed_manifest_path", path_value(&manifest_path))
        .set("managed_overlay_path", path_value(&overlay_path))
        .set("pretool_hook_path", path_value(&pretool_path))
        .set("capabilities", PyVal::Dict(capabilities))
        .set("config_paths", PyVal::List(config_paths.clone()))
        .set("artifact_count", artifact_count.clone())
        .set("notes", PyVal::List(notes));
    if let Some(identity) = &identity {
        manifest.set(
            "cloud_agent_identity",
            cloud_identity::hints_value(identity),
        );
    }
    let mut overlay = Doc::default();
    overlay
        .set("harness", text("openclaw"))
        .set("config_paths", PyVal::List(config_paths))
        .set("artifact_count", artifact_count)
        .set("artifact_ids", PyVal::List(artifact_ids));
    let mut pretool = Doc::default();
    pretool
        .set("command", PyVal::List(argv))
        .set("harness", text("openclaw"))
        .set(
            "timeout_seconds",
            PyVal::Int(HOOK_HOST_TIMEOUT_SECONDS.to_string()),
        )
        .set("fail_open", PyVal::Bool(false));
    let manifest = manifest.value();
    let payloads = [overlay.value(), pretool.value(), manifest.clone()];
    let mut changes = Vec::new();
    for ((path, before), payload) in normalized.iter().zip(before).zip(&payloads) {
        let before_mode = match before {
            Some(_) => files::mode(ctx, path).ok_or(Failure::Invalid)?,
            None => 0o600,
        };
        let after = format!("{}\n", files::render(payload)?).into_bytes();
        changes.push(Change {
            path: ctx.resolved(path),
            before,
            after: Some(after),
            before_mode,
            after_mode: 0o600,
            no_follow: true,
        });
    }
    Ok(json!({
        "files": changes.iter().map(Change::wire).collect::<Vec<_>>(),
        "manifest": files::render(&manifest)?,
    }))
}

fn prepare_uninstall(ctx: &Ctx) -> Step<Value> {
    let root = managed_root(ctx);
    let manifest = manifest(ctx)?;
    let mut deletes = Vec::new();
    for key in MANAGED_KEYS {
        let Some(value) = manifest
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let path = PathBuf::from(value);
        files::within_root(ctx, &root, &path, key)?;
        if ctx.absolute(&path).exists() {
            deletes.push(value.to_owned());
        }
    }
    Ok(json!({"writes": [], "deletes": deletes, "finish": {}}))
}

fn finish_uninstall(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
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
    let mut doc = Doc::default();
    doc.set("harness", text("openclaw"))
        .set("active", PyVal::Bool(false))
        .set(
            "config_path",
            path_value(&managed_root(ctx).join("overlay.json")),
        )
        .spread(&shim)
        .set("removed_paths", PyVal::List(removed))
        .set("notes", PyVal::List(notes));
    files::manifest_answer(doc)
}

/// `_runtime_manifest`: the manifest, or `{}` when its root check fails.
fn runtime_manifest(ctx: &Ctx) -> Map<String, Value> {
    manifest(ctx).unwrap_or_default()
}

fn launch_env(ctx: &Ctx) -> Value {
    let Some((overlay, pretool)) = validated_paths(ctx, &runtime_manifest(ctx)) else {
        return json!({"env": {}});
    };
    let mut env = Map::new();
    env.insert(
        "OPENCLAW_GUARD_OVERLAY_PATH".into(),
        json!(path_text(&overlay)),
    );
    env.insert(
        "OPENCLAW_GUARD_PRETOOL_PATH".into(),
        json!(path_text(&pretool)),
    );
    env.insert("OPENCLAW_GUARD_CHANNEL_POSTURE".into(), json!("enabled"));
    let identity = cloud_identity::hints(ctx, "openclaw");
    env.extend(cloud_identity::environment(identity.as_deref(), "OPENCLAW"));
    json!({ "env": env })
}

/// The probe fields; Python runs `command_argv` and puts its result first.
fn runtime_probe(spec: &Spec, ctx: &Ctx) -> Value {
    let manifest = runtime_manifest(ctx);
    let ready = validated_paths(ctx, &manifest).is_some_and(|(overlay, pretool)| {
        ctx.absolute(&overlay).exists() && ctx.absolute(&pretool).exists()
    });
    let command = which::which(ctx, spec.executable).map(|_| [spec.executable, "--help"]);
    json!({
        "command_argv": command,
        "probe": {
            "managed_install_present": !manifest.is_empty(),
            "managed_install_ready": ready,
            "cloud_agent_identity_configured": cloud_identity::hints(ctx, "openclaw").is_some(),
        },
    })
}

fn approval_flow(fields: &Map<String, Value>) -> Value {
    let same_channel = fields
        .get("managed_install")
        .and_then(|install| install.get("manifest"))
        .and_then(|manifest| manifest.get("capabilities"))
        .and_then(Value::as_object)
        .and_then(|capabilities| capabilities.get("same_channel"))
        .is_some_and(truthy);
    if same_channel {
        json!({
            "tier": "native-or-center",
            "summary": "Guard uses OpenClaw native agent/channel delivery first and falls back to the approval center.",
            "fallback_hint": "Use the Guard approval center if OpenClaw cannot surface the pending request inline.",
            "prompt_channel": "native",
            "auto_open_browser": false,
        })
    } else {
        json!({
            "tier": "approval-center",
            "summary": "Guard keeps OpenClaw approvals in the local approval center without forcing a browser open.",
            "fallback_hint": "Resolve pending OpenClaw requests from the Guard approval center.",
            "prompt_channel": "native-fallback",
            "auto_open_browser": false,
        })
    }
}

/// Python's `bool(value)` for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(&config_path(ctx)),
        "detect" => detect(spec, ctx),
        "hook_spec" => Ok(json!({
            "cli_args": hook_args(ctx),
            "timeout_seconds": HOOK_INTERNAL_TIMEOUT_SECONDS,
        })),
        "prepare_install" => prepare_install(spec, ctx, fields),
        "prepare_uninstall" => prepare_uninstall(ctx),
        "finish_uninstall" => finish_uninstall(ctx, fields),
        "launch_env" => Ok(launch_env(ctx)),
        "runtime_probe" => Ok(runtime_probe(spec, ctx)),
        "approval_flow" => Ok(approval_flow(fields)),
        _ => common(spec, op, ctx),
    }
}
