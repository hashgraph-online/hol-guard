//! Hermes: a Guard-managed bundle under `guard_home/hermes` (MCP overlay,
//! pre-tool hook payload and an authenticated manifest), Guard's MCP proxies,
//! `guard` section and `hooks.pre_tool_call` entry in the Hermes
//! `config.yaml`, and the shell-hooks allowlist that approves that entry.
//!
//! Python answers three replies this module cannot: the proxy launch of each
//! local stdio server (`launchers`), PyYAML's rendering of a rewritten
//! `config.yaml` (`yaml`), and, on Windows, the skill directory identities the
//! resident's descriptor walk cannot read (`skills`).

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, Doc};
use super::openclaw::{json_payload, truthy};
use super::{cloud_identity, hermes_hooks, hermes_install, hermes_uninstall};
use super::{common, detection, path_answer, path_text, which, Ctx, Failure, Spec, Step};
use crate::adapter_state_integrity_op::state_verified;
use crate::guard_store_json::py_strip;
use crate::pyjson::PyVal;

pub(super) const HARNESS: &str = "hermes";
pub(super) const HOOK_HOST_TIMEOUT_SECONDS: i64 = 5;
const HOOK_INTERNAL_TIMEOUT_SECONDS: u64 = 3;
const MANAGED_LABEL: &str = "Hermes managed";
const LAUNCH_REVIEW_ONLY: &str = "launch-review only";

/// `_hermes_home`: `HERMES_HOME` when set, as Hermes's `get_hermes_home` reads it.
pub(super) fn hermes_home(ctx: &Ctx) -> PathBuf {
    match ctx
        .env("HERMES_HOME")
        .map(py_strip)
        .filter(|home| !home.is_empty())
    {
        Some(home) => PathBuf::from(home),
        None => ctx.home.join(".hermes"),
    }
}

/// `_hermes_host_home`: the mounted host installation a sandbox can fall back to.
pub(super) fn host_home(ctx: &Ctx) -> Option<PathBuf> {
    let path = match ctx
        .env("HERMES_HOST_HOME")
        .map(py_strip)
        .filter(|home| !home.is_empty())
    {
        Some(home) => PathBuf::from(home),
        None => ctx.home.join("hermes-host-home"),
    };
    ctx.absolute(&path).is_dir().then_some(path)
}

pub(super) fn managed_root(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("hermes")
}

pub(super) fn key_home(ctx: &Ctx) -> PathBuf {
    ctx.absolute(&ctx.guard_home)
}

pub(super) fn verified(ctx: &Ctx, manifest: &Map<String, Value>) -> bool {
    state_verified(&key_home(ctx), HARNESS, &Value::Object(manifest.clone()))
}

/// The managed bundle paths: manifest, overlay and pre-tool hook payload.
pub(super) fn bundle(ctx: &Ctx) -> (PathBuf, PathBuf, PathBuf) {
    let root = managed_root(ctx);
    (
        root.join("manifest.json"),
        root.join("mcp-overlay.json"),
        root.join("pretool-hook.json"),
    )
}

/// `hermes_manifest`: the manifest after its root check.
pub(super) fn manifest(ctx: &Ctx) -> Step<(Map<String, Value>, Option<PyVal>)> {
    let (path, _, _) = bundle(ctx);
    files::within_root(ctx, &ctx.guard_home, &path, "Hermes manifest")?;
    Ok(manifest_snapshot(ctx, &path))
}

/// The manifest read once: the payload its MAC covers and the ordered form
/// the install and cleanup read, so both come from the same bytes.
pub(super) fn manifest_snapshot(ctx: &Ctx, path: &Path) -> (Map<String, Value>, Option<PyVal>) {
    let bytes = std::fs::read(ctx.absolute(path)).ok();
    let payload = bytes
        .as_deref()
        .and_then(|raw| serde_json::from_slice(raw).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    let ordered = bytes
        .and_then(|raw| String::from_utf8(raw).ok())
        .and_then(|raw| crate::pyjson::parse(&raw).ok());
    (payload, ordered)
}

/// `_read_managed_server_names`: the `servers` recorded by the last install.
pub(super) fn managed_server_names(ctx: &Ctx) -> Vec<String> {
    let payload = json_payload(ctx, &managed_root(ctx).join("managed-servers.json"));
    strings(payload.get("servers"))
}

pub(super) fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `validated_hermes_managed_paths`: the overlay and hook paths when an
/// authentic manifest names exactly the managed ones.
fn validated_paths(ctx: &Ctx, manifest: &Map<String, Value>) -> Option<(PathBuf, PathBuf)> {
    if manifest.contains_key("state_authentication") && !verified(ctx, manifest) {
        return None;
    }
    let root = managed_root(ctx);
    let (_, overlay, pretool) = bundle(ctx);
    files::within_root(ctx, &ctx.guard_home, &root, MANAGED_LABEL).ok()?;
    files::within_root(ctx, &root, &overlay, MANAGED_LABEL).ok()?;
    files::within_root(ctx, &root, &pretool, MANAGED_LABEL).ok()?;
    let named = |key: &str| {
        manifest
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && !value.contains('\0'))
    };
    (named("mcp_overlay_path")? == path_text(&overlay)
        && named("pretool_hook_path")? == path_text(&pretool))
    .then_some((overlay, pretool))
}

fn hook_args(ctx: &Ctx) -> Vec<String> {
    let mut args: Vec<String> = vec!["guard".into(), "hook".into(), "--guard-home".into()];
    args.extend([
        path_text(&ctx.guard_home),
        "--harness".into(),
        HARNESS.into(),
    ]);
    if !ctx.default_home() {
        args.extend(["--home".into(), path_text(&ctx.home)]);
    }
    args.push("--json".into());
    args
}

fn detect(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let home = ctx.absolute(&hermes_home(ctx));
    let host = host_home(ctx).map(|host| ctx.absolute(&host));
    let mut request = Map::new();
    request.insert("harness".into(), json!(HARNESS));
    request.insert("hermes_home".into(), json!(path_text(&home)));
    request.insert(
        "host_home".into(),
        host.as_deref()
            .map_or(Value::Null, |host| json!(path_text(host))),
    );
    request.insert("managed_names".into(), json!(managed_server_names(ctx)));
    request.insert(
        "manifest_path".into(),
        json!(path_text(&ctx.absolute(&bundle(ctx).0))),
    );
    if ctx.windows {
        // The resident's descriptor walk is unix-only; Python reads the skills.
        let roots: Vec<String> = std::iter::once(&home)
            .chain(&host)
            .map(|root| path_text(root))
            .collect();
        let identities = fields
            .get("skills")
            .and_then(Value::as_str)
            .and_then(|answer| serde_json::from_str::<Value>(answer).ok())
            .filter(Value::is_object)
            .ok_or_else(|| Failure::Reply(json!({ "skills": roots })))?;
        request.insert("skill_identities".into(), identities);
    }
    let found = crate::hermes_detect::detect(&Value::Object(request));
    let available = which::command_available(ctx, spec.executable, Some(&ctx.home), &[]);
    detection(spec, found, available)
}

fn launch_env(ctx: &Ctx) -> Step<Value> {
    let Some((overlay, pretool)) = validated_paths(ctx, &manifest(ctx)?.0) else {
        return Ok(json!({"env": {}}));
    };
    let mut env = Map::new();
    env.insert(
        "HERMES_GUARD_MCP_OVERLAY_PATH".into(),
        json!(path_text(&overlay)),
    );
    env.insert(
        "HERMES_GUARD_PRETOOL_PATH".into(),
        json!(path_text(&pretool)),
    );
    let identity = cloud_identity::hints(ctx, HARNESS);
    env.extend(cloud_identity::environment(identity.as_deref(), "HERMES"));
    Ok(json!({ "env": env }))
}

fn hook_registered(ctx: &Ctx) -> bool {
    hermes_hooks::registered(ctx, &hermes_home(ctx).join("config.yaml"))
}

/// The probe fields; Python runs `command_argv` and puts its result first.
fn runtime_probe(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let (manifest, _) = manifest(ctx)?;
    let registered = hook_registered(ctx);
    let ready = registered
        && validated_paths(ctx, &manifest).is_some_and(|(overlay, pretool)| {
            ctx.absolute(&overlay).exists() && ctx.absolute(&pretool).exists()
        });
    let command = which::which(ctx, spec.executable).map(|_| [spec.executable, "--help"]);
    Ok(json!({
        "command_argv": command,
        "probe": {
            "managed_install_present": !manifest.is_empty(),
            "runtime_hook_registered": registered,
            "managed_install_ready": ready,
            "cloud_agent_identity_configured": cloud_identity::hints(ctx, HARNESS).is_some(),
        },
    }))
}

/// A managed install whose hook is not registered only reviews launches;
/// `harness_diagnostics` adds the matching warning.
fn diagnostics(ctx: &Ctx) -> Step<Value> {
    if manifest(ctx)?.0.is_empty() || hook_registered(ctx) {
        return Ok(json!({ "update": "{}" }));
    }
    let update = json!({ "runtime_protection_label": LAUNCH_REVIEW_ONLY });
    Ok(json!({ "update": update.to_string() }))
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
            "summary": "Guard uses the managed Hermes same-channel seam first and falls back to the approval center.",
            "fallback_hint": "Use the Guard approval center if Hermes does not surface the pending request inline.",
            "prompt_channel": "native",
            "auto_open_browser": false,
        })
    } else {
        json!({
            "tier": "approval-center",
            "summary": "Guard keeps Hermes approvals in the local approval center without forcing a browser open.",
            "fallback_hint": "Resolve pending Hermes requests from the Guard approval center.",
            "prompt_channel": "native-fallback",
            "auto_open_browser": false,
        })
    }
}

/// PyYAML's `yaml.dump(doc, default_flow_style=False, sort_keys=False)`,
/// which Python renders for the JSON text it is shown.
pub(super) fn yaml(fields: &Map<String, Value>, doc: &PyVal) -> Step<String> {
    let rendered = files::render(doc)?;
    let answer = fields
        .get("yaml")
        .and_then(Value::as_str)
        .and_then(|answer| serde_json::from_str::<Vec<String>>(answer).ok())
        .filter(|pair| pair.len() == 2 && pair[0] == rendered);
    match answer {
        Some(mut pair) => pair.pop().ok_or(Failure::Invalid),
        None => Err(Failure::Reply(json!({ "yaml": rendered }))),
    }
}

/// `config.yaml` written through its resolved directory, as
/// `write_text_at_authorized_path` writes it.
pub(super) fn authorized(ctx: &Ctx, path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or(path);
    let name = path.file_name().map(PathBuf::from).unwrap_or_default();
    ctx.resolved(parent).join(name)
}

/// `{"harness", "active", "config_path", **shim, ...}` in the order both results open with.
pub(super) fn result_head(active: bool, config_path: &Path, shim: &[(String, PyVal)]) -> Doc {
    let mut doc = Doc::default();
    doc.set("harness", files::text(HARNESS))
        .set("active", PyVal::Bool(active))
        .set("config_path", files::path_value(config_path));
    doc.spread(shim);
    doc
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => path_answer(
            &ctx.workspace
                .as_ref()
                .unwrap_or(&ctx.home)
                .join(".mcp.json"),
        ),
        "detect" => detect(spec, ctx, fields),
        "hook_spec" => Ok(json!({
            "cli_args": hook_args(ctx),
            "timeout_seconds": HOOK_INTERNAL_TIMEOUT_SECONDS,
        })),
        "prepare_install" => hermes_install::prepare(spec, ctx, fields),
        "prepare_uninstall" => hermes_uninstall::prepare(ctx, fields),
        "finish_uninstall" => hermes_uninstall::finish(ctx, fields),
        "launch_env" => launch_env(ctx),
        "runtime_probe" => runtime_probe(spec, ctx),
        "approval_flow" => Ok(approval_flow(fields)),
        "diagnostics" => diagnostics(ctx),
        _ => common(spec, op, ctx),
    }
}
