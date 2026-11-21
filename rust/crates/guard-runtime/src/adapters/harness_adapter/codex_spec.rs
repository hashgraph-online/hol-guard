//! Codex: the hook manifest spec, the installation every live check and
//! publication expects, built here from the calling process's stamp.
//!
//! Python sends only the facts about its launch (`launch`: the same fields the
//! `argv` op takes). The interpreter, each packaged file's path, the package
//! version, the fallback and daemon start commands and the event bindings are
//! derived from the caller stamp, the context and the hook argv, so no
//! adapter assembles them.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex::{argv, config_path, groups, strings};
use super::paseo_paths::abspath;
use super::{caller, kimi, path_text, Ctx, Failure, Step};

/// Each authenticated role's file under the caller's `codex_plugin_scanner`
/// directory, after `bridge` (the native runtime the hook runs).
const ROLES: [(&str, &str); 8] = [
    ("hook_probe", "guard/runtime_transition_hook_probe.py"),
    ("native_receipt", "guard/native_decision_receipt.py"),
    ("fallback_entrypoint", "cli.py"),
    ("daemon_entrypoint", "guard/cli/daemon_serve.py"),
    ("daemon_manager", "guard/native_daemon_manage.py"),
    ("launch_runtime", "guard/codex_hook_launch_runtime.py"),
    ("runtime_trust", "guard/codex_hook_runtime_trust.py"),
    ("windows_job", "guard/codex_hook_windows_job.py"),
];

/// `str(path.expanduser())`.
pub(super) fn spelled(ctx: &Ctx, path: &Path) -> String {
    path_text(&kimi::expand_user(ctx, &path_text(path)))
}

/// Each role's file, `bridge` first. A frozen caller is its own runtime, so
/// every role is its resolved executable's bytes.
fn packaged_file_paths(ctx: &Ctx, bridge: &str) -> Step<Vec<Value>> {
    let mut roles: Vec<(&str, String)> = Vec::with_capacity(ROLES.len() + 1);
    if caller::frozen(ctx)? {
        let python = caller::hook_python(ctx)?;
        roles.push(("bridge", python.to_owned()));
        roles.extend(ROLES.iter().map(|(role, _)| (*role, python.to_owned())));
    } else {
        roles.push(("bridge", path_text(&ctx.resolved(Path::new(bridge)))));
        let mut root = PathBuf::from(caller::package_root(ctx)?);
        root.push("codex_plugin_scanner");
        for (role, relative) in ROLES {
            let file = relative
                .split('/')
                .fold(root.clone(), |path, part| path.join(part));
            roles.push((role, path_text(&file)));
        }
    }
    Ok(roles
        .into_iter()
        .map(|(role, path)| json!([role, spelled(ctx, Path::new(&path))]))
        .collect())
}

fn launch_text<'a>(launch: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    launch
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

/// The spec `CodexHookManifestSpec` holds, as the verifier and publication
/// read it. `fields` supplies any 8.3 short names a Windows render needs.
pub(super) fn build(
    ctx: &Ctx,
    launch: &Map<String, Value>,
    fields: &Map<String, Value>,
) -> Step<Value> {
    let answer = argv(ctx, launch)?;
    let hook_argv = strings(answer.get("argv"))?;
    let mut rendering = Map::new();
    rendering.insert("argv".into(), json!(hook_argv));
    rendering.insert(
        "long_timeout".into(),
        launch
            .get("long_timeout")
            .cloned()
            .ok_or(Failure::Invalid)?,
    );
    if let Some(names) = fields.get("short_names") {
        rendering.insert("short_names".into(), names.clone());
    }
    let rendered = groups(ctx, &rendering)?;
    let bindings: Value = rendered
        .get("bindings")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str(text).ok())
        .filter(Value::is_array)
        .ok_or(Failure::Invalid)?;
    let workspace = match &ctx.workspace {
        Some(workspace)
            if launch.get("workspace_explicit").and_then(Value::as_bool) == Some(true) =>
        {
            json!(spelled(ctx, workspace))
        }
        _ => Value::Null,
    };
    let bridge = hook_argv.first().ok_or(Failure::Invalid)?;
    Ok(json!({
        "guard_home": spelled(ctx, &ctx.guard_home),
        "home_dir": spelled(ctx, &ctx.home),
        "runtime_guard_home": spelled(ctx, Path::new(launch_text(launch, "runtime_guard_home")?)),
        "workspace_dir": workspace,
        "config_path": spelled(ctx, &config_path(ctx)),
        "interpreter_path": caller::hook_python(ctx)?,
        "package_version": caller::version(ctx)?,
        "packaged_file_paths": packaged_file_paths(ctx, bridge)?,
        "fallback_argv": answer.get("fallback").cloned().ok_or(Failure::Invalid)?,
        "daemon_start_argv": answer.get("start").cloned().ok_or(Failure::Invalid)?,
        "event_bindings": bindings,
    }))
}

/// The `manifest_spec` op: `{"spec": ...}` for the `launch` a caller sent.
pub(super) fn manifest_spec(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let launch = fields
        .get("launch")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    Ok(json!({ "spec": build(ctx, launch, fields)? }))
}

/// `os.path.abspath` of a spec path.
fn anchored(ctx: &Ctx, spec: &Value, key: &str) -> Value {
    match spec.get(key).and_then(Value::as_str) {
        Some(text) => json!(path_text(&abspath(ctx, Path::new(text)))),
        None => Value::Null,
    }
}

/// What a publication generation says of its installation, from the spec it
/// publishes (`generation_request`): the anchored home, config, Guard home,
/// runtime Guard home and workspace, and whether the workspace may be
/// rebound. A field the request names is kept.
fn generation_base(
    ctx: &Ctx,
    spec: &Value,
    launch: &Map<String, Value>,
    generation: &mut Map<String, Value>,
) {
    let rebinding = launch.get("workspace_explicit").and_then(Value::as_bool) != Some(true);
    for (key, from) in [
        ("home", "guard_home"),
        ("config", "config_path"),
        ("guard_home", "guard_home"),
        ("home_dir", "home_dir"),
        ("runtime_guard_home", "runtime_guard_home"),
        ("workspace_dir", "workspace_dir"),
    ] {
        generation
            .entry(key)
            .or_insert_with(|| anchored(ctx, spec, from));
    }
    generation
        .entry("workspace_rebinding_allowed")
        .or_insert(json!(rebinding));
}

/// A request whose `launch` stands for the spec it needs: the spec is built
/// here and set at the top level and in a `generation` request. A request
/// without `launch` carries its own spec and is left as it is; one with both
/// keeps its spec.
pub(super) fn with_spec<'a>(
    ctx: &Ctx,
    fields: &'a Map<String, Value>,
) -> Step<Cow<'a, Map<String, Value>>> {
    let Some(launch) = fields.get("launch") else {
        return Ok(Cow::Borrowed(fields));
    };
    let launch = launch.as_object().ok_or(Failure::Invalid)?;
    let spec = match fields.get("spec") {
        Some(spec) => spec.clone(),
        None => build(ctx, launch, fields)?,
    };
    let mut request = fields.clone();
    request.remove("launch");
    if let Some(Value::Object(generation)) = request.get_mut("generation") {
        generation.insert("spec".into(), spec.clone());
        generation_base(ctx, &spec, launch, generation);
    }
    request.insert("spec".into(), spec);
    Ok(Cow::Owned(request))
}
