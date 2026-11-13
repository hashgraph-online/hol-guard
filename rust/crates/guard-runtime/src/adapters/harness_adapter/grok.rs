//! Grok Build: a catch-all `PreToolUse` hook and a prompt hook under
//! `.grok/hooks`, Guard's permission rules in `.grok/config.toml`, and a
//! launcher the `grok_executable` runtime has verified and registered.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::files::{self, text, Doc};
use super::kimi::{expand_user, guard_hook_args};
use super::{common, detection, path_answer, path_text, which, Ctx, Failure, Spec, Step};
use crate::grok_user_config::{
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS, MANAGED_DENY_RULES, OBSERVE_HOOK_EVENTS,
    OBSERVE_HOOK_TIMEOUT_SECONDS,
};
use crate::pyjson::PyVal;

pub(super) const GROK_DIR: &str = ".grok";
pub(super) const CONFIG_FILE: &str = "config.toml";
const MANAGED_CONFIG_FILE: &str = "managed_config.toml";
const HOOKS_DIR: &str = "hooks";
pub(super) const PRETOOL_FILE: &str = "hol-guard-pretooluse.json";
pub(super) const PROMPT_FILE: &str = "hol-guard-prompt.json";
const MANAGED_BEGIN: &str = "# BEGIN HOL GUARD MANAGED GROK";
const HOOK_INTERNAL_TIMEOUT_SECONDS: i64 = 85;
const SYSTEM_POLICY_PATHS: [&str; 2] = [
    "/etc/grok/managed_config.toml",
    "/etc/grok/requirements.toml",
];
const WINDOWS_ROOT_VARIABLES: [&str; 3] = ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"];
const EXECUTABLE_SCHEMA: &str = "grok-executable.v1";
const UNAVAILABLE: &str = "The Guard runtime could not verify the Grok executable.";
const NOT_FOUND: &str = "Trusted Grok executable not found.";
const NO_LONGER_TRUSTED: &str = "The selected Grok executable is no longer trusted.";
const STALE: &str = "Stale or duplicate Guard-managed Grok entries detected.";
const SOURCES: [&str; 3] = ["automatic", "explicit", "registration"];

/// `GROK_HOME`, expanded and resolved, or the context home.
pub(super) fn grok_home(ctx: &Ctx) -> PathBuf {
    match ctx.env("GROK_HOME").filter(|value| !value.is_empty()) {
        Some(value) => ctx.resolved(&expand_user(ctx, value)),
        None => ctx.home.clone(),
    }
}

fn grok_root(ctx: &Ctx) -> PathBuf {
    grok_home(ctx).join(GROK_DIR)
}

pub(super) fn config_path(ctx: &Ctx) -> PathBuf {
    grok_root(ctx).join(CONFIG_FILE)
}

pub(super) fn legacy_path(ctx: &Ctx) -> PathBuf {
    grok_root(ctx).join(MANAGED_CONFIG_FILE)
}

pub(super) fn hooks_dir(ctx: &Ctx) -> PathBuf {
    grok_root(ctx).join(HOOKS_DIR)
}

pub(super) fn state_dir(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("managed").join("grok")
}

pub(super) fn backup_path(ctx: &Ctx, name: &str) -> PathBuf {
    state_dir(ctx).join(format!("{name}.backup"))
}

pub(super) fn state_path(ctx: &Ctx) -> PathBuf {
    state_dir(ctx).join("install.state.json")
}

fn hook_entry(command: &str, timeout: i64) -> PyVal {
    let mut hook = Doc::default();
    hook.set("type", text("command"))
        .set("command", text(command))
        .set("timeout", PyVal::Int(timeout.to_string()));
    let mut entry = Doc::default();
    entry.set("hooks", PyVal::List(vec![hook.value()]));
    entry.value()
}

fn hooks_file(events: &[&str], command: &str, timeout: i64) -> PyVal {
    let mut hooks = Doc::default();
    for event in events {
        hooks.set(event, PyVal::List(vec![hook_entry(command, timeout)]));
    }
    let mut file = Doc::default();
    file.set("hooks", hooks.value());
    file.value()
}

/// `build_pretool_hook_json`: one handler with no matcher, so every current
/// and future tool, subagent and MCP call reaches Guard once.
pub(super) fn pretool_hook(command: &str) -> PyVal {
    hooks_file(&["PreToolUse"], command, GROK_PRETOOL_HOOK_TIMEOUT_SECONDS)
}

/// `build_observe_hook_json`: the prompt gate beside the passive session and
/// subagent hooks.
pub(super) fn observe_hook(command: &str) -> PyVal {
    hooks_file(&OBSERVE_HOOK_EVENTS, command, OBSERVE_HOOK_TIMEOUT_SECONDS)
}

/// More managed hook files than Guard writes, or a repeated legacy block.
fn stale_entries(ctx: &Ctx) -> bool {
    let hooks = ctx.absolute(&hooks_dir(ctx));
    let Ok(entries) = fs::read_dir(&hooks) else {
        return false;
    };
    let managed = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with("hol-guard-") && name.ends_with(".json")
        })
        .count();
    if managed > 2 {
        return true;
    }
    fs::read_to_string(ctx.absolute(&legacy_path(ctx)))
        .is_ok_and(|legacy| legacy.matches(MANAGED_BEGIN).count() > 1)
}

/// A launcher the runtime verified, or why it would not.
pub(super) struct Resolution {
    pub(super) executable: Option<(String, String)>,
    pub(super) error: Option<String>,
}

impl Resolution {
    fn unavailable() -> Self {
        Self {
            executable: None,
            error: Some(UNAVAILABLE.to_owned()),
        }
    }

    /// `_resolution`: `{executable: {path, content_sha256, source}|null, error}`.
    fn from_answer(answer: &Value) -> Self {
        match answer.get("executable") {
            Some(Value::Object(fields)) => {
                let field = |key: &str| fields.get(key).and_then(Value::as_str);
                match (field("path"), field("content_sha256"), field("source")) {
                    (Some(path), Some(_), Some(source)) if SOURCES.contains(&source) => Self {
                        executable: Some((path.to_owned(), source.to_owned())),
                        error: None,
                    },
                    _ => Self::unavailable(),
                }
            }
            Some(Value::Null) | None => match answer.get("error") {
                Some(Value::String(error)) => Self {
                    executable: None,
                    error: Some(error.clone()),
                },
                _ => Self::unavailable(),
            },
            Some(_) => Self::unavailable(),
        }
    }
}

/// The `grok_executable` runtime's answer, or `None` where Python's runtime
/// call answered nothing.
fn executable_answer(ctx: &Ctx, op: &str, fields: Map<String, Value>) -> Option<Value> {
    let cwd = ctx.cwd.as_ref()?;
    let windows_roots: Vec<&str> = if ctx.windows {
        WINDOWS_ROOT_VARIABLES
            .iter()
            .filter_map(|name| ctx.env(name).filter(|value| !value.is_empty()))
            .collect()
    } else {
        Vec::new()
    };
    let mut request = json!({
        "schema": EXECUTABLE_SCHEMA,
        "op": op,
        "guard_home": path_text(&ctx.absolute(&ctx.guard_home)),
        "home_dir": path_text(&ctx.absolute(&ctx.home)),
        "workspace_dir": ctx.workspace.as_ref().map(|path| path_text(&ctx.absolute(path))),
        "cwd": path_text(cwd),
        "windows_roots": windows_roots,
    });
    for (key, value) in fields {
        if !value.is_null() {
            request[key] = value;
        }
    }
    crate::grok_executable::answer_value(&request).ok()
}

fn executable_names(ctx: &Ctx) -> &'static [&'static str] {
    if ctx.windows {
        &["grok.exe", "grok.cmd", "grok.bat", "grok.com"]
    } else {
        &["grok"]
    }
}

/// `_which_grok`: the first PATH or user-directory candidate.
fn candidate(ctx: &Ctx) -> Option<String> {
    executable_names(ctx).iter().find_map(|name| {
        which::which(ctx, name).or_else(|| which::user_directory_command(ctx, name, &ctx.home, &[]))
    })
}

/// `resolve_trusted_grok_executable`: never a workspace or relative PATH entry.
pub(super) fn resolve(ctx: &Ctx) -> Resolution {
    let mut fields = Map::new();
    fields.insert("candidate".into(), json!(candidate(ctx)));
    if let Some(explicit) = ctx.executable_overrides.get("grok") {
        fields.insert("explicit".into(), json!(explicit));
    }
    executable_answer(ctx, "resolve", fields).map_or_else(Resolution::unavailable, |answer| {
        Resolution::from_answer(&answer)
    })
}

fn found(resolution: Resolution) -> Step<(String, String)> {
    let error = resolution.error;
    resolution
        .executable
        .ok_or_else(|| Failure::NotFound(error.unwrap_or_else(|| NOT_FOUND.to_owned())))
}

/// `register_trusted_grok_executable`: bind an explicit selection to its hash.
fn register(ctx: &Ctx, path: &str) -> Step<String> {
    let mut fields = Map::new();
    fields.insert("path".into(), json!(path));
    let answer = executable_answer(ctx, "register", fields)
        .ok_or_else(|| Failure::Os(UNAVAILABLE.to_owned()))?;
    let resolution = Resolution::from_answer(&answer);
    if let Some((path, _)) = resolution.executable {
        return Ok(path);
    }
    let message = resolution
        .error
        .unwrap_or_else(|| NO_LONGER_TRUSTED.to_owned());
    if answer.get("trusted") == Some(&Value::Bool(true)) {
        Err(Failure::Os(message))
    } else {
        Err(Failure::NotFound(message))
    }
}

fn args(fields: &Map<String, Value>) -> Step<Vec<Value>> {
    let args = fields
        .get("args")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    if args.iter().all(Value::is_string) {
        Ok(args.clone())
    } else {
        Err(Failure::Invalid)
    }
}

fn argv(path: String, fields: &Map<String, Value>) -> Step<Value> {
    let mut argv = vec![json!(path)];
    argv.extend(args(fields)?);
    Ok(json!({ "argv": argv }))
}

/// `sanitized_grok_launch_environment`: the variables to drop and the PATH
/// to launch with.
fn sanitize_env(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut request = Map::new();
    for key in ["path_value", "grok_home", "env_keys"] {
        request.insert(key.into(), fields.get(key).cloned().unwrap_or(Value::Null));
    }
    let answer = executable_answer(ctx, "launch-env", request);
    match answer
        .as_ref()
        .map(|answer| (answer.get("path"), answer.get("drop")))
    {
        Some((Some(Value::String(path)), Some(Value::Array(drop)))) => Ok(json!({
            "path": path,
            "drop": drop.iter().filter(|key| key.is_string()).collect::<Vec<_>>(),
        })),
        _ => Err(Failure::Os(UNAVAILABLE.to_owned())),
    }
}

fn detect(spec: &Spec, ctx: &Ctx) -> Step<Value> {
    let system_policy_paths: Vec<&str> = SYSTEM_POLICY_PATHS
        .iter()
        .copied()
        .filter(|path| Path::new(path).is_file() && fs::File::open(path).is_ok())
        .collect();
    let mut request = ctx.detection_request(spec.harness);
    request.insert("grok_home".into(), json!(path_text(&grok_home(ctx))));
    request.insert("system_policy_paths".into(), json!(system_policy_paths));
    let mut answer = crate::grok_detect::detect(&Value::Object(request));
    let resolution = resolve(ctx);
    if let Ok(Value::Object(found)) = &mut answer {
        let mut warnings: Vec<Value> = match found.remove("warnings") {
            Some(Value::Array(warnings)) => warnings,
            _ => Vec::new(),
        };
        warnings.extend(resolution.error.iter().map(|error| json!(error)));
        if stale_entries(ctx) {
            warnings.push(json!(STALE));
        }
        let mut unique: Vec<Value> = Vec::new();
        for warning in warnings {
            if !unique.contains(&warning) {
                unique.push(warning);
            }
        }
        found.insert("warnings".into(), Value::Array(unique));
    }
    detection(spec, answer, resolution.executable.is_some())
}

pub(crate) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    match op {
        "policy_path" => {
            let project = ctx
                .workspace
                .as_ref()
                .map(|workspace| workspace.join(GROK_DIR).join(CONFIG_FILE))
                .filter(|project| ctx.absolute(project).is_file());
            path_answer(&project.unwrap_or_else(|| config_path(ctx)))
        }
        "resolved_executable" => {
            Ok(json!({ "path": resolve(ctx).executable.map(|(path, _)| path) }))
        }
        "detect" => detect(spec, ctx),
        "launch_command" => {
            let (path, source) = found(resolve(ctx))?;
            let path = if source == "explicit" {
                register(ctx, &path)?
            } else {
                path
            };
            argv(path, fields)
        }
        "preview_launch" => argv(found(resolve(ctx))?.0, fields),
        "sanitize_env" => sanitize_env(ctx, fields),
        "hook_spec" => {
            let mut cli_args = guard_hook_args(ctx, spec.harness);
            cli_args.push("--json".to_owned());
            Ok(json!({"cli_args": cli_args, "timeout_seconds": HOOK_INTERNAL_TIMEOUT_SECONDS}))
        }
        // What the CLI's protection checks and update repair compare against.
        "protection" => {
            let hooks = hooks_dir(ctx);
            Ok(json!({
                "config_path": path_text(&config_path(ctx)),
                "pretool_hook_path": path_text(&hooks.join(PRETOOL_FILE)),
                "prompt_hook_path": path_text(&hooks.join(PROMPT_FILE)),
                "managed_deny_rules": MANAGED_DENY_RULES,
                "pretool_timeout_seconds": GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
                "hook_internal_timeout_seconds": HOOK_INTERNAL_TIMEOUT_SECONDS,
            }))
        }
        "observe_hook" => {
            let command = fields
                .get("command")
                .and_then(Value::as_str)
                .ok_or(Failure::Invalid)?;
            Ok(json!({ "hook": files::render(&observe_hook(command))? }))
        }
        "hook_candidates" => super::grok_install::hook_candidates(ctx, fields),
        "prepare_install" => super::grok_install::prepare_install(spec, ctx, fields),
        "prepare_uninstall" => super::grok_install::prepare_uninstall(ctx),
        "finish_uninstall" => files::finished(spec.harness, &config_path(ctx), fields),
        _ => common(spec, op, ctx),
    }
}
