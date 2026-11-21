//! Codex: the native hook groups Guard registers in `~/.codex/config.toml`,
//! the bridge argv each handler runs, the hook state launch and doctor read,
//! the backups and legacy shell cleanup an install plans, and its manifest.
//!
//! Python keeps the TOML reads and renders, the authenticated hook manifest,
//! the ownership strips over existing hooks and every publication. A payload
//! read from TOML crosses as order-preserving JSON whose exotic scalars are
//! tokens (`codex_merge`). One reply comes back: `relaunch` (in
//! `codex_merge`) asks for the proxy launch of each Guard server.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::files::{self, Doc};
use super::{
    codex_alternate_plan, codex_config_hooks, codex_failure, codex_files, codex_install_request,
    codex_live_read, codex_live_state, codex_main_plan, codex_manifest_verify, codex_merge,
    codex_migration, codex_publish, codex_servers, codex_sources, codex_spec, codex_uninstall,
    codex_uninstall_config, codex_uninstall_plan, common, hook_render, path_answer, path_text, Ctx,
    Failure, Spec, Step,
};
use crate::claude_hook_bridge_recovery::frozen_recovery_command;
use crate::harness_diagnostics::setup_failures_besides_missing_command;
use crate::hook_env_stamp::dumps;
use crate::hook_process_spawn::{isolated_daemon_start_command, isolated_guard_cli_command};
use crate::pyjson::{self, PyVal};
use crate::runner_sync_url::urlencode;

const HOOK_TIMEOUT_SECONDS: i64 = 30;
pub(super) const TOOL_MATCHER: &str = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*";
const POST_TOOL_MATCHER: &str = "Bash|Read|mcp__.*";
pub(super) const ENFORCEMENT_BOUNDARY: &str = "codex-native-hooks";
pub(super) const HOOK_UNAVAILABLE: &str = "codex_authoritative_hook_unavailable";
pub(super) const NATIVE_HOOK_COMMAND: &str = "codex-hook-bridge";

/// `(event, matcher, status message, long timeout)` in registration order.
pub(super) const EVENTS: [(&str, Option<&str>, &str, bool); 4] = [
    (
        "PreToolUse",
        Some(TOOL_MATCHER),
        "HOL Guard checking tool action",
        true,
    ),
    (
        "PermissionRequest",
        Some(TOOL_MATCHER),
        "HOL Guard checking Codex approval request",
        false,
    ),
    ("UserPromptSubmit", None, "HOL Guard checking prompt", false),
    (
        "PostToolUse",
        Some(POST_TOOL_MATCHER),
        "HOL Guard checking tool result",
        true,
    ),
];

pub(super) fn dispatch(
    spec: &Spec,
    op: &str,
    ctx: &Ctx,
    fields: &Map<String, Value>,
) -> Step<Value> {
    let hosted = codex_install_request::host_syntax(ctx, fields);
    let fields = &*hosted;
    match op {
        "policy_path" => path_answer(&config_path(ctx)),
        "backup_path" => path_answer(&backup_path(ctx)),
        "paths" => Ok(paths(ctx)),
        "argv" => argv(ctx, fields),
        "launch_env" => Ok(json!({ "env": { "CODEX_HOME": path_text(&ctx.home.join(".codex")) } })),
        "groups" => groups(ctx, fields),
        "doctor_status" => doctor_status(fields),
        "migration_backup" => codex_files::migration_backup(ctx, fields),
        "hook_migration" => codex_migration::migration(ctx, fields),
        "config_hooks" => codex_config_hooks::config_hooks(ctx, fields),
        "main_backup" => codex_files::main_backup(ctx, fields),
        "shell_cleanup" => codex_files::shell_cleanup(ctx),
        "manifest" => codex_files::manifest(spec, ctx, fields),
        "migrate" | "readback" | "subset" => codex_merge::dispatch(op, fields),
        "alternate_cleanup" => codex_servers::alternate_cleanup(fields),
        "alternate_plan" => codex_alternate_plan::alternate_plan(ctx, fields),
        "alternate_change" => codex_alternate_plan::alternate_change(ctx, fields),
        "main_plan" => codex_main_plan::main_plan(ctx, fields),
        "managed_mcp" => codex_servers::managed_mcp(ctx, fields),
        "check_sources" => codex_sources::check_sources(fields),
        "uninstall_restore" => codex_uninstall::uninstall_restore(fields),
        "uninstall_config" => codex_uninstall_config::uninstall_config(ctx, fields),
        "uninstall_plan" => codex_uninstall_plan::uninstall_plan(ctx, fields),
        "uninstall" => {
            let request = codex_install_request::complete_uninstall(ctx, fields)?;
            super::codex_uninstall_op::uninstall(ctx, &request).map(codex_failure::with_raise)
        }
        "detect_legacy" => codex_install_request::detect_legacy(ctx, fields),
        "detect" => codex_detect_op::detect(spec, ctx, fields),
        "prepare_install" => codex_prepare::prepare_install(spec, ctx, fields),
        "manifest_spec" => codex_spec::manifest_spec(ctx, fields),
        "live_hook_state" => {
            let spec_fields = codex_spec::with_spec(ctx, fields)?;
            codex_live_state::live_hook_state(ctx, &spec_fields)
        }
        "verify_manifest" => codex_manifest_verify::verify_manifest(ctx, fields),
        "incident_report" => super::codex_incident::incident_report(ctx, fields),
        "runtime_hooks_verified" => {
            let spec_fields = codex_spec::with_spec(ctx, fields)?;
            codex_live_read::runtime_hooks_verified(ctx, &spec_fields)
        }
        "publish_hooks" => codex_publish::publish_hooks(ctx, fields).map(codex_failure::with_raise),
        "install" => {
            let request = codex_install_request::complete(ctx, fields, true)?;
            let spec_fields = codex_spec::with_spec(ctx, &request)?;
            super::codex_install::install(ctx, &spec_fields).map(codex_failure::with_raise)
        }
        "install_plan" => {
            let request = codex_install_request::complete(ctx, fields, false)?;
            let spec_fields = codex_spec::with_spec(ctx, &request)?;
            super::codex_install_plan::install_plan(ctx, &spec_fields)
                .map(codex_failure::with_raise)
        }
        _ => common(spec, op, ctx),
    }
}

pub(super) fn config_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".codex").join("config.toml")
}

pub(super) fn hooks_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join(".codex").join("hooks.json")
}

/// `_scope_for`: a path inside the workspace is project scoped.
pub(super) fn scope_for(ctx: &Ctx, path: &Path) -> &'static str {
    match &ctx.workspace {
        Some(workspace) if path.starts_with(workspace) => "project",
        _ => "global",
    }
}

pub(super) fn digest(ctx: &Ctx, path: &Path, length: usize) -> String {
    let resolved = path_text(&ctx.resolved(path));
    hex::encode(Sha256::digest(resolved.as_bytes()))[..length].to_owned()
}

pub(super) fn backup_path(ctx: &Ctx) -> PathBuf {
    let name = format!("{}.backup.toml", digest(ctx, &config_path(ctx), 12));
    ctx.guard_home.join("managed").join("codex").join(name)
}

/// The config and hooks files Guard reads, the global pair first.
pub(super) fn paths(ctx: &Ctx) -> Value {
    let mut pairs = vec![(config_path(ctx), hooks_path(ctx))];
    if let Some(workspace) = &ctx.workspace {
        let root = workspace.join(".codex");
        pairs.push((root.join("config.toml"), root.join("hooks.json")));
    }
    let pairs: Vec<Value> = pairs
        .iter()
        .map(|(config, hooks)| {
            json!({
                "config": path_text(config),
                "hooks": path_text(hooks),
                "scope": scope_for(ctx, config),
            })
        })
        .collect();
    json!({
        "config": path_text(&config_path(ctx)),
        "hooks": path_text(&hooks_path(ctx)),
        "backup": path_text(&backup_path(ctx)),
        "pairs": pairs,
    })
}

pub(super) fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Step<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

pub(super) fn flag(fields: &Map<String, Value>, key: &str) -> Step<bool> {
    fields
        .get(key)
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)
}

pub(super) fn strings(value: Option<&Value>) -> Step<Vec<String>> {
    value
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

/// An ordered JSON object Python sent as text.
pub(super) fn dict(fields: &Map<String, Value>, key: &str) -> Step<Vec<(String, PyVal)>> {
    match pyjson::parse(text(fields, key)?) {
        Ok(PyVal::Dict(entries)) => Ok(entries),
        _ => Err(Failure::Invalid),
    }
}

/// `json.dumps(value, separators=(",", ":"))`.
pub(super) fn compact(value: &PyVal, ensure_ascii: bool) -> String {
    let mut out = String::new();
    dumps(value, ensure_ascii, false, &mut out);
    out
}

pub(super) fn str_list(items: &[String]) -> PyVal {
    PyVal::List(items.iter().cloned().map(PyVal::Str).collect())
}

fn int(value: i64) -> PyVal {
    PyVal::Int(value.to_string())
}

/// `_hook_command_parts_for_home_mode`: the bridge argv every handler runs,
/// with the isolated fallback and daemon start commands it launches through.
///
/// A frozen Guard (`frozen`) is its own interpreter: the fallback drops the
/// `-c` bootstrap and the start command is its private recovery argument.
/// The handler itself is always the native runtime's `codex-hook-bridge`.
/// `NATIVE_CODEX_HOOK_FEATURE`: a runtime that can answer Codex hooks.
const NATIVE_HOOK_FEATURE: &str = "codex-hook-bridge-v1";

pub(super) fn argv(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let home_is_current = flag(fields, "home_is_current")?;
    let runtime_home = PathBuf::from(text(fields, "runtime_guard_home")?);
    let home = ctx.resolved(&ctx.home);
    let workspace = ctx
        .workspace
        .as_ref()
        .filter(|_| fields.get("workspace_explicit").and_then(Value::as_bool) == Some(true));
    let mut guard_args: Vec<String> = ["guard", "hook", "--harness", "codex"]
        .map(str::to_owned)
        .to_vec();
    if !home_is_current {
        guard_args.extend(["--home".to_owned(), path_text(&ctx.home)]);
        if runtime_home != home {
            guard_args.extend(["--guard-home".to_owned(), path_text(&runtime_home)]);
        }
    }
    if let Some(workspace) = workspace {
        guard_args.extend(["--workspace".to_owned(), path_text(workspace)]);
    }
    // Every hook runs in the native runtime. Without one there is nothing
    // to review hooks with, so the install asks for a repair instead.
    let Some(native) =
        super::proxy_launch::bridge(ctx, NATIVE_HOOK_FEATURE, Some(runtime_home.as_path()))?
    else {
        return Err(Failure::Runtime(
            super::claude_argv::RUNTIME_MISSING.to_owned(),
        ));
    };
    let python = super::caller::hook_python(ctx)?;
    let frozen = super::caller::frozen(ctx)?;
    let (fallback, start) = if frozen {
        let mut fallback = vec![python.to_owned()];
        fallback.extend(guard_args[1..].iter().cloned());
        let start =
            frozen_recovery_command(python, &runtime_home, &home).ok_or(Failure::Invalid)?;
        (fallback, start)
    } else {
        let root = Path::new(super::caller::package_root(ctx)?);
        (
            isolated_guard_cli_command(python, root, &guard_args),
            isolated_daemon_start_command(python, root, &runtime_home, Some(&home)),
        )
    };
    let mut query = vec![
        ("guard-home".to_owned(), path_text(&runtime_home)),
        ("home".to_owned(), path_text(&home)),
    ];
    if let Some(workspace) = workspace {
        query.push(("workspace".to_owned(), path_text(workspace)));
    }
    let long = fields
        .get("long_timeout")
        .and_then(Value::as_i64)
        .ok_or(Failure::Invalid)?;
    let mut timeouts = Doc::default();
    timeouts
        .set("PreToolUse", int(long))
        .set("PermissionRequest", int(HOOK_TIMEOUT_SECONDS))
        .set("UserPromptSubmit", int(HOOK_TIMEOUT_SECONDS))
        .set("PostToolUse", int(long));
    let mut config = Doc::default();
    config
        .set(
            "state_path",
            files::path_value(&runtime_home.join("daemon-state.json")),
        )
        .set("manifest_path", files::text(text(fields, "manifest_path")?))
        .set("fallback_command", str_list(&fallback))
        .set("start_command", str_list(&start))
        .set("query", files::text(urlencode(&query)))
        .set("hook_timeouts", timeouts.value());
    let config = compact(&config.value(), true);
    let argument = if ctx.windows {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(config.as_bytes())
    } else {
        config
    };
    let argv = [native.to_owned(), NATIVE_HOOK_COMMAND.to_owned(), argument];
    Ok(json!({ "argv": argv, "fallback": fallback, "start": start }))
}

/// The environment each handler runs with: the launcher's pinned package
/// and native bindings, then the Codex home it reviews.
fn hook_env(ctx: &Ctx) -> Step<Vec<(String, PyVal)>> {
    let mut env: Vec<(String, PyVal)> = super::caller::launcher_env(ctx)?
        .into_iter()
        .map(|(name, value)| (name, files::text(value)))
        .collect();
    env.push((
        "CODEX_HOME".to_owned(),
        files::text(path_text(&ctx.home.join(".codex"))),
    ));
    Ok(env)
}

/// `_managed_hook_groups` and `_manifest_event_bindings`, as ordered JSON.
pub(super) fn groups(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let argv = strings(fields.get("argv"))?;
    let names = hook_render::names_for(fields, [&argv[..]], ctx.windows)?;
    let command = &hook_render::render(&argv, ctx.windows, &names)?;
    let env = PyVal::Dict(hook_env(ctx)?);
    let long = fields
        .get("long_timeout")
        .and_then(Value::as_i64)
        .ok_or(Failure::Invalid)?;
    let mut groups = Doc::default();
    let mut bindings = Vec::new();
    for (event, matcher, status, long_timeout) in EVENTS {
        let timeout = if long_timeout {
            long
        } else {
            HOOK_TIMEOUT_SECONDS
        };
        let mut handler = Doc::default();
        handler
            .set("type", files::text("command"))
            .set("command", files::text(command))
            .set("timeout", int(timeout))
            .set("statusMessage", files::text(status))
            .set("env", env.clone());
        let handler = handler.value();
        let mut group = Doc::default();
        if let Some(matcher) = matcher {
            group.set("matcher", files::text(matcher));
        }
        group.set("hooks", PyVal::List(vec![handler.clone()]));
        let group = group.value();
        let mut binding = Doc::default();
        binding
            .set("argv", str_list(&argv))
            .set("event", files::text(event))
            .set("group", group.clone())
            .set("group_matcher", matcher.map_or(PyVal::Null, files::text))
            .set("handler", handler)
            .set(
                "handler_id",
                files::text(format!("codex:{event}:guard-handler-v1")),
            )
            .set("handler_index", int(0));
        bindings.push(binding.value());
        groups.set(event, group);
    }
    Ok(json!({
        "groups": compact(&groups.value(), false),
        "bindings": compact(&PyVal::List(bindings), false),
    }))
}

/// `_hooks_have_registered_entries`.
pub(super) fn registered(hooks: Option<&PyVal>) -> bool {
    hooks.and_then(PyVal::as_dict).is_some_and(|events| {
        events
            .iter()
            .any(|(_, groups)| groups.as_list().is_some_and(|groups| !groups.is_empty()))
    })
}

/// The doctor's final setup status once the hook warnings are in.
pub(super) fn doctor_status(fields: &Map<String, Value>) -> Step<Value> {
    let warnings = strings(fields.get("warnings"))?;
    let warnings: Vec<&str> = warnings.iter().map(String::as_str).collect();
    let status = fields.get("status").cloned().unwrap_or(Value::Null);
    let base = fields.get("base_status").and_then(Value::as_str);
    let leftover_only = !setup_failures_besides_missing_command(&warnings);
    let status = match status.as_str() {
        // Hook warnings land after the base status, so recheck before
        // calling it leftover config.
        Some("not_found") if !leftover_only => json!("broken"),
        // A hook Codex is no longer there to run is part of the leftover
        // configuration, not a second fault.
        Some("broken") if base == Some("not_found") && leftover_only => json!("not_found"),
        _ => status,
    };
    Ok(json!({ "status": status }))
}

#[path = "codex_detect_op.rs"]
mod codex_detect_op;
#[path = "codex_detection.rs"]
pub(super) mod codex_detection;
#[path = "codex_managed.rs"]
pub(super) mod codex_managed;
#[path = "codex_prepare.rs"]
mod codex_prepare;
