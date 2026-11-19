//! `runner_authority` kind `harness_adapter`: the Gemini, Antigravity, Kimi,
//! Devin, Muse, OpenClaw, Paseo, Grok, ZCode, Pi, Oh My Pi, OpenCode,
//! Cline, Copilot, Cursor, Claude Code, Hermes and Codex harness adapters.
//!
//! The runtime answers the adapter descriptions, paths, detection, install and
//! uninstall plans, their publication under one installation transaction, the
//! managed-install records, the update repairs and Paseo's delegated native
//! installs. The caller supplies only the facts of its own process.
//!
//! Every request carries `harness`, `op` and a `context` object:
//! `{home, workspace, guard_home, home_override_explicit, cwd, user_home,
//! env}`, where `env` holds only the variables `describe` names and the ones
//! starting with its prefixes. A failure Python raises answers one key:
//! `{"refusal": message}` is a `ValueError`, `{"os_error": message}` an
//! `OSError`, `{"not_found": message}` a `FileNotFoundError` and
//! `{"integrity": reason}` the snapshot's integrity error.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::harness_coverage::artifacts::resolve_lenient;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

mod attested_cli;
mod authorized_write;
mod caller;
mod claude;
mod claude_argv;
mod claude_install_target;
mod claude_install_target_text;
mod claude_settings;
mod cline;
mod cline_apply;
mod cline_hooks;
mod cline_install;
mod cline_mcp;
mod cline_plugin;
mod cline_run;
mod cloud_identity;
mod codex;
mod codex_alternate_plan;
mod codex_config_hooks;
mod codex_detect_legacy;
mod codex_failure;
mod codex_files;
mod codex_hook_state;
mod codex_incident;
mod codex_incident_read;
mod codex_install;
mod codex_install_plan;
mod codex_install_request;
mod codex_live_hooks;
mod codex_live_read;
mod codex_live_state;
mod codex_main_plan;
mod codex_manifest_verify;
mod codex_merge;
mod codex_migration;
mod codex_owner_home;
mod codex_owners;
mod codex_preactivation;
mod codex_publish;
mod codex_python_hook;
mod codex_python_imports;
mod codex_python_values;
mod codex_repair_verify;
mod codex_servers;
mod codex_sources;
mod codex_spec;
mod codex_uninstall;
mod codex_uninstall_config;
mod codex_uninstall_op;
mod codex_uninstall_plan;
mod contract_config_paths;
mod copilot;
mod copilot_install;
mod copilot_mcp;
mod copilot_state;
mod copilot_uninstall;
mod cursor;
mod cursor_apply;
mod cursor_ask;
mod cursor_editor;
mod cursor_files;
mod cursor_hooks;
mod cursor_hooks_plan;
mod cursor_hooks_uninstall;
mod cursor_rebind;
mod cursor_state;
mod cursor_surfaces;
mod describe;
mod describe_env;
mod desktop_core;
mod detect_merged;
mod durable_runtime;
mod files;
mod firewall;
mod grok;
mod grok_hook_command;
mod grok_hook_files;
mod grok_hook_op;
mod grok_install;
mod grok_protection_checks;
mod grok_update;
mod guard_shim;
mod guard_shim_text;
mod hermes;
mod hermes_config;
mod hermes_hooks;
mod hermes_install;
mod hermes_uninstall;
mod hook_config;
mod hook_render;
mod install_apply;
mod isolated_python;
mod kimi;
mod launch_default;
mod live_hook_verification;
mod managed_install;
mod managed_install_target;
mod managed_record;
mod managed_servers;
mod managed_store;
mod managed_update;
mod mcp_servers;
mod openclaw;
mod opencode;
mod opencode_build;
mod opencode_checks;
mod opencode_install;
mod opencode_servers;
mod opencode_update;
mod opencode_workspace;
mod paseo;
mod paseo_install;
mod paseo_paths;
mod pi;
mod pi_extension;
mod probe_run;
mod proof;
mod proxy_launch;
mod settings_hooks;
mod setup_detection;
mod shim_profile;
mod shim_remove;
mod shims_apply;
mod simple;
mod skills_scan;
mod standalone_install;
mod uninstall_apply;
mod update_bounded;
mod update_support;
mod which;
mod zcode;
mod zcode_desktop_keys;

pub(crate) use codex_repair_verify::{verify_captured, Verdict};

#[cfg(test)]
#[path = "codex_owners_tests.rs"]
mod codex_owners_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[cfg(test)]
#[path = "tests_mcp_launch.rs"]
mod tests_mcp_launch;

pub(crate) use codex_detect_legacy::DetectLegacy;
pub(crate) use describe::Spec;

/// The paths a harness adapter works from, as Python's `HarnessContext` and
/// process hold them.
#[derive(Clone)]
pub(crate) struct Ctx {
    pub(crate) home: PathBuf,
    pub(crate) workspace: Option<PathBuf>,
    pub(crate) guard_home: PathBuf,
    pub(crate) home_explicit: bool,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) user_home: PathBuf,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) executable_overrides: BTreeMap<String, String>,
    pub(crate) windows: bool,
    /// Whether CLI probes may run; the passive global doctor turns them off.
    pub(crate) probes: bool,
    /// `native_caller.caller_identity()`: the Guard process that asked.
    pub(crate) caller: Map<String, Value>,
}

impl Ctx {
    fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
        let map = value.and_then(Value::as_object).ok_or(ERR_INVALID)?;
        let text = |key: &str| map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
        let optional = |key: &str| match map.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(PathBuf::from(text))),
            Some(_) => Err(ERR_INVALID),
        };
        let flag = |key: &str| match map.get(key) {
            None => Ok(false),
            Some(value) => value.as_bool().ok_or(ERR_INVALID),
        };
        let strings = |key: &str| match map.get(key) {
            None | Some(Value::Null) => Ok(BTreeMap::new()),
            Some(Value::Object(entries)) => entries
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|text| (key.clone(), text.to_owned()))
                        .ok_or(ERR_INVALID)
                })
                .collect::<Result<_, _>>(),
            Some(_) => Err(ERR_INVALID),
        };
        Ok(Self {
            home: PathBuf::from(text("home")?),
            workspace: optional("workspace")?,
            guard_home: PathBuf::from(text("guard_home")?),
            home_explicit: flag("home_override_explicit")?,
            cwd: optional("cwd")?,
            user_home: PathBuf::from(text("user_home")?),
            env: strings("env")?,
            executable_overrides: strings("executable_overrides")?,
            windows: cfg!(windows),
            probes: match map.get("probes") {
                None => true,
                Some(value) => value.as_bool().ok_or(ERR_INVALID)?,
            },
            caller: match map.get("caller") {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(caller)) => caller.clone(),
                Some(_) => return Err(ERR_INVALID),
            },
        })
    }

    /// `os.path.abspath`-style anchoring against the caller's directory.
    pub(crate) fn absolute(&self, path: &Path) -> PathBuf {
        match &self.cwd {
            Some(cwd) if !path.is_absolute() => cwd.join(path),
            _ => path.to_path_buf(),
        }
    }

    /// `path.resolve()` as the caller's process would answer it.
    pub(crate) fn resolved(&self, path: &Path) -> PathBuf {
        resolve_lenient(&self.absolute(path))
    }

    /// `context.home_dir.resolve() == Path.home().resolve()`.
    pub(crate) fn default_home(&self) -> bool {
        self.resolved(&self.home) == self.resolved(&self.user_home)
    }

    pub(crate) fn env(&self, name: &str) -> Option<&str> {
        self.env.get(name).map(String::as_str)
    }

    /// The request a native detection kind reads for this harness.
    pub(crate) fn detection_request(&self, harness: &str) -> Map<String, Value> {
        let mut request = Map::new();
        request.insert("harness".into(), json!(harness));
        request.insert("home".into(), json!(path_text(&self.home)));
        request.insert(
            "workspace".into(),
            self.workspace
                .as_deref()
                .map_or(Value::Null, |path| json!(path_text(path))),
        );
        if let Some(cwd) = &self.cwd {
            request.insert("cwd".into(), json!(path_text(cwd)));
        }
        request
    }
}

pub(crate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Why an op stopped, as the Python adapter raised it.
#[derive(Debug)]
pub(crate) enum Failure {
    Refusal(String),
    Os(String),
    NotFound(String),
    Integrity(&'static str),
    /// The `RuntimeError` an adapter raised.
    Runtime(String),
    /// A fact only the Guard process can supply; Python answers and asks again.
    Reply(Value),
    Invalid,
}

pub(crate) type Step<T> = Result<T, Failure>;

impl From<&'static str> for Failure {
    fn from(_: &'static str) -> Self {
        Self::Invalid
    }
}

fn answer(step: Step<Value>) -> KindResult {
    match step {
        Ok(value) => Ok(value),
        Err(Failure::Refusal(message)) => Ok(json!({ "refusal": message })),
        Err(Failure::Os(message)) => Ok(json!({ "os_error": message })),
        Err(Failure::NotFound(message)) => Ok(json!({ "not_found": message })),
        Err(Failure::Integrity(reason)) => Ok(json!({ "integrity": reason })),
        Err(Failure::Runtime(message)) => Ok(json!({ "runtime_error": message })),
        Err(Failure::Reply(needed)) => Ok(json!({ "reply": needed })),
        Err(Failure::Invalid) => Err(ERR_INVALID),
    }
}

/// The `codex_hook_owners` kind: which Codex hook handlers this install owns.
pub(crate) fn codex_owners(args: &Value) -> KindResult {
    answer(codex_owners::dispatch(args_object(args)?))
}

/// The `isolated_hook_python` kind: the system interpreter a stdlib hook
/// client runs under.
pub(crate) fn isolated_python(args: &Value) -> KindResult {
    answer(isolated_python::dispatch(args_object(args)?))
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    if op == "describe" {
        return Ok(describe::describe());
    }
    if mcp_servers::handles(op) {
        return answer(mcp_servers::dispatch(op, fields));
    }
    let ctx = Ctx::parse(fields.get("context"))?;
    if grok_protection_checks::handles(op) {
        return answer(grok_protection_checks::dispatch(op, &ctx));
    }
    if contract_config_paths::handles(op) {
        return answer(contract_config_paths::dispatch(&ctx, fields));
    }
    if setup_detection::handles(op) {
        return answer(setup_detection::dispatch(op, &ctx, fields));
    }
    if live_hook_verification::handles(op) {
        return answer(live_hook_verification::dispatch(&ctx, fields));
    }
    if grok_hook_op::handles(op) {
        return answer(grok_hook_op::dispatch(op, &ctx, fields));
    }
    if op == "proof_verify" || op == "proof_bind" {
        return answer(proof::dispatch(op, &ctx, fields));
    }
    if let Some(done) = managed_install::route(op, &ctx, fields) {
        return done;
    }
    if op == "prepare_guard_shim" {
        return answer(guard_shim::prepare(&ctx, fields));
    }
    if op == "prepare_guard_shim_shell_profile" {
        return answer(shim_profile::prepare(&ctx, fields));
    }
    if op == "apply_guard_shims" {
        return answer(shims_apply::apply_guard_shims(&ctx, fields));
    }
    if op == "prepare_guard_shim_removal" {
        return answer(shim_remove::prepare(&ctx, fields));
    }
    let harness = fields
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let spec = describe::spec(harness).ok_or(ERR_INVALID)?;
    if op == "adapter_install" || op == "adapter_uninstall" {
        return managed_install::adapter(op, spec, &ctx, fields);
    }
    if op == "detect_merged" {
        return answer(detect_merged::one(spec, &ctx, fields));
    }
    if op == "apply_uninstall" {
        return uninstall_apply::apply(spec, &ctx, fields);
    }
    if op == "apply_install" {
        return answer(install_apply::apply(spec, &ctx, fields));
    }
    if op == "prepare_surfaces" && spec.harness == "cursor" {
        return answer(cursor_apply::prepare(spec, &ctx, fields));
    }
    if op == "apply_plan" {
        return answer(shims_apply::apply_plan(spec, &ctx, fields));
    }
    if op == "probe_runtime" {
        return answer(probe_run::runtime(spec, &ctx, fields));
    }
    answer(if op == "default_launch" {
        launch_default::answer(spec, &ctx, fields)
    } else if op == "hook_config" {
        hook_config::answer(spec, &ctx, fields)
    } else if op == "hook_spec" {
        route(spec, op, &ctx, fields)
            .and_then(|spec_answer| hook_config::with_config(spec, &ctx, spec_answer))
    } else {
        route(spec, op, &ctx, fields)
    })
}

fn route(spec: &Spec, op: &str, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    match spec.harness {
        "gemini" | "antigravity" => simple::dispatch(spec, op, ctx, fields),
        "kimi" => kimi::dispatch(spec, op, ctx, fields),
        "devin" | "muse" => settings_hooks::dispatch(spec, op, ctx, fields),
        "openclaw" => openclaw::dispatch(spec, op, ctx, fields),
        "paseo" => paseo::dispatch(spec, op, ctx, fields),
        "grok" => grok::dispatch(spec, op, ctx, fields),
        "zcode" => zcode::dispatch(spec, op, ctx, fields),
        "pi" | "omp" => pi::dispatch(spec, op, ctx, fields),
        "opencode" => opencode::dispatch(spec, op, ctx, fields),
        "cline" => cline::dispatch(spec, op, ctx, fields),
        "copilot" => copilot::dispatch(spec, op, ctx, fields),
        "cursor" => cursor::dispatch(spec, op, ctx, fields),
        "claude-code" => claude::dispatch(spec, op, ctx, fields),
        "hermes" => hermes::dispatch(spec, op, ctx, fields),
        "codex" => codex::dispatch(spec, op, ctx, fields),
        _ => Err(Failure::Invalid),
    }
}

/// `{"path": ...}` for `resolved_executable`, shared by every harness.
pub(crate) fn resolved_executable(spec: &Spec, ctx: &Ctx, candidates: &[PathBuf]) -> Step<Value> {
    Ok(json!({ "path": which::resolve_command(ctx, spec.executable, candidates) }))
}

/// A native detection kind's `{artifacts, found_paths, warnings?}` answer,
/// with this adapter's command lookup, as Python builds `HarnessDetection`.
pub(crate) fn detection(
    spec: &Spec,
    kind_answer: KindResult,
    command_available: bool,
) -> Step<Value> {
    let mut found = kind_answer.map_err(|_| Failure::Invalid)?;
    let found = found.as_object_mut().ok_or(Failure::Invalid)?;
    let artifacts = found.remove("artifacts").ok_or(Failure::Invalid)?;
    let paths = found.remove("found_paths").ok_or(Failure::Invalid)?;
    let installed = paths.as_array().is_some_and(|paths| !paths.is_empty()) || command_available;
    Ok(json!({
        "artifacts": artifacts,
        "config_paths": paths,
        "warnings": found.remove("warnings").unwrap_or_else(|| json!([])),
        "installed": installed,
        "command_available": command_available,
        "workspace_aibom": spec.workspace_aibom,
    }))
}

/// A path answer, as `policy_path` returns it.
pub(crate) fn path_answer(path: &Path) -> Step<Value> {
    Ok(json!({ "path": path_text(path) }))
}

/// The ops whose answer is the `HarnessAdapter` default for this harness.
pub(crate) fn common(spec: &Spec, op: &str, ctx: &Ctx) -> Step<Value> {
    match op {
        "resolved_executable" => resolved_executable(spec, ctx, &[]),
        "command_available" => Ok(json!({
            "available": which::command_available(ctx, spec.executable, Some(&ctx.home), &[]),
        })),
        "launch_env" => Ok(json!({ "env": {} })),
        "runtime_probe" => Ok(json!({ "probe": null })),
        "approval_flow" => Ok(spec.approval_flow()),
        _ => Err(Failure::Invalid),
    }
}
