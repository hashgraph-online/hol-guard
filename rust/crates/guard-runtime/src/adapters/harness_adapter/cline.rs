//! Cline: the CLI, VS Code and JetBrains hosts, two enforcement transports
//! (native hooks and a managed AgentPlugin) and the MCP proxy rewrite.
//!
//! Python runs the processes: the CLI's `--version`, the hook canary, the
//! plugin's `node --check` and the shim. An op that needs the canary answers
//! `{"canary": {"argv", "input"}}` before it changes anything, and Python asks
//! again with the run.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::kimi::expand_user;
use super::{common, path_answer, path_text, resolved_executable, Ctx, Failure, Spec, Step};
use crate::context_digest::python_strip;
use crate::zcode_artifacts::{Fields, Scope};

use super::{cline_hooks, cline_install, cline_mcp, cline_plugin};

const VERSION: &str = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?";
const DUPLICATE_DETECTED: &str = "Guard found both managed Cline enforcement transports. Run `hol-guard apps repair cline` to restore one transport.";
const DUPLICATE: &str =
    "Both Guard-managed Cline transports are present; run `hol-guard apps repair cline`.";
const PENDING: &str = "Cline protection is installed but live runtime proof is pending or stale. Run a safe Cline tool action, then `hol-guard apps test cline`.";
const JETBRAINS: &str =
    "Cline JetBrains remains unverified until a live pre-tool proof is recorded.";

/// What stopped an op that reads hook state: a canary run to ask for, or a
/// failure.
pub(super) enum Need {
    Canary(Value),
    Fail(Failure),
}

pub(super) type Read<T> = Result<T, Need>;

impl From<Failure> for Need {
    fn from(failure: Failure) -> Self {
        Self::Fail(failure)
    }
}

impl From<&'static str> for Need {
    fn from(_: &'static str) -> Self {
        Self::Fail(Failure::Invalid)
    }
}

/// The `RuntimeError` the Cline adapter raised.
pub(super) fn runtime(message: impl Into<String>) -> Failure {
    Failure::Runtime(message.into())
}

pub(super) fn managed_root(ctx: &Ctx) -> PathBuf {
    ctx.guard_home.join("managed").join("cline")
}

pub(super) fn adapter_state_path(ctx: &Ctx) -> PathBuf {
    managed_root(ctx).join("adapter-state.json")
}

/// A file's UTF-8 text, or `None` when it cannot be read as one.
pub(super) fn state_text(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

pub(super) fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Step<()> {
    crate::encrypted_secret_store::atomic_write_bytes(path, bytes, mode)
        .map_err(|error| Failure::Os(error.to_string()))
}

/// One `cline_paths` answer; a refusal is the adapter's `RuntimeError`.
pub(super) fn paths(ctx: &Ctx, op: &str, extra: Map<String, Value>) -> Step<Value> {
    let cwd = ctx
        .cwd
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .ok_or(Failure::Invalid)?;
    let configured = |name: &str| match ctx.env(name).map(python_strip) {
        Some(value) if !value.is_empty() => path_text(&cwd.join(expand_user(ctx, value))),
        _ => String::new(),
    };
    let mut request = extra;
    request.insert("op".into(), json!(op));
    request.insert("home".into(), json!(path_text(&ctx.absolute(&ctx.home))));
    request.insert(
        "guard_home".into(),
        json!(path_text(&ctx.absolute(&ctx.guard_home))),
    );
    request.insert("cwd".into(), json!(path_text(&cwd)));
    request.insert(
        "data_dirs".into(),
        json!([configured("CLINE_DATA_DIR"), configured("CLINE_DIR")]),
    );
    let answer = crate::cline_paths::dispatch(&Value::Object(request))?;
    match answer.get("refusal").and_then(Value::as_str) {
        Some(refusal) => Err(runtime(refusal)),
        None => Ok(answer),
    }
}

/// Cline's data directory.
pub(super) fn data_dir(ctx: &Ctx) -> Step<PathBuf> {
    paths(ctx, "roots", Map::new())?
        .get("data_dir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(Failure::Invalid)
}

/// The hosts Cline runs in: the CLI Python probed, and the editor installs.
pub(super) struct Hosts {
    pub(super) cli: Option<String>,
    pub(super) version: Option<String>,
    pub(super) vscode: Vec<String>,
    pub(super) jetbrains: Vec<String>,
}

impl Hosts {
    pub(super) fn names(&self) -> Vec<&'static str> {
        [
            (self.cli.is_some(), "cli"),
            (!self.vscode.is_empty(), "vscode"),
            (!self.jetbrains.is_empty(), "jetbrains"),
        ]
        .into_iter()
        .filter_map(|(present, name)| present.then_some(name))
        .collect()
    }

    pub(super) fn wire(&self) -> Value {
        json!({
            "cli_version": self.version,
            "vscode_versions": self.vscode,
            "jetbrains_detected": !self.jetbrains.is_empty(),
        })
    }
}

/// The `cli` field: `{path, output}` from the `--version` probe.
fn cli(fields: &Map<String, Value>) -> (Option<String>, Option<String>) {
    let cli = fields.get("cli");
    let path = cli
        .and_then(|cli| cli.get("path"))
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(str::to_owned);
    let output = cli
        .and_then(|cli| cli.get("output"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let version = path.as_ref().and_then(|_| {
        regex::Regex::new(VERSION)
            .ok()?
            .find(output)
            .map(|found| found.as_str().to_owned())
    });
    (path, version)
}

/// The native inventory of `settings` and the editor hosts.
fn inventory(ctx: &Ctx, settings: &[PathBuf]) -> Step<Value> {
    let mut request = ctx.detection_request("cline");
    let settings: Vec<String> = settings.iter().map(|path| path_text(path)).collect();
    request.insert("mcp_settings".into(), json!(settings));
    Ok(crate::cline_detect::detect(&Value::Object(request))?)
}

fn host_fields(cli: (Option<String>, Option<String>), artifacts: &Value) -> Hosts {
    let hosts: Vec<&Value> = artifacts
        .as_array()
        .map(|artifacts| {
            artifacts
                .iter()
                .filter(|artifact| artifact["artifact_type"] == "harness_host")
                .collect()
        })
        .unwrap_or_default();
    let surface = |name: &str, key: &str| -> Vec<String> {
        hosts
            .iter()
            .filter(|host| host["metadata"]["surface"] == name)
            .filter_map(|host| match key {
                "version" => host["metadata"]["version"].as_str().map(str::to_owned),
                _ => host["config_path"].as_str().map(str::to_owned),
            })
            .collect()
    };
    Hosts {
        cli: cli.0,
        version: cli.1,
        vscode: surface("vscode", "version"),
        jetbrains: surface("jetbrains", "config_path"),
    }
}

/// `detect_cline_hosts`: the hosts without reading MCP settings.
pub(super) fn hosts(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Hosts> {
    let found = inventory(ctx, &[])?;
    Ok(host_fields(cli(fields), &found["artifacts"]))
}

fn cli_artifact(hosts: &Hosts) -> Option<Value> {
    let path = hosts.cli.as_deref()?;
    let parent = Path::new(path).parent().unwrap_or(Path::new(""));
    let mut metadata = Map::new();
    let version = hosts.version.as_deref().unwrap_or("unknown");
    metadata.insert("version".into(), json!(version));
    metadata.insert("surface".into(), json!("cli"));
    let scope = Scope {
        harness: "cline",
        scope: "global",
    };
    let fields = Fields {
        command: Some(path),
        ..Fields::default()
    };
    Some(scope.wire(
        "cline:host:cli".to_owned(),
        "Cline CLI",
        "harness_host",
        parent,
        fields,
        metadata,
    ))
}

/// Hook state for reads that never use `ready`, so no canary runs.
fn hook_inventory(ctx: &Ctx) -> Step<Value> {
    cline_hooks::state(ctx, false, None).map_err(|need| match need {
        Need::Fail(failure) => failure,
        Need::Canary(_) => Failure::Invalid,
    })
}

fn installed(state: &Value) -> bool {
    state["installed"] == json!(true)
}

fn detect(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut found = inventory(ctx, &cline_mcp::candidates(ctx)?)?;
    let hosts = host_fields(cli(fields), &found["artifacts"]);
    let hooks = hook_inventory(ctx)?;
    let plugin = cline_plugin::state(ctx);
    let mut warnings = Vec::new();
    if installed(&hooks) && installed(&plugin) {
        warnings.push(json!(DUPLICATE_DETECTED));
    }
    warnings.extend(found["warnings"].as_array().cloned().unwrap_or_default());
    let mut artifacts: Vec<Value> = cli_artifact(&hosts).into_iter().collect();
    artifacts.extend(found["artifacts"].as_array().cloned().unwrap_or_default());
    let config_paths = found["found_paths"].take();
    let has_paths = config_paths
        .as_array()
        .is_some_and(|paths| !paths.is_empty());
    let present = !hosts.names().is_empty() || has_paths || installed(&hooks) || installed(&plugin);
    Ok(json!({
        "artifacts": artifacts,
        "config_paths": config_paths,
        "warnings": warnings,
        "installed": present,
        "command_available": hosts.cli.is_some(),
        "workspace_aibom": spec.workspace_aibom,
        "firewall": true,
    }))
}

/// The recorded adapter state, or an empty object.
pub(super) fn adapter_state(ctx: &Ctx) -> Map<String, Value> {
    match state_text(&adapter_state_path(ctx)).map(|text| serde_json::from_str::<Value>(&text)) {
        Some(Ok(Value::Object(state))) => state,
        _ => Map::new(),
    }
}

/// The `canary` run Python sent, if any.
pub(super) fn canary_run(fields: &Map<String, Value>) -> Option<&Value> {
    fields.get("canary").filter(|run| !run.is_null())
}

fn runtime_probe(ctx: &Ctx, fields: &Map<String, Value>) -> Read<Value> {
    let hosts = hosts(ctx, fields)?;
    let hooks = cline_hooks::state(ctx, true, canary_run(fields))?;
    let plugin = cline_plugin::state(ctx);
    let active = adapter_state(ctx)
        .remove("active_transport")
        .unwrap_or(Value::Null);
    Ok(json!({ "probe": {
        "hosts": hosts.names(),
        "cli_version": hosts.version,
        "vscode_versions": hosts.vscode,
        "jetbrains_detected": !hosts.jetbrains.is_empty(),
        "active_transport": active,
        "duplicate_managed_transports": installed(&hooks) && installed(&plugin),
        "native_hooks": hooks,
        "plugin": plugin,
        "mcp": cline_mcp::state(ctx),
    }}))
}

fn diagnostic_warnings(fields: &Map<String, Value>) -> Step<Value> {
    let mut warnings = fields
        .get("warnings")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(Failure::Invalid)?;
    let probe = match fields.get("probe") {
        Some(Value::Object(probe)) => probe,
        _ => return Ok(json!({ "warnings": warnings })),
    };
    if probe.get("duplicate_managed_transports") == Some(&json!(true)) {
        warnings.push(json!(DUPLICATE));
    }
    let key = match probe.get("active_transport") {
        Some(Value::String(transport)) if transport == "plugin" => "plugin",
        _ => "native_hooks",
    };
    if let Some(Value::Object(state)) = probe.get(key) {
        if state.get("ready") != Some(&json!(true)) {
            warnings.push(json!(PENDING));
        }
    }
    if probe.get("jetbrains_detected") == Some(&json!(true)) {
        warnings.push(json!(JETBRAINS));
    }
    Ok(json!({ "warnings": warnings }))
}

/// A hook-state read: the canary request Python must run, or the failure.
pub(super) fn settle(read: Read<Value>) -> Step<Value> {
    match read {
        Ok(value) => Ok(value),
        Err(Need::Canary(request)) => Ok(json!({ "canary": request })),
        Err(Need::Fail(failure)) => Err(failure),
    }
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
                .as_deref()
                .unwrap_or(&ctx.home)
                .join(".mcp.json"),
        ),
        "resolved_executable" => {
            let candidates = [".local", ".bun", ".npm-global"]
                .map(|base| ctx.home.join(base).join("bin").join("cline"));
            resolved_executable(spec, ctx, &candidates)
        }
        "detect" => detect(spec, ctx, fields),
        "runtime_probe" => settle(runtime_probe(ctx, fields)),
        "diagnostic_warnings" => diagnostic_warnings(fields),
        "mcp_scan" => cline_mcp::scan(ctx),
        "mcp_apply" => cline_mcp::apply(ctx, fields),
        "install_plan" | "install_transport" | "confirm_transport" | "finish_install"
        | "uninstall" => cline_install::dispatch(op, ctx, fields),
        _ => common(spec, op, ctx),
    }
}
