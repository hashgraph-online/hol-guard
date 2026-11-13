//! The Pi-family extension's runtime half: the `hol-guard` it runs, the
//! `pi_extension_render` request, and the doctor checks that read a rendered
//! extension back (a pinned Desktop Core, Oh My Pi's code mode).
//!
//! Requests that render the extension carry `runtime`, the facts only the
//! Guard process holds: `installing_cli` (its own `hol-guard` entry points),
//! `native_hook_runtime` and, on Windows, `windows` with the interpreter,
//! package root, contained sink argv, request root and `taskkill` path.

use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{json, Map, Value};

use super::desktop_core;
use super::kimi::expand_user;
use super::{path_text, which, Ctx, Failure, Step};
use crate::guard_store_json::py_repr_str;

pub(super) const EXTENSION_NAME: &str = "hol-guard.ts";
const REMOTE_PREFIXES: [&str; 5] = ["npm:", "git:", "http://", "https://", "ssh://"];
const MAX_EXTENSION_BYTES: u64 = 2_000_000;
/// The daemon compatibility the extension's readiness check expects.
const COMPATIBILITY_VERSION: i64 = 2;
const DESKTOP_RUNTIME_OWNER: &str = "HOL_GUARD_DESKTOP_RUNTIME_OWNER";

fn guard_args(ctx: &Ctx, harness: &str) -> Vec<String> {
    let mut args = vec![
        "hook".to_owned(),
        "--json".to_owned(),
        "--guard-home".to_owned(),
        path_text(&ctx.guard_home),
        "--harness".to_owned(),
        harness.to_owned(),
    ];
    if !ctx.default_home() {
        args.extend(["--home".to_owned(), path_text(&ctx.home)]);
    }
    args
}

/// The process facts the Guard process sent.
pub(super) struct Runtime<'a>(&'a Map<String, Value>);

impl<'a> Runtime<'a> {
    pub(super) fn parse(fields: &'a Map<String, Value>) -> Step<Self> {
        fields
            .get("runtime")
            .and_then(Value::as_object)
            .map(Self)
            .ok_or(Failure::Invalid)
    }

    fn installing_cli(&self) -> Step<Vec<&'a str>> {
        self.0
            .get("installing_cli")
            .and_then(Value::as_array)
            .ok_or(Failure::Invalid)?
            .iter()
            .map(|item| item.as_str().ok_or(Failure::Invalid))
            .collect()
    }

    fn windows(&self) -> Step<&'a Map<String, Value>> {
        self.0
            .get("windows")
            .and_then(Value::as_object)
            .ok_or(Failure::Invalid)
    }
}

/// The durable `hol-guard` the extension runs: Desktop's runtime owner, its
/// app-data launcher, the official user install, then the installing
/// runtime's own entry points. An AppImage mount and a versioned Desktop Core
/// never own the extension; `hol-guard` on PATH is the last resort.
fn stable_cli(ctx: &Ctx, runtime: &Runtime) -> Step<String> {
    let mut candidates: Vec<String> = Vec::new();
    candidates.extend(ctx.env(DESKTOP_RUNTIME_OWNER).map(str::to_owned));
    candidates.extend(desktop_core::durable_current(ctx, &ctx.home).map(|path| path_text(&path)));
    candidates.push(path_text(
        &ctx.home.join(".local").join("bin").join("hol-guard"),
    ));
    candidates.extend(runtime.installing_cli()?.into_iter().map(str::to_owned));
    for candidate in candidates.iter().filter(|candidate| !candidate.is_empty()) {
        let path = ctx.absolute(&expand_user(ctx, candidate));
        let resolved = ctx.resolved(&path);
        let normalized = path_text(&path).replace('\\', "/").to_lowercase();
        if normalized.contains("/tmp/.mount_") {
            continue;
        }
        if let Some(shim) = desktop_core::shim_for_executable(ctx, &resolved) {
            if shim.is_file() && which::executable(&shim) {
                return Ok(path_text(&shim));
            }
            continue;
        }
        if path.is_file() && which::executable(&path) {
            return Ok(path_text(&path));
        }
    }
    Ok("hol-guard".to_owned())
}

fn windows_cli_bootstrap(package_root: &str, guard_home: &str, harness: &str) -> String {
    format!(
        "import json,os,sys;sys.path.insert(0,{root});\
         from codex_plugin_scanner.guard.codex_hook_windows_job import assign_current_process_to_windows_hook_job;\
         _windows_job=assign_current_process_to_windows_hook_job() if os.name=='nt' else None;\
         sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;\
         sys.stderr.flush() if _windows_job is not None else None;from pathlib import Path;\
         from codex_plugin_scanner.guard.hook_execution_environment import stamp_hook_input_text;\
         from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import run_bounded_cli_hook;\
         argv=json.loads(sys.argv[1]);config={{'python_executable':sys.executable,\
         'package_root':{root},'guard_home':{home},\
         'cli_args':argv,'harness':{harness},'timeout_seconds':0.75}};\
         raise SystemExit(run_bounded_cli_hook(config,input_text=stamp_hook_input_text(sys.stdin.read(1000001))))",
        root = py_repr_str(package_root),
        home = py_repr_str(guard_home),
        harness = py_repr_str(harness),
    )
}

fn windows_recovery_bootstrap(package_root: &str, guard_home: &str, home: &str) -> String {
    format!(
        "import os,sys;sys.path.insert(0,{root});\
         from codex_plugin_scanner.guard.codex_hook_windows_job import assign_current_process_to_windows_hook_job;\
         _windows_job=assign_current_process_to_windows_hook_job(allow_breakaway=True) if os.name=='nt' else None;\
         sys.stderr.write('HOL_GUARD_WINDOWS_JOB_CONTAINED\\n') if _windows_job is not None else None;\
         sys.stderr.flush() if _windows_job is not None else None;from pathlib import Path;\
         from codex_plugin_scanner.guard.native_daemon_manage import recover_guard_daemon_after_hook_failure;\
         recover_guard_daemon_after_hook_failure(Path({guard_home}),\
         home_dir=Path({home}),failure_kind=sys.argv[1])",
        root = py_repr_str(package_root),
        guard_home = py_repr_str(guard_home),
        home = py_repr_str(home),
    )
}

/// The `pi_extension_render` request for `variant` with this harness's names.
fn render_request(
    ctx: &Ctx,
    runtime: &Runtime,
    variant: &str,
    harness: &str,
    display_name: &str,
    settings: &Path,
) -> Step<Value> {
    let guard_home = path_text(&ctx.guard_home);
    let hook_args = guard_args(ctx, harness);
    let mut request = json!({
        "variant": variant,
        "harness": harness,
        "display_name": display_name,
        "guard_args": hook_args,
        "guard_home": guard_home,
        "home_dir": path_text(&ctx.home),
        "home_dir_is_default": ctx.default_home(),
        "config_path": path_text(settings),
        "compatibility_version": COMPATIBILITY_VERSION,
        "taskkill_path": null,
    });
    let (sink, request_root) = if ctx.windows {
        let windows = runtime.windows()?;
        let field = |key: &str| {
            windows
                .get(key)
                .and_then(Value::as_str)
                .ok_or(Failure::Invalid)
        };
        let python = field("python")?;
        let root = field("package_root")?;
        request["cli_command"] = json!(python);
        request["cli_args"] = json!([
            "-I",
            "-c",
            windows_cli_bootstrap(root, &guard_home, harness)
        ]);
        request["cli_accepts_json_args"] = json!(true);
        request["recovery_command"] = json!(python);
        request["recovery_args"] = json!([
            "-I",
            "-c",
            windows_recovery_bootstrap(root, &guard_home, &path_text(&ctx.home)),
        ]);
        request["taskkill_path"] = windows.get("taskkill").cloned().unwrap_or(Value::Null);
        (
            windows
                .get("sink_command")
                .cloned()
                .ok_or(Failure::Invalid)?,
            field("request_root")?.to_owned(),
        )
    } else {
        let cli = stable_cli(ctx, runtime)?;
        let mut recovery = vec![
            "daemon".to_owned(),
            "recover".to_owned(),
            "--guard-home".to_owned(),
            guard_home,
        ];
        if !ctx.default_home() {
            recovery.extend(["--home".to_owned(), path_text(&ctx.home)]);
        }
        request["cli_command"] = json!(cli);
        request["cli_args"] = json!(hook_args);
        request["cli_accepts_json_args"] = json!(false);
        request["recovery_command"] = json!(cli);
        request["recovery_args"] = json!(recovery);
        (json!([]), String::new())
    };
    request["recovery_accepts_failure_kind"] = json!(true);
    if variant == "active" {
        request["native_hook_runtime"] = runtime
            .0
            .get("native_hook_runtime")
            .cloned()
            .unwrap_or(Value::Null);
        request["contained_sink_command"] = sink;
        request["contained_request_root"] = json!(request_root);
    }
    Ok(request)
}

pub(super) fn render_source(
    ctx: &Ctx,
    runtime: &Runtime,
    variant: &str,
    harness: &str,
    display_name: &str,
    settings: &Path,
) -> Step<String> {
    let request = render_request(ctx, runtime, variant, harness, display_name, settings)?;
    let answer = crate::pi_extension_render::render(&request)
        .map_err(|error| Failure::Refusal(format!("Pi extension render failed: {error}")))?;
    answer
        .get("source")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Failure::Refusal("Pi extension render answer is malformed".to_owned()))
}

/// The versioned Core launcher the extension bakes once Desktop replaced it.
pub(super) fn pinned_core(ctx: &Ctx, extension: &Path) -> Option<String> {
    let path = ctx.absolute(extension);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_EXTENSION_BYTES {
        return None;
    }
    let source = std::fs::read_to_string(&path).ok()?;
    let baked = Regex::new(
        r#"(?m)^const (?:GUARD_CLI_WRAPPER_COMMAND|GUARD_DAEMON_RECOVERY_COMMAND) = ("(?:[^"\\\n]|\\.)*");$"#,
    )
    .ok()?;
    let pinned = baked.captures_iter(&source).find_map(|captures| {
        let command = match serde_json::from_str::<Value>(&captures[1]) {
            Ok(Value::String(command)) if !command.is_empty() => command,
            _ => return None,
        };
        let launcher = PathBuf::from(&command);
        let shim = desktop_core::shim_for_executable(ctx, &launcher)?;
        (desktop_core::runnable(ctx, &shim) && desktop_core::superseded(ctx, &launcher))
            .then_some(command)
    });
    pinned
}

/// Oh My Pi's code-mode warnings; an explicit home ignores the caller's env.
pub(super) fn code_mode_warnings(ctx: &Ctx) -> Vec<String> {
    let env = |name: &str| (!ctx.home_explicit).then(|| ctx.env(name)).flatten();
    let agent_dir = env("PI_CODING_AGENT_DIR")
        .filter(|dir| !dir.is_empty())
        .map(|dir| path_text(&ctx.absolute(&expand_user(ctx, dir))));
    let request = json!({
        "home": path_text(&ctx.absolute(&ctx.home)),
        "workspace": ctx.workspace.as_ref().map(|workspace| path_text(&ctx.absolute(workspace))),
        "agentDir": agent_dir,
        "configDir": env("PI_CONFIG_DIR"),
    });
    crate::omp_code_mode::dispatch(&request)
        .ok()
        .and_then(|answer| answer.get("warnings").cloned())
        .and_then(|warnings| serde_json::from_value::<Vec<Value>>(warnings).ok())
        .map(|warnings| {
            warnings
                .into_iter()
                .filter_map(|warning| warning.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a local settings entry names a managed extension file.
pub(super) fn managed_reference(ctx: &Ctx, value: &str, settings: &Path) -> bool {
    reference(ctx, value, settings).is_some_and(|candidate| {
        candidate
            .file_name()
            .is_some_and(|name| name == EXTENSION_NAME)
    })
}

/// A local settings entry as a path, relative entries against the settings directory.
fn reference(ctx: &Ctx, value: &str, settings: &Path) -> Option<PathBuf> {
    if REMOTE_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
    {
        return None;
    }
    let candidate = expand_user(ctx, value);
    Some(match candidate.is_absolute() {
        true => candidate,
        false => settings.parent().unwrap_or(Path::new("")).join(candidate),
    })
}

/// Whether a settings entry names the managed file in any spelling.
pub(super) fn names_extension(ctx: &Ctx, value: &str, settings: &Path, extension: &str) -> bool {
    value == extension
        || reference(ctx, value, settings)
            .is_some_and(|path| ctx.resolved(&path) == ctx.resolved(Path::new(extension)))
}
