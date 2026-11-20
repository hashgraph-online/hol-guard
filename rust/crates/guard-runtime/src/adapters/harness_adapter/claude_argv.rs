//! The argv vectors Guard's Claude Code hook entries run: the `guard hook`
//! fallback, the daemon hook and the SessionStart hook, each in its native,
//! frozen or source-checkout form.
//!
//! Python answers a `{"reply": {"facts": null}}` with what only the Guard
//! process knows: the daemon URL and the query extras the attributed harness
//! adds. The caller's frozen state, launchers, interpreter, package root and
//! the native runtimes that carry each hook feature come from the request's
//! `caller` stamp.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::cursor::get;
use super::{path_text, proxy_launch, Ctx, Failure, Step};
use crate::claude_hook_bridge_recovery::frozen_recovery_command;
use crate::claude_hook_plan::py_repr_str;
use crate::claude_session_start_contract::{
    bridge_config_text, DaemonHookTemplate, HookGroupsContract,
};
use crate::hook_env_stamp::json_string;
use crate::hook_process_spawn::isolated_daemon_start_command;
use crate::pyjson::{self, PyVal};

pub(super) const NATIVE_COMMAND: &str = "claude-hook-bridge";
/// The refusal an install without a native runtime answers.
pub(super) const RUNTIME_MISSING: &str =
    "HOL Guard's native runtime is missing, so Guard cannot review hooks. Run `hol-guard repair`.";
const HOOK_FEATURE: &str = "claude-hook-bridge-v1";
const SESSION_START_FEATURE: &str = "claude-session-start-v1";
const SESSION_START_MODE: &str = "session-start";
const FROZEN_COMMAND: &str = "__guard-claude-hook";

/// The caller's stamp and what the Guard process answered for `facts`.
pub(super) struct Facts {
    /// The runtime that carries `claude-hook-bridge-v1`.
    bridge: Option<String>,
    /// The runtime that carries `claude-session-start-v1`.
    session_runtime: Option<String>,
    /// `"{runtime_version}+{build_sha}"` of the running native runtime.
    runtime_build: Option<String>,
    frozen: bool,
    launcher: Option<String>,
    python: String,
    package_root: String,
    daemon_url: String,
    /// `resolve_frozen_guard_cli()`: the program a frozen build recovers
    /// its daemon through.
    recovery_launcher: Option<String>,
}

fn optional_text(value: Option<&PyVal>) -> Step<Option<String>> {
    match value {
        None | Some(PyVal::Null) => Ok(None),
        Some(PyVal::Str(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Failure::Invalid),
    }
}

fn required_text(value: Option<&PyVal>) -> Step<String> {
    optional_text(value)?.ok_or(Failure::Invalid)
}

/// The facts merged into this request, or the reply that asks for them.
pub(super) fn facts(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Facts> {
    let Some(raw) = fields.get("facts") else {
        return Err(Failure::Reply(json!({ "facts": null })));
    };
    let raw = raw.as_str().ok_or(Failure::Invalid)?;
    let Ok(PyVal::Dict(facts)) = pyjson::parse(raw) else {
        return Err(Failure::Invalid);
    };
    let frozen = super::caller::frozen(ctx)?;
    let guard_home = Some(ctx.guard_home.as_path());
    let bridge = proxy_launch::bridge(ctx, HOOK_FEATURE, guard_home)?;
    let session_runtime = proxy_launch::bridge(ctx, SESSION_START_FEATURE, guard_home)?;
    // One runtime carries both hooks, so its build is the running binary's.
    let runtime_build = (bridge.is_some() && bridge == session_runtime)
        .then(crate::claude_session_start::runtime_build);
    Ok(Facts {
        bridge,
        session_runtime,
        runtime_build,
        frozen,
        launcher: if frozen {
            Some(super::caller::launcher(ctx)?.to_owned())
        } else {
            None
        },
        python: super::caller::executable(ctx)?.to_owned(),
        package_root: super::caller::package_root(ctx)?.to_owned(),
        daemon_url: required_text(get(&facts, "daemon_url"))?,
        recovery_launcher: if frozen {
            Some(super::caller::frozen_launcher(ctx)?.to_owned())
        } else {
            None
        },
    })
}

impl Facts {
    /// `guard_cli_launcher()` of a frozen build.
    fn launcher(&self) -> Step<&str> {
        self.launcher.as_deref().ok_or(Failure::Invalid)
    }

    fn root(&self) -> String {
        py_repr_str(&self.package_root)
    }
}

fn workspace(ctx: &Ctx) -> Option<String> {
    ctx.workspace.as_deref().map(path_text)
}

/// `guard_hook_command_parts`: Guard's own `hook` command.
pub(super) fn hook_argv(ctx: &Ctx, facts: &Facts) -> Step<Vec<String>> {
    let mut args = vec![
        "guard".to_owned(),
        "hook".to_owned(),
        format!("--guard-home={}", path_text(&ctx.guard_home)),
    ];
    if !ctx.default_home() {
        args.push(format!("--home={}", path_text(&ctx.home)));
    }
    if let Some(workspace) = workspace(ctx) {
        args.push(format!("--workspace={workspace}"));
    }
    if facts.frozen {
        // The frozen binary is the hol-guard program, where `hook` is a top-level command.
        let mut argv = vec![facts.launcher()?.to_owned()];
        argv.extend(args.into_iter().skip(1));
        return Ok(argv);
    }
    let code = format!(
        "import sys;sys.path.insert(0, {});from codex_plugin_scanner.cli import main;\
         raise SystemExit(main(sys.argv[1:]))",
        facts.root()
    );
    let mut argv = vec![facts.python.clone(), "-c".to_owned(), code];
    argv.extend(args);
    Ok(argv)
}

/// `urlencode(_hook_query(context, extras))`; an extra replaces a key in place.
/// The hook query names only where Guard keeps its state. These hooks live
/// in the user's Claude settings and run in every Claude session, so the
/// installer's own environment says nothing about which app a later hook
/// runs in. A harness or workspace taken from it, such as the Cursor markers
/// of a repair that ran inside Cursor, was written into every hook and filed
/// all Claude sessions under that app and that one project.
fn query(ctx: &Ctx) -> String {
    let mut pairs = vec![("guard-home".to_owned(), path_text(&ctx.guard_home))];
    if !ctx.default_home() {
        pairs.push(("home".to_owned(), path_text(&ctx.home)));
    }
    if let Some(workspace) = workspace(ctx) {
        pairs.push(("workspace".to_owned(), workspace));
    }
    crate::runner_sync_url::urlencode(&pairs)
}

/// The recovery command the bridge config carries (`_recovery`): it binds
/// the caller's own home unless the context names another one.
fn recovery(ctx: &Ctx, facts: &Facts) -> Step<Vec<String>> {
    if facts.bridge.is_none() {
        return Err(Failure::Invalid);
    }
    let home = if ctx.default_home() {
        &ctx.user_home
    } else {
        &ctx.home
    };
    if facts.frozen {
        // A frozen desktop core cannot run the Python `-I -c` bootstrap.
        let launcher = facts.recovery_launcher.as_deref().ok_or(Failure::Invalid)?;
        return frozen_recovery_command(launcher, &ctx.guard_home, home).ok_or(Failure::Invalid);
    }
    Ok(isolated_daemon_start_command(
        &facts.python,
        Path::new(&facts.package_root),
        &ctx.guard_home,
        Some(home),
    ))
}

/// `bridge_config_template`: the daemon hook config, less the daemon URL.
struct Template {
    state_path: String,
    fallback_command: Vec<String>,
    query: String,
    recovery_command: Vec<String>,
}

fn template(ctx: &Ctx, facts: &Facts, query: String) -> Step<Template> {
    Ok(Template {
        state_path: path_text(&ctx.guard_home.join("daemon-state.json")),
        fallback_command: hook_argv(ctx, facts)?,
        query,
        recovery_command: recovery(ctx, facts)?,
    })
}

fn list(items: &[String]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|item| json_string(item, false, false))
        .collect();
    format!("[{}]", parts.join(","))
}

impl Template {
    /// The compact JSON of the template in its own key order.
    fn json(&self) -> String {
        let mut parts = vec![
            format!(
                "\"state_path\":{}",
                json_string(&self.state_path, false, false)
            ),
            format!("\"fallback_command\":{}", list(&self.fallback_command)),
            format!("\"query\":{}", json_string(&self.query, false, false)),
        ];
        parts.push(format!(
            "\"recovery_command\":{}",
            list(&self.recovery_command)
        ));
        format!("{{{}}}", parts.join(","))
    }

    /// `bridge_config_text(template, daemon_url)`.
    fn text(&self, contract: &HookGroupsContract, daemon_url: &str) -> Step<String> {
        let mut config = Map::new();
        config.insert("state_path".into(), json!(self.state_path));
        config.insert("fallback_command".into(), json!(self.fallback_command));
        config.insert("query".into(), json!(self.query));
        config.insert("recovery_command".into(), json!(self.recovery_command));
        let template = DaemonHookTemplate {
            command: Vec::new(),
            bridge_config: config,
        };
        bridge_config_text(contract, &template, daemon_url).ok_or(Failure::Invalid)
    }
}

/// `daemon_hook_command_parts`: the native bridge. Without a runtime there
/// is nothing to review a hook, so installation stops and asks for repair.
pub(super) fn daemon_argv(
    ctx: &Ctx,
    facts: &Facts,
    contract: &HookGroupsContract,
) -> Step<Vec<String>> {
    let Some(bridge) = &facts.bridge else {
        return Err(Failure::Runtime(RUNTIME_MISSING.to_owned()));
    };
    let template = template(ctx, facts, query(ctx))?;
    let config = template.text(contract, &facts.daemon_url)?;
    Ok(vec![
        bridge.clone(),
        NATIVE_COMMAND.to_owned(),
        contract.daemon_hook_marker.clone(),
        config,
    ])
}

/// `session_start_command_parts`: the native lane when it can stand in for
/// the Python refresh, else the Python command.
pub(super) fn session_start_argv(
    ctx: &Ctx,
    facts: &Facts,
    contract: &HookGroupsContract,
) -> Step<Vec<String>> {
    let python_argv = python_session_start_argv(ctx, facts, contract)?;
    Ok(native_session_start_argv(ctx, facts, contract, &python_argv)?.unwrap_or(python_argv))
}

/// The native SessionStart lane, which answers the no-op case in Rust. It
/// reproduces the refresh only for the installing user's own home.
fn native_session_start_argv(
    ctx: &Ctx,
    facts: &Facts,
    contract: &HookGroupsContract,
    python_argv: &[String],
) -> Step<Option<Vec<String>>> {
    let (Some(runtime), Some(build)) = (&facts.session_runtime, &facts.runtime_build) else {
        return Ok(None);
    };
    if facts.bridge.as_ref() != Some(runtime) || !ctx.default_home() {
        return Ok(None);
    }
    let marker = &contract.daemon_hook_marker;
    let template = template(ctx, facts, query(ctx))?;
    let config = format!(
        "{{\"fallback_command\":{},\"home\":{},\"home_dir\":{},\"runtime_build\":{},\
         \"daemon_hook_command\":{},\"bridge_config\":{}}}",
        list(python_argv),
        json_string(&path_text(&ctx.user_home), false, false),
        json_string(&path_text(&ctx.home), false, false),
        json_string(build, false, false),
        list(&[runtime.clone(), NATIVE_COMMAND.to_owned(), marker.clone()]),
        template.json(),
    );
    Ok(Some(vec![
        runtime.clone(),
        NATIVE_COMMAND.to_owned(),
        SESSION_START_MODE.to_owned(),
        contract.session_start_hook_marker.clone(),
        config,
    ]))
}

/// The Python SessionStart command over a shell-free path vector.
pub(super) fn python_session_start_argv(
    ctx: &Ctx,
    facts: &Facts,
    contract: &HookGroupsContract,
) -> Step<Vec<String>> {
    let marker = contract.session_start_hook_marker.clone();
    let mut paths = vec![path_text(&ctx.guard_home), path_text(&ctx.home)];
    paths.extend(workspace(ctx));
    let mut argv = if facts.frozen {
        vec![
            facts.launcher()?.to_owned(),
            FROZEN_COMMAND.to_owned(),
            marker,
        ]
    } else {
        let code = format!(
            "_HOL_GUARD_CLAUDE_SESSION_START_HOOK_MARKER = {};import sys;\
             sys.path.insert(0, {});\
             from codex_plugin_scanner.guard.claude_hook_entry import \
             _run_session_start_from_argv;\
             raise SystemExit(_run_session_start_from_argv(sys.argv[1:]))",
            py_repr_str(&marker),
            facts.root()
        );
        vec![facts.python.clone(), "-c".to_owned(), code]
    };
    argv.extend(paths);
    Ok(argv)
}
