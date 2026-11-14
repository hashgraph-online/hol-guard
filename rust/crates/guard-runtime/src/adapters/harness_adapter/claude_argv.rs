//! The argv vectors Guard's Claude Code hook entries run: the `guard hook`
//! fallback, the daemon hook and the SessionStart hook, each in its native,
//! frozen or source-checkout form.
//!
//! Python answers a `{"reply": {"facts": null}}` with what only the Guard
//! process knows: the native runtimes that carry each hook feature, whether it
//! is a frozen build and its stable launcher, its interpreter and package
//! root, the daemon URL, the query extras the attributed harness adds, and the
//! daemon recovery commands.

use serde_json::{json, Map, Value};

use super::cursor::get;
use super::{path_text, Ctx, Failure, Step};
use crate::claude_hook_plan::py_repr_str;
use crate::claude_session_start_contract::{
    bridge_config_text, DaemonHookTemplate, HookGroupsContract,
};
use crate::hook_env_stamp::json_string;
use crate::pyjson::{self, PyVal};

pub(super) const NATIVE_COMMAND: &str = "claude-hook-bridge";
const SESSION_START_MODE: &str = "session-start";
const FROZEN_COMMAND: &str = "__guard-claude-hook";

/// What the Guard process answered for `facts`.
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
    query_extras: Vec<(String, String)>,
    /// The daemon recovery command for the caller's own home.
    recovery_home: Option<Vec<String>>,
    /// The daemon recovery command for the context's home.
    recovery_context: Option<Vec<String>>,
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

fn strings(value: &PyVal) -> Step<Vec<String>> {
    value
        .as_list()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

fn optional_strings(value: Option<&PyVal>) -> Step<Option<Vec<String>>> {
    match value {
        None | Some(PyVal::Null) => Ok(None),
        Some(value) => strings(value).map(Some),
    }
}

/// The facts merged into this request, or the reply that asks for them.
pub(super) fn facts(fields: &Map<String, Value>) -> Step<Facts> {
    let Some(raw) = fields.get("facts") else {
        return Err(Failure::Reply(json!({ "facts": null })));
    };
    let raw = raw.as_str().ok_or(Failure::Invalid)?;
    let Ok(PyVal::Dict(facts)) = pyjson::parse(raw) else {
        return Err(Failure::Invalid);
    };
    let query_extras = get(&facts, "query_extras")
        .and_then(PyVal::as_list)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|pair| match strings(pair)?.as_slice() {
            [key, value] => Ok((key.clone(), value.clone())),
            _ => Err(Failure::Invalid),
        })
        .collect::<Step<Vec<_>>>()?;
    Ok(Facts {
        bridge: optional_text(get(&facts, "bridge"))?,
        session_runtime: optional_text(get(&facts, "session_runtime"))?,
        runtime_build: optional_text(get(&facts, "runtime_build"))?,
        frozen: matches!(get(&facts, "frozen"), Some(PyVal::Bool(true))),
        launcher: optional_text(get(&facts, "launcher"))?,
        python: required_text(get(&facts, "python"))?,
        package_root: required_text(get(&facts, "package_root"))?,
        daemon_url: required_text(get(&facts, "daemon_url"))?,
        query_extras,
        recovery_home: optional_strings(get(&facts, "recovery_home"))?,
        recovery_context: optional_strings(get(&facts, "recovery_context"))?,
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
fn query(ctx: &Ctx, extras: &[(String, String)]) -> String {
    let mut pairs = vec![("guard-home".to_owned(), path_text(&ctx.guard_home))];
    if !ctx.default_home() {
        pairs.push(("home".to_owned(), path_text(&ctx.home)));
    }
    if let Some(workspace) = workspace(ctx) {
        pairs.push(("workspace".to_owned(), workspace));
    }
    for (key, value) in extras {
        match pairs.iter_mut().find(|(name, _)| name == key) {
            Some(pair) => pair.1 = value.clone(),
            None => pairs.push((key.clone(), value.clone())),
        }
    }
    crate::runner_sync_url::urlencode(&pairs)
}

/// The recovery command the bridge config carries: the query names the home
/// only when it is not the caller's own.
fn recovery<'a>(ctx: &Ctx, facts: &'a Facts) -> Step<&'a [String]> {
    let recovery = if ctx.default_home() {
        &facts.recovery_home
    } else {
        &facts.recovery_context
    };
    recovery.as_deref().ok_or(Failure::Invalid)
}

/// `bridge_config_template`: the daemon hook config, less the daemon URL.
struct Template {
    state_path: String,
    fallback_command: Vec<String>,
    query: String,
    recovery_command: Option<Vec<String>>,
}

fn template(ctx: &Ctx, facts: &Facts, query: String, native: bool) -> Step<Template> {
    Ok(Template {
        state_path: path_text(&ctx.guard_home.join("daemon-state.json")),
        fallback_command: hook_argv(ctx, facts)?,
        query,
        recovery_command: if native {
            Some(recovery(ctx, facts)?.to_vec())
        } else {
            None
        },
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
        if let Some(recovery) = &self.recovery_command {
            parts.push(format!("\"recovery_command\":{}", list(recovery)));
        }
        format!("{{{}}}", parts.join(","))
    }

    /// `bridge_config_text(template, daemon_url)`.
    fn text(&self, contract: &HookGroupsContract, daemon_url: &str) -> Step<String> {
        let mut config = Map::new();
        config.insert("state_path".into(), json!(self.state_path));
        config.insert("fallback_command".into(), json!(self.fallback_command));
        config.insert("query".into(), json!(self.query));
        if let Some(recovery) = &self.recovery_command {
            config.insert("recovery_command".into(), json!(recovery));
        }
        let template = DaemonHookTemplate {
            command: Vec::new(),
            bridge_config: config,
        };
        bridge_config_text(contract, &template, daemon_url).ok_or(Failure::Invalid)
    }
}

/// `daemon_hook_command_parts`: the native bridge, else the frozen launcher,
/// else the source checkout's compatibility bridge.
pub(super) fn daemon_argv(
    ctx: &Ctx,
    facts: &Facts,
    contract: &HookGroupsContract,
) -> Step<Vec<String>> {
    let query = query(ctx, &facts.query_extras);
    let template = template(ctx, facts, query, facts.bridge.is_some())?;
    let config = template.text(contract, &facts.daemon_url)?;
    let marker = contract.daemon_hook_marker.clone();
    if let Some(bridge) = &facts.bridge {
        return Ok(vec![
            bridge.clone(),
            NATIVE_COMMAND.to_owned(),
            marker,
            config,
        ]);
    }
    if facts.frozen {
        let launcher = facts.launcher()?.to_owned();
        return Ok(vec![launcher, FROZEN_COMMAND.to_owned(), marker, config]);
    }
    let code = format!(
        "_HOL_GUARD_CLAUDE_DAEMON_HOOK_MARKER = {};import sys;sys.path.insert(0, {});\
         from codex_plugin_scanner.guard.adapters.claude_daemon_hook_bridge import \
         _bridge_config_from_argv,main;_config=_bridge_config_from_argv(sys.argv);\
         raise SystemExit(main(state_path=_config['state_path'], \
         fallback_daemon_url=_config['fallback_daemon_url'], \
         fallback_command=_config['fallback_command'], query=_config['query']))",
        py_repr_str(&marker),
        facts.root()
    );
    Ok(vec![facts.python.clone(), "-c".to_owned(), code, config])
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
    let template = template(ctx, facts, query(ctx, &[]), true)?;
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
             from codex_plugin_scanner.guard.adapters.claude_code import \
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
