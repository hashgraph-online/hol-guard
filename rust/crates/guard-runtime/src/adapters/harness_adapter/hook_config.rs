//! The config a bounded hook command carries: the `guard hook` arguments a
//! `hook_spec` names, bound to the calling Guard process.
//!
//! The Python adapter no longer gathers the interpreter, package root and
//! frozen state to build it. `bounded_cli_hook_command` used to write this
//! JSON itself; the native runtime now answers it as the `config` of a
//! `hook_spec` (and the `workspace_config` of a spec with workspace
//! arguments). The same answers carry `hook_argv`, the command a harness runs
//! for it: the signed Desktop proxy launch when a frozen Desktop Core has one,
//! else the caller's validated native runtime in its bounded bridge.
//! `bounded_hook_command_for_config` and `native_bridge_executable` built it in
//! Python before.

use serde_json::{json, Map, Value};

use super::{caller, path_text, proxy_launch, Ctx, Failure, Spec, Step};
use crate::desktop_hook_proxy::signed_argv;
use crate::hook_env_stamp::json_string;

/// The subcommand of the native runtime that answers a bounded hook.
const BOUNDED_COMMAND: &str = "bounded-hook-bridge";
const BOUNDED_FEATURE: &str = "bounded-hook-bridge-v1";
/// A runtime without this feature refuses a Muse config.
const MUSE_FEATURE: &str = "bounded-hook-bridge-muse-v1";
/// The harnesses whose hook the native runtime answers from the daemon itself.
const BOUNDED_HARNESSES: [&str; 10] = [
    "copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode", "grok", "muse",
];
const DESKTOP: &str = "HOL_GUARD_DESKTOP";
const DESKTOP_PROXY: &str = "HOL_GUARD_DESKTOP_HOOK_PROXY";
/// The refusal an install without a native runtime answers.
const RUNTIME_MISSING: &str =
    "HOL Guard's native runtime is missing, so Guard blocked this hook. Run `hol-guard repair`.";

/// `json.dumps(..., ensure_ascii=True)` for one string.
fn ascii(text: &str) -> String {
    json_string(text, true, false)
}

/// The compact config JSON `bounded_cli_hook_command` wrote.
fn config(ctx: &Ctx, harness: &str, cli_args: &[String], timeout_seconds: i64) -> Step<String> {
    let frozen = caller::frozen(ctx)?;
    let args: Vec<String> = cli_args.iter().map(|arg| ascii(arg)).collect();
    Ok(format!(
        "{{\"python_executable\":{},\"package_root\":{},\"guard_home\":{},\"cli_args\":[{}],\
         \"harness\":{},\"timeout_seconds\":{},\"frozen_launcher\":{}}}",
        ascii(caller::cli_executable(ctx)?),
        ascii(caller::package_root(ctx)?),
        ascii(&path_text(&ctx.resolved(&ctx.guard_home))),
        args.join(","),
        ascii(harness),
        timeout_seconds,
        frozen
    ))
}

fn arguments(value: &Value) -> Step<Vec<String>> {
    value
        .as_array()
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|arg| arg.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

/// The command a harness runs for a bounded
/// hook config. A frozen Desktop Core with a verified signed proxy runs
/// through it; otherwise the native runtime that carries the bounded bridge
/// feature, which a frozen caller names by its durable copy.
fn bounded_argv(ctx: &Ctx, harness: &str, config: &str) -> Step<Vec<String>> {
    let frozen = caller::frozen(ctx)?;
    if frozen {
        let proxy = signed_argv(
            caller::cli_executable(ctx)?,
            config,
            false,
            ctx.env(DESKTOP),
            ctx.env(DESKTOP_PROXY),
        );
        if let Some(argv) = proxy {
            return Ok(argv);
        }
    }
    let feature = if harness == "muse" {
        MUSE_FEATURE
    } else {
        BOUNDED_FEATURE
    };
    let guard_home = ctx.resolved(&ctx.guard_home);
    let native = if BOUNDED_HARNESSES.contains(&harness) {
        proxy_launch::bridge(ctx, feature, Some(guard_home.as_path()).filter(|_| frozen))?
    } else {
        None
    };
    let native = native.ok_or_else(|| Failure::Runtime(RUNTIME_MISSING.to_owned()))?;
    Ok(vec![native, BOUNDED_COMMAND.to_owned(), config.to_owned()])
}

/// The command a bounded hook of `harness` runs for the `guard hook`
/// arguments it names.
pub(super) fn hook_argv(
    ctx: &Ctx,
    harness: &str,
    cli_args: &[String],
    timeout_seconds: i64,
) -> Step<Vec<String>> {
    bounded_argv(
        ctx,
        harness,
        &config(ctx, harness, cli_args, timeout_seconds)?,
    )
}

/// A `hook_spec` answer with the bounded hook config of each argument list
/// it names.
pub(super) fn with_config(spec: &Spec, ctx: &Ctx, mut answer: Value) -> Step<Value> {
    let fields: &mut Map<String, Value> = answer.as_object_mut().ok_or(Failure::Invalid)?;
    let timeout = fields
        .get("timeout_seconds")
        .and_then(Value::as_i64)
        .ok_or(Failure::Invalid)?;
    let cli_args = arguments(fields.get("cli_args").ok_or(Failure::Invalid)?)?;
    let main = config(ctx, spec.harness, &cli_args, timeout)?;
    let (workspace, workspace_argv) = match fields.get("workspace_cli_args") {
        None | Some(Value::Null) => (Value::Null, Value::Null),
        Some(args) => {
            let text = config(ctx, spec.harness, &arguments(args)?, timeout)?;
            let argv = bounded_argv(ctx, spec.harness, &text)?;
            (json!(text), json!(argv))
        }
    };
    fields.insert(
        "hook_argv".to_owned(),
        json!(bounded_argv(ctx, spec.harness, &main)?),
    );
    fields.insert("workspace_hook_argv".to_owned(), workspace_argv);
    fields.insert("config".to_owned(), json!(main));
    fields.insert("workspace_config".to_owned(), workspace);
    Ok(answer)
}

/// `{"config": ...}`, the bounded hook config for the `cli_args` and
/// `timeout_seconds` the caller names, for an adapter that builds its own
/// hook argument list.
pub(super) fn answer(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let timeout = fields
        .get("timeout_seconds")
        .and_then(Value::as_i64)
        .ok_or(Failure::Invalid)?;
    let cli_args = arguments(fields.get("cli_args").ok_or(Failure::Invalid)?)?;
    let text = config(ctx, spec.harness, &cli_args, timeout)?;
    let argv = bounded_argv(ctx, spec.harness, &text)?;
    Ok(json!({ "config": text, "hook_argv": argv }))
}
