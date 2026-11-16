//! The config a bounded hook command carries: the `guard hook` arguments a
//! `hook_spec` names, bound to the calling Guard process.
//!
//! The Python adapter no longer gathers the interpreter, package root and
//! frozen state to build it. `bounded_cli_hook_command` used to write this
//! JSON itself; the native runtime now answers it as the `config` of a
//! `hook_spec` (and the `workspace_config` of a spec with workspace
//! arguments), and Python only wraps it in the runtime's bounded bridge.

use serde_json::{json, Map, Value};

use super::{caller, path_text, Ctx, Failure, Spec, Step};
use crate::hook_env_stamp::json_string;

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
    let workspace = match fields.get("workspace_cli_args") {
        None | Some(Value::Null) => Value::Null,
        Some(args) => json!(config(ctx, spec.harness, &arguments(args)?, timeout)?),
    };
    fields.insert("config".to_owned(), json!(main));
    fields.insert("workspace_config".to_owned(), workspace);
    Ok(answer)
}
