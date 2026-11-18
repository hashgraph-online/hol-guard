//! `default_launch`: the launch for a harness with no launcher of its own.

use serde_json::{json, Map, Value};

use super::{path_text, route, Ctx, Failure, Spec, Step};

/// `{"argv": [...]}`, the launch for a harness with no launcher of its own:
/// its resolved executable or else its bare name, the workspace for the two
/// harnesses that open one, then the caller's `args`.
pub(super) fn answer(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let args = fields
        .get("args")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|arg| arg.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    let resolved = route(spec, "resolved_executable", ctx, fields)?;
    let mut argv = vec![resolved
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(spec.executable)
        .to_owned()];
    if matches!(spec.harness, "opencode" | "claude-code") {
        argv.extend(ctx.workspace.as_deref().map(path_text));
    }
    argv.extend(args);
    Ok(json!({ "argv": argv }))
}
