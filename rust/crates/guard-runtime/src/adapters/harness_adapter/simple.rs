//! Gemini and Antigravity: detection and policy paths; the install is the
//! launcher shim alone.

use serde_json::{Map, Value};

use super::{common, detection, path_answer, which, Ctx, Spec, Step};

/// The settings file under `.gemini` each harness reads policy from.
fn policy_parts(spec: &Spec) -> &'static [&'static str] {
    if spec.harness == "antigravity" {
        &[".gemini", "antigravity", "mcp_config.json"]
    } else {
        &[".gemini", "settings.json"]
    }
}

pub(crate) fn dispatch(spec: &Spec, op: &str, ctx: &Ctx, _: &Map<String, Value>) -> Step<Value> {
    match op {
        "policy_path" => {
            let base = ctx.workspace.as_ref().unwrap_or(&ctx.home);
            path_answer(
                &policy_parts(spec)
                    .iter()
                    .fold(base.clone(), |path, part| path.join(part)),
            )
        }
        "detect" => {
            let request = Value::Object(ctx.detection_request(spec.harness));
            let found = if spec.harness == "antigravity" {
                crate::antigravity_detect::detect(&request)
            } else {
                crate::gemini_detect::detect(&request)
            };
            let available = which::command_available(ctx, spec.executable, Some(&ctx.home), &[]);
            detection(spec, found, available)
        }
        _ => common(spec, op, ctx),
    }
}
