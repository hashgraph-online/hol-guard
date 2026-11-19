//! `detect_merged` and `detect_all`: a harness's detection with the shared
//! workspace AIBOM artifacts merged in, as `extend_detection_with_workspace_aibom`
//! extended it from the caller's process.
//!
//! The plan comes from the same `workspace_merge_plan` the install ops use. A
//! plan that adds nothing leaves the answer as the harness's own `detect`
//! wrote it; otherwise its replacements and appended artifacts join the
//! artifacts and its found paths join the config paths, without repeats.

use serde_json::{json, Map, Value};

use crate::aibom_op::workspace_merge_plan;
use crate::harness_adapter::describe::{spec, Spec};
use crate::harness_adapter::{path_text, route, Ctx, Failure, Step};

/// The registry order `list_adapters` returned the harnesses in.
pub(super) const ORDER: [&str; 18] = [
    "codex",
    "claude-code",
    "copilot",
    "cursor",
    "cline",
    "devin",
    "antigravity",
    "gemini",
    "grok",
    "hermes",
    "kimi",
    "omp",
    "pi",
    "openclaw",
    "opencode",
    "zcode",
    "paseo",
    "muse",
];

fn invalid() -> Failure {
    Failure::Refusal("native_runner_authority_result_invalid".into())
}

/// The artifacts as `workspace_merge_plan` reads the ones already found.
fn existing(answer: &Value) -> Step<Vec<Value>> {
    Ok(answer
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|artifact| {
            let key = |name: &str| artifact.get(name).cloned().unwrap_or(Value::Null);
            json!({
                "artifact_id": key("artifact_id"),
                "artifact_type": key("artifact_type"),
                "harness": key("harness"),
                "config_path": key("config_path").as_str().map_or(Value::Null, |path| json!(path)),
            })
        })
        .collect())
}

/// The plan for one harness's answer, or null when its detection takes no
/// workspace artifacts or there is no workspace.
pub(super) fn plan(ctx: &Ctx, harness: &str, answer: &Value) -> Step<Value> {
    let Some(workspace) = ctx.workspace.as_deref() else {
        return Ok(Value::Null);
    };
    if answer.get("workspace_aibom") != Some(&Value::Bool(true)) {
        return Ok(Value::Null);
    }
    workspace_merge_plan(&json!({
        "harness": harness,
        "workspace_dir": path_text(&ctx.absolute(workspace)),
        "existing": existing(answer)?,
    }))
    .map_err(|_| Failure::Invalid)
}

/// The answer with `plan` applied.
fn apply(answer: &mut Value, plan: &Value) -> Step<()> {
    if plan.is_null() || plan.get("extra_count").and_then(Value::as_i64) == Some(0) {
        return Ok(());
    }
    let list = |key: &str| plan.get(key).and_then(Value::as_array).ok_or_else(invalid);
    let (replacements, appended, found) = (
        list("replacements")?,
        list("appended")?,
        list("found_paths")?,
    );
    let artifacts = answer
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .ok_or(Failure::Invalid)?;
    for replacement in replacements {
        let index = replacement
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < artifacts.len())
            .ok_or_else(invalid)?;
        artifacts[index] = replacement.get("artifact").cloned().ok_or_else(invalid)?;
    }
    artifacts.extend(appended.iter().cloned());
    let mut paths: Vec<Value> = answer
        .get("config_paths")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for path in found {
        path.as_str().ok_or_else(invalid)?;
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    answer["config_paths"] = Value::Array(paths);
    Ok(())
}

/// `detect_merged`: one harness's detection, merged. A Codex whose hook files
/// are not trusted answers `untrusted` untouched.
pub(super) fn one(spec: &Spec, ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut answer = route(spec, "detect", ctx, fields)?;
    if answer.get("untrusted").is_some() {
        return Ok(answer);
    }
    let plan = plan(ctx, spec.harness, &answer)?;
    apply(&mut answer, &plan)?;
    Ok(answer)
}

/// `detect_all`: every harness's merged detection in registry order, each
/// named by its `harness`, or the first untrusted answer.
pub(super) fn all(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut detections = Vec::with_capacity(ORDER.len());
    for name in ORDER {
        let spec = spec(name).ok_or(Failure::Invalid)?;
        let mut answer = one(spec, ctx, fields)?;
        if answer.get("untrusted").is_some() {
            return Ok(answer);
        }
        answer["harness"] = json!(name);
        detections.push(answer);
    }
    Ok(json!({ "detections": detections }))
}
