//! `detected_harnesses`: the harnesses an install or uninstall of `--all`
//! targets, as `_resolve_targets` read them from `detect_all`.
//!
//! Every harness is detected by its own `detect` op, then extended with the
//! shared workspace AIBOM artifacts when its spec asks for it. A harness counts
//! as detected when it is installed, its command is available, or it found
//! config paths or artifacts. The caller's process supplies only the Codex
//! facts its `detect` takes (`facts.codex`, `transition`); the workspace skills
//! are walked here on every platform.

use serde_json::{json, Map, Value};

use crate::aibom_op::workspace_merge_plan;
use crate::harness_adapter::describe::SPECS;
use crate::harness_adapter::{path_text, route, Ctx, Failure, Step};

/// What one harness's detection found, as `HarnessDetection` counts it.
fn found(answer: &Value, extra: &Value) -> bool {
    let flag = |key: &str| answer.get(key).and_then(Value::as_bool) == Some(true);
    let count = |value: &Value, key: &str| {
        value
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, std::vec::Vec::len)
    };
    flag("installed")
        || flag("command_available")
        || count(answer, "config_paths") > 0
        || count(answer, "artifacts") > 0
        || count(extra, "found_paths") > 0
        || count(extra, "appended") > 0
}

/// `extend_detection_with_workspace_aibom`'s plan for one harness's answer.
fn workspace_plan(ctx: &Ctx, harness: &str, answer: &Value) -> Step<Value> {
    let Some(workspace) = ctx.workspace.as_deref() else {
        return Ok(Value::Null);
    };
    if answer.get("workspace_aibom") != Some(&Value::Bool(true)) {
        return Ok(Value::Null);
    }
    let existing: Vec<Value> = answer
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
                "config_path": key("config_path"),
            })
        })
        .collect();
    workspace_merge_plan(&json!({
        "harness": harness,
        "workspace_dir": path_text(&ctx.absolute(workspace)),
        "existing": existing,
    }))
    .map_err(|_| Failure::Invalid)
}

/// The sorted harness names that were detected, or the first detection's
/// failure (a Codex whose hook files are not trusted answers `untrusted`).
pub(super) fn run(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut detected: Vec<&str> = Vec::new();
    for spec in &SPECS {
        let answer = route(spec, "detect", ctx, fields)?;
        if answer.get("untrusted").is_some() {
            return Ok(answer);
        }
        let extra = workspace_plan(ctx, spec.harness, &answer)?;
        if found(&answer, &extra) {
            detected.push(spec.harness);
        }
    }
    detected.sort_unstable();
    Ok(json!({ "harnesses": detected }))
}
