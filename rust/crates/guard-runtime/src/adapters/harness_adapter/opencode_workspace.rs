//! The config paths an OpenCode workspace's own skills, instructions and
//! plugins add to an install's source config paths.

use serde_json::{json, Map, Value};

use super::{Ctx, Failure, Step};
use crate::aibom_extend::Existing;

/// `extend_detection_with_workspace_aibom`: the config paths the workspace's
/// own skills, instructions and plugins add. The portable skill walk of a
/// Windows workspace is Python's; the first answer asks for it.
pub(super) fn workspace_paths(
    ctx: &Ctx,
    fields: &Map<String, Value>,
    artifacts: &[Value],
    mut paths: Vec<String>,
) -> Step<Vec<String>> {
    let Some(workspace) = &ctx.workspace else {
        return Ok(paths);
    };
    let skills = match fields.get("workspace_skills") {
        _ if !ctx.windows => None,
        None => return Err(Failure::Reply(json!({ "workspace_skills": null }))),
        Some(Value::Null) => None,
        Some(Value::Array(skills)) => Some(skills.clone()),
        Some(_) => return Err(Failure::Invalid),
    };
    let field = |artifact: &Value, key: &str| {
        artifact
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(Failure::Invalid)
    };
    let existing = artifacts
        .iter()
        .map(|artifact| {
            Ok(Existing {
                artifact_id: field(artifact, "artifact_id")?,
                artifact_type: field(artifact, "artifact_type")?,
                harness: field(artifact, "harness")?,
                config_path: artifact
                    .get("config_path")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect::<Step<Vec<_>>>()?;
    let plan = crate::aibom_extend::workspace_plan(
        "opencode",
        &ctx.absolute(workspace),
        existing,
        &skills,
    )
    .map_err(|error| Failure::Refusal(error.to_owned()))?;
    if plan.get("extra_count").and_then(Value::as_i64) == Some(0) {
        return Ok(paths);
    }
    let found = plan
        .get("found_paths")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?;
    for path in found {
        paths.push(path.as_str().ok_or(Failure::Invalid)?.to_owned());
    }
    let mut unique: Vec<String> = Vec::with_capacity(paths.len());
    for path in paths {
        if !unique.contains(&path) {
            unique.push(path);
        }
    }
    Ok(unique)
}
