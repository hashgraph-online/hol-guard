//! Codex detection composed natively: `CodexHarnessAdapter.detect` as the
//! install and the `detect` op share it.
//!
//! The filesystem half is the `codex_detect` runner kind. This adds what
//! Python chained around it: the strict source check of a captured
//! generation, the legacy-adoption block, the workspace AIBOM merge plan and
//! the Codex skill inventory that replaces the detected skills. Both walk
//! the skills natively on every platform.

use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use crate::harness_adapter::codex::paths;
use crate::harness_adapter::codex_install_request::detect_legacy;
use crate::harness_adapter::codex_sources::check_sources;
use crate::harness_adapter::{path_text, Ctx, Failure, Step};

/// What detection found: the artifacts as the native kinds wrote them, the
/// config paths they came from, and the warnings.
pub(crate) struct Detection {
    pub(crate) artifacts: Vec<Value>,
    pub(crate) found_paths: Vec<String>,
    pub(crate) warnings: Vec<String>,
    /// Whether the config sources alone named a path, before the workspace and
    /// skill inventories added theirs: what `installed` reads.
    pub(crate) sourced: bool,
}

fn native(code: &'static str) -> Failure {
    Failure::Refusal(code.to_owned())
}

fn malformed() -> Failure {
    native("native_runner_authority_result_invalid")
}

fn list<'a>(answer: &'a Value, key: &str) -> Step<&'a Vec<Value>> {
    answer
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(malformed)
}

fn texts(answer: &Value, key: &str) -> Step<Vec<String>> {
    list(answer, key)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or_else(malformed))
        .collect()
}

fn dedup(paths: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for path in paths {
        if !kept.contains(&path) {
            kept.push(path);
        }
    }
    kept
}

/// The base64 contents of a capture as the hex the runner kind reads.
fn hex_contents(captured: &Map<String, Value>) -> Step<Map<String, Value>> {
    captured
        .iter()
        .map(|(path, data)| {
            let hex = match data {
                Value::Null => Value::Null,
                Value::String(text) => json!(hex::encode(
                    STANDARD.decode(text).map_err(|_| Failure::Invalid)?
                )),
                _ => return Err(Failure::Invalid),
            };
            Ok((path.clone(), hex))
        })
        .collect()
}

/// Anchored on the caller's directory without folding `..`: after a link it
/// names another tree, which the discovery helpers resolve themselves.
fn anchored(ctx: &Ctx, path: &Path) -> String {
    path_text(&ctx.absolute(path))
}

/// `_merge_plan` applied: the workspace's shared artifacts replace or join
/// the detected ones.
fn merge_workspace(ctx: &Ctx, workspace: &Path, detection: &mut Detection) -> Step<()> {
    let existing: Vec<Value> = detection
        .artifacts
        .iter()
        .map(|artifact| {
            json!({
                "artifact_id": artifact.get("artifact_id"),
                "artifact_type": artifact.get("artifact_type"),
                "harness": artifact.get("harness"),
                "config_path": artifact.get("config_path").filter(|path| path.is_string()),
            })
        })
        .collect();
    let request = json!({
        "harness": "codex",
        "workspace_dir": anchored(ctx, workspace),
        "existing": existing,
    });
    let plan = crate::aibom_op::workspace_merge_plan(&request).map_err(native)?;
    let extra = plan
        .get("extra_count")
        .and_then(Value::as_i64)
        .ok_or_else(malformed)?;
    let replacements = list(&plan, "replacements")?;
    let appended = list(&plan, "appended")?;
    let found = texts(&plan, "found_paths")?;
    if extra == 0 {
        return Ok(());
    }
    for replacement in replacements {
        let index = replacement
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < detection.artifacts.len())
            .ok_or_else(malformed)?;
        detection.artifacts[index] = replacement.get("artifact").cloned().ok_or_else(malformed)?;
    }
    detection.artifacts.extend(appended.iter().cloned());
    detection.found_paths = dedup(detection.found_paths.drain(..).chain(found));
    Ok(())
}

/// `extend_codex_runtime_inventory`: the home and workspace skills replace
/// every detected skill.
fn replace_skills(ctx: &Ctx, detection: &mut Detection) -> Step<()> {
    let request = json!({
        "harness": "codex",
        "home_dir": anchored(ctx, &ctx.home),
        "workspace_dir": ctx.workspace.as_deref().map(|workspace| anchored(ctx, workspace)),
        "user_home": path_text(&ctx.user_home),
    });
    let skills = crate::aibom_op::codex_skills(&request).map_err(native)?;
    let mut merged: Vec<Value> = detection
        .artifacts
        .drain(..)
        .filter(|artifact| artifact.get("artifact_type").and_then(Value::as_str) != Some("skill"))
        .collect();
    let mut found = std::mem::take(&mut detection.found_paths);
    for artifact in list(&skills, "artifacts")? {
        let path = artifact
            .get("config_path")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        found.push(path.to_owned());
        merged.push(artifact.clone());
    }
    detection.artifacts = merged;
    detection.found_paths = dedup(found);
    Ok(())
}

/// Detect Codex over its config and hooks sources. `contents` is a capture
/// (a path mapped to base64, or null for an absent file) that an install
/// checks strictly and detects over; without one the sources are read here.
/// `bindings` are the authenticated hook bindings.
pub(crate) fn detect(
    ctx: &Ctx,
    launch: &Map<String, Value>,
    bindings: &[Value],
    contents: Option<&Map<String, Value>>,
) -> Step<Detection> {
    let located = paths(ctx);
    let pairs = located["pairs"].as_array().ok_or(Failure::Invalid)?;
    let mut request = Map::new();
    if let Some(captured) = contents {
        let mut check = Map::new();
        check.insert(
            "pairs".into(),
            Value::Array(
                pairs
                    .iter()
                    .map(|pair| json!([pair["config"], pair["hooks"]]))
                    .collect(),
            ),
        );
        check.insert("contents".into(), Value::Object(captured.clone()));
        check_sources(&check)?;
        request.insert("contents".into(), Value::Object(hex_contents(captured)?));
    }
    let mut asked = Map::new();
    asked.insert("launch".into(), Value::Object(launch.clone()));
    let legacy = detect_legacy(ctx, &asked)?
        .get("legacy")
        .cloned()
        .ok_or(Failure::Invalid)?;
    request.insert("harness".into(), json!("codex"));
    request.insert("authenticated_bindings".into(), json!(bindings));
    request.insert("pairs".into(), Value::Array(pairs.clone()));
    request.insert("authenticated_config".into(), located["config"].clone());
    request.insert("cwd".into(), json!(ctx.cwd.as_deref().map(path_text)));
    request.insert("legacy".into(), legacy);
    let found = crate::codex_detect::detect(&Value::Object(request)).map_err(native)?;
    let found_paths = texts(&found, "found_paths")?;
    let mut detection = Detection {
        artifacts: list(&found, "artifacts")?.clone(),
        sourced: !found_paths.is_empty(),
        found_paths,
        warnings: match found.get("warnings") {
            None => Vec::new(),
            Some(_) => texts(&found, "warnings")?,
        },
    };
    if let Some(workspace) = &ctx.workspace {
        merge_workspace(ctx, workspace, &mut detection)?;
    }
    replace_skills(ctx, &mut detection)?;
    Ok(detection)
}
