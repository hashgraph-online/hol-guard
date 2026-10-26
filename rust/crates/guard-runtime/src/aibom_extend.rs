//! Detection extension plans: how workspace AIBOM artifacts merge into an
//! existing harness detection, and how Codex skill inventory is rebuilt with
//! enablement rules. The caller applies the plan to its own artifact objects
//! so runtime-private metadata never crosses the transport.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde_json::{json, Map, Value};

use super::aibom_discovery::shared_workspace_artifacts;
use super::aibom_paths::{py_join, resolve};
use super::aibom_skill_rules::{load_rules, resolve_enabled};
use super::aibom_skills::{
    scope_skill_artifacts, SkillSource, HOME_SKILL_ROOTS, WORKSPACE_SKILL_ROOTS,
};

pub(crate) struct Existing {
    pub(crate) artifact_id: String,
    pub(crate) artifact_type: String,
    pub(crate) harness: String,
    pub(crate) config_path: Option<String>,
}

fn field<'a>(artifact: &'a Value, key: &str) -> Option<&'a str> {
    artifact.get(key).and_then(Value::as_str)
}

fn resolved(path: &str) -> Option<std::path::PathBuf> {
    resolve(Path::new(path)).ok()
}

fn is_workspace_root_claude_md(artifact: &Value, workspace: &Path) -> bool {
    let role = artifact
        .get("metadata")
        .and_then(|metadata| metadata.get("instructionRole"))
        .and_then(Value::as_str);
    if role != Some("claude_md") {
        return false;
    }
    let Some(config_path) = field(artifact, "config_path") else {
        return false;
    };
    match (
        resolved(config_path),
        resolve(&py_join(workspace, "CLAUDE.md")),
    ) {
        (Some(path), Ok(expected)) => path == expected,
        _ => false,
    }
}

/// Only Claude rules markdown may be replaced by a workspace-root `CLAUDE.md`
/// when ids collide.
fn is_claude_rules_replacement_target(existing: &Existing, workspace: &Path) -> bool {
    if existing.artifact_type != "instruction" || existing.harness != "claude-code" {
        return false;
    }
    let Some(config_path) = &existing.config_path else {
        return false;
    };
    match (
        resolved(config_path),
        resolve(&py_join(workspace, ".claude/rules")),
    ) {
        (Some(path), Ok(rules_dir)) => path.starts_with(rules_dir),
        _ => false,
    }
}

/// `extend_detection_with_workspace_aibom`, as a plan over the caller's
/// existing artifacts (by position).
pub(crate) fn workspace_plan(
    harness: &str,
    workspace: &Path,
    existing: Vec<Existing>,
    skills: &SkillSource,
) -> Result<Value, &'static str> {
    let extra = shared_workspace_artifacts(harness, workspace, skills)?;
    let original = existing.len();
    let mut ids: HashMap<String, usize> = HashMap::new();
    for (index, entry) in existing.iter().enumerate() {
        ids.insert(entry.artifact_id.clone(), index);
    }
    let mut entries = existing;
    let mut added: Vec<Option<Value>> = Vec::new();
    let mut replaced: BTreeMap<usize, Value> = BTreeMap::new();
    let mut found_paths: Vec<String> = Vec::new();
    let extra_count = extra.len();
    for artifact in extra {
        let artifact_id = field(&artifact, "artifact_id")
            .unwrap_or_default()
            .to_owned();
        let config_path = field(&artifact, "config_path").map(str::to_owned);
        if let Some(&index) = ids.get(&artifact_id) {
            if is_workspace_root_claude_md(&artifact, workspace)
                && is_claude_rules_replacement_target(&entries[index], workspace)
            {
                entries[index] = Existing {
                    artifact_id: artifact_id.clone(),
                    artifact_type: field(&artifact, "artifact_type")
                        .unwrap_or_default()
                        .to_owned(),
                    harness: field(&artifact, "harness").unwrap_or_default().to_owned(),
                    config_path: config_path.clone(),
                };
                found_paths.extend(config_path);
                if index < original {
                    replaced.insert(index, artifact);
                } else {
                    added[index - original] = Some(artifact);
                }
            }
            continue;
        }
        ids.insert(artifact_id.clone(), entries.len());
        entries.push(Existing {
            artifact_id,
            artifact_type: field(&artifact, "artifact_type")
                .unwrap_or_default()
                .to_owned(),
            harness: field(&artifact, "harness").unwrap_or_default().to_owned(),
            config_path: config_path.clone(),
        });
        found_paths.extend(config_path);
        added.push(Some(artifact));
    }
    let replacements: Vec<Value> = replaced
        .into_iter()
        .map(|(index, artifact)| json!({"index": index, "artifact": artifact}))
        .collect();
    Ok(json!({
        "extra_count": extra_count,
        "replacements": replacements,
        "appended": added.into_iter().flatten().collect::<Vec<_>>(),
        "found_paths": found_paths,
    }))
}

/// Finished skill artifacts per scope when the native walk cannot serve it.
#[derive(Default)]
pub(crate) struct CodexSkillSources {
    pub(crate) project: SkillSource,
    pub(crate) global: SkillSource,
}

/// `discover_codex_skill_artifacts`.
pub(crate) fn codex_skill_artifacts(
    harness: &str,
    home_dir: &Path,
    workspace: Option<&Path>,
    sources: &CodexSkillSources,
    user_home: Option<&str>,
) -> Result<Vec<Value>, &'static str> {
    let mut artifacts = Vec::new();
    if let Some(workspace) = workspace {
        artifacts.extend(scope_skill_artifacts(
            harness,
            workspace,
            &WORKSPACE_SKILL_ROOTS,
            "project",
            &sources.project,
        )?);
    }
    artifacts.extend(scope_skill_artifacts(
        harness,
        home_dir,
        &HOME_SKILL_ROOTS,
        "global",
        &sources.global,
    )?);
    let rules = load_rules(home_dir, workspace, user_home)?;
    if rules.is_empty() {
        return Ok(artifacts);
    }
    for artifact in &mut artifacts {
        if field(artifact, "artifact_type") != Some("skill") {
            continue;
        }
        let config_path = field(artifact, "config_path")
            .unwrap_or_default()
            .to_owned();
        let name = field(artifact, "name").unwrap_or_default().to_owned();
        let enabled = resolve_enabled(&config_path, &name, &rules, home_dir, user_home)?;
        if let Some(Value::Object(metadata)) = artifact.get_mut("metadata") {
            metadata.insert("enabled".to_owned(), Value::Bool(enabled));
        } else {
            let mut metadata = Map::new();
            metadata.insert("enabled".to_owned(), Value::Bool(enabled));
            artifact["metadata"] = Value::Object(metadata);
        }
    }
    Ok(artifacts)
}
