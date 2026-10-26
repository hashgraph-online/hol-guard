//! `runner_authority` kinds for AIBOM discovery (`aibom_detection.py`):
//! shared workspace artifacts, the detection merge plan, Codex skill
//! inventory with enablement rules, and MCP server metadata digests. Paths
//! arrive absolute; every refusal is a stable code and never a partial list.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::aibom_discovery::{shared_workspace_artifacts, ERR_ROOT};
use super::aibom_extend::{codex_skill_artifacts, workspace_plan, CodexSkillSources, Existing};
use super::aibom_mcp_metadata::{enrich, McpMetadataInput, ERR_METADATA};
use super::aibom_paths::py_path;
use super::aibom_skills::SkillSource;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn absolute(value: Option<&Value>) -> Result<PathBuf, &'static str> {
    let text = value.and_then(Value::as_str).ok_or(ERR_ROOT)?;
    if text.is_empty()
        || text.contains('\0')
        || !text.starts_with('/') && !is_windows_absolute(text)
    {
        return Err(ERR_ROOT);
    }
    Ok(py_path(text))
}

fn is_windows_absolute(text: &str) -> bool {
    cfg!(windows) && Path::new(text).is_absolute()
}

fn optional_absolute(value: Option<&Value>) -> Result<Option<PathBuf>, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(None),
        other => absolute(other).map(Some),
    }
}

fn string(value: Option<&Value>) -> Result<&str, &'static str> {
    value.and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn skills(value: Option<&Value>) -> Result<SkillSource, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) if items.iter().all(Value::is_object) => Ok(Some(items.clone())),
        Some(_) => Err(ERR_INVALID),
    }
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(ERR_INVALID),
    }
}

fn string_list(value: Option<&Value>) -> Result<Vec<String>, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(ERR_INVALID))
            .collect(),
        Some(_) => Err(ERR_INVALID),
    }
}

pub(crate) fn workspace_artifacts(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let harness = string(args.get("harness"))?;
    let workspace = absolute(args.get("workspace_dir"))?;
    let artifacts = shared_workspace_artifacts(harness, &workspace, &skills(args.get("skills"))?)?;
    Ok(json!({ "artifacts": artifacts }))
}

pub(crate) fn workspace_merge_plan(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let harness = string(args.get("harness"))?;
    let workspace = absolute(args.get("workspace_dir"))?;
    let existing = args
        .get("existing")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|entry| {
            let entry = args_object(entry)?;
            Ok(Existing {
                artifact_id: string(entry.get("artifact_id"))?.to_owned(),
                artifact_type: string(entry.get("artifact_type"))?.to_owned(),
                harness: string(entry.get("harness"))?.to_owned(),
                config_path: optional_string(entry.get("config_path"))?,
            })
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    workspace_plan(harness, &workspace, existing, &skills(args.get("skills"))?)
}

pub(crate) fn codex_skills(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let harness = string(args.get("harness"))?;
    let home = absolute(args.get("home_dir"))?;
    let workspace = optional_absolute(args.get("workspace_dir"))?;
    let sources = CodexSkillSources {
        project: skills(args.get("project_skills"))?,
        global: skills(args.get("global_skills"))?,
    };
    let user_home = optional_string(args.get("user_home"))?;
    let artifacts = codex_skill_artifacts(
        harness,
        &home,
        workspace.as_deref(),
        &sources,
        user_home.as_deref(),
    )?;
    Ok(json!({ "artifacts": artifacts }))
}

pub(crate) fn mcp_metadata(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let input = McpMetadataInput {
        command: optional_string(args.get("command"))?,
        args: string_list(args.get("args"))?,
        url: optional_string(args.get("url"))?,
        transport: optional_string(args.get("transport"))?,
        env_keys: string_list(args.get("env_keys"))?,
        headers_keys: string_list(args.get("headers_keys"))?,
        env: args.get("env").cloned().unwrap_or(Value::Null),
        headers: args.get("headers").cloned().unwrap_or(Value::Null),
        env_values_hash: optional_string(args.get("env_values_hash"))?,
        header_values_hash: optional_string(args.get("header_values_hash"))?,
        label: string(args.get("label"))?.to_owned(),
    };
    enrich(&input).map_err(|_| ERR_METADATA)
}
