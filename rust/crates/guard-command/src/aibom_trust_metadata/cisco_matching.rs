use super::*;

/// `_cisco_trust_layers_for_artifact(artifact, *, item_kind, captured_at, cisco_runs, workspace_dir)`
pub(super) fn _cisco_trust_layers_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    captured_at: &str,
    cisco_runs: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    let mut layers = Vec::new();
    for run in cisco_runs {
        let source = a_str(run, "source");
        if source == Some("cisco-skill-scanner")
            && (item_kind == "skill" || item_kind == "plugin")
            && _matches_skill_cisco_run(artifact, item_kind, run, workspace_dir)
        {
            layers.push(_cisco_trust_layer(
                run,
                deps,
                captured_at,
                "cisco_skill_scanner",
                "cisco.skill.score",
                "Cisco Skill Scanner",
            ));
        }
        if source == Some("cisco-mcp-scanner")
            && (item_kind == "mcp_server" || item_kind == "mcp_tool")
            && _matches_mcp_cisco_run(artifact, run)
        {
            layers.push(_cisco_trust_layer(
                run,
                deps,
                captured_at,
                "cisco_mcp_scanner",
                "cisco.mcp.score",
                "Cisco MCP Scanner",
            ));
        }
    }
    layers
}

/// `_matches_skill_cisco_run(artifact, *, item_kind, run, workspace_dir)`
pub(super) fn _matches_skill_cisco_run(
    artifact: &Map<String, Value>,
    item_kind: &str,
    run: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> bool {
    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir);
    let run_target = match _cisco_run_target_path(run) {
        Some(t) => t,
        None => return false,
    };
    match trust_root {
        None => false,
        Some(trust_root) => _paths_related(&trust_root, &run_target),
    }
}

/// `_matches_mcp_cisco_run(artifact, *, run)`
pub(super) fn _matches_mcp_cisco_run(
    artifact: &Map<String, Value>,
    run: &Map<String, Value>,
) -> bool {
    let run_config_path = _cisco_run_config_path(run);
    let config_path = match a_str(artifact, "config_path") {
        Some(c) if !c.trim().is_empty() => c,
        _ => return false,
    };
    let path = PathBuf::from(config_path);
    if let Some(run_config_path) = run_config_path {
        return _paths_related(&path, &run_config_path);
    }
    let run_target = match _cisco_run_target_path(run) {
        Some(t) => t,
        None => return false,
    };
    if path.is_file()
        && (_paths_related(&path, &run_target)
            || _paths_related(
                &path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| path.clone()),
                &run_target,
            ))
    {
        return true;
    }
    _paths_related(&path, &run_target)
}

/// `_paths_related(left, right)`
pub(super) fn _paths_related(left: &Path, right: &Path) -> bool {
    let left_resolved = left.canonicalize().unwrap_or_else(|_| left.to_path_buf());
    let right_resolved = right.canonicalize().unwrap_or_else(|_| right.to_path_buf());
    if left_resolved == right_resolved {
        return true;
    }
    left_resolved.starts_with(&right_resolved) || right_resolved.starts_with(&left_resolved)
}

/// `_cisco_run_config_path(run)`
pub(super) fn _cisco_run_config_path(run: &Map<String, Value>) -> Option<PathBuf> {
    let metadata = run_meta(run)?;
    let config_path = metadata.get("_configPath").and_then(Value::as_str)?;
    if config_path.trim().is_empty() {
        return None;
    }
    Some(PathBuf::from(config_path))
}

/// `_cisco_run_target_path(run)`
pub(super) fn _cisco_run_target_path(run: &Map<String, Value>) -> Option<PathBuf> {
    let metadata = run_meta(run)?;
    for key in ["_targetPath", "target"] {
        if let Some(target) = metadata.get(key).and_then(Value::as_str) {
            if !target.trim().is_empty() && target != "missing" {
                return Some(PathBuf::from(target));
            }
        }
    }
    None
}
