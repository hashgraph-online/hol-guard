use super::*;

/// `_go_mod_replace_map` (:3630-3645).
// supply_chain_package_eval.py:3630-3645
#[allow(dead_code)]
pub(super) fn go_mod_replace_map(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
) -> BTreeMap<String, String> {
    let mut replacements: BTreeMap<String, String> = BTreeMap::new();
    let mut in_replace_block = false;
    for raw_line in text.lines() {
        let mut line = raw_line.trim().to_string();
        if line.starts_with("replace (") {
            in_replace_block = true;
            continue;
        }
        if in_replace_block && line == ")" {
            in_replace_block = false;
            continue;
        }
        if let Some(rest) = line.strip_prefix("replace ") {
            line = rest.trim().to_string();
        } else if !in_replace_block {
            continue;
        }
        if !line.contains("=>") {
            continue;
        }
        let (original, _sep, replacement) = py_partition(&line, "=>");
        let normalized_original = original.split_whitespace().next().unwrap_or("").to_string();
        let normalized_replacement = replacement
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();
        if !normalized_original.is_empty() && !normalized_replacement.is_empty() {
            replacements.insert(
                normalize_package_name(deps, "go", &normalized_original),
                normalized_replacement,
            );
        }
    }
    replacements
}

/// `_go_replace_result` (:3598-3628).
// supply_chain_package_eval.py:3598-3628
#[allow(dead_code)]
pub(super) fn go_replace_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let ws = workspace_dir?;
    if optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string()) != "go" {
        return None;
    }
    let manifest_paths = match artifact.metadata.get("manifest_paths") {
        Some(Value::Array(list)) => list.clone(),
        _ => return None,
    };
    let mut go_mod_relative_path: Option<String> = None;
    for path in &manifest_paths {
        let rel = match path.as_str() {
            Some(s) => s,
            None => continue,
        };
        if Path::new(rel).file_name().and_then(|n| n.to_str()) != Some("go.mod") {
            continue;
        }
        if let Some(resolved) = resolve_path_within_workspace(ws, rel) {
            if resolved.exists() {
                go_mod_relative_path = Some(rel.to_string());
                break;
            }
        }
    }
    let go_mod_relative_path = go_mod_relative_path?;
    let go_mod_text = deps.workspace_io.read_text(ws, &go_mod_relative_path)?;
    let replacements = go_mod_replace_map(deps, &go_mod_text);
    for candidate in target_candidate_names(deps, target) {
        let Some(replacement) = replacements.get(&candidate) else {
            continue;
        };
        if ["file:", "./", "../", "/", "~", ".\\", "..\\"]
            .iter()
            .any(|prefix| replacement.starts_with(prefix))
        {
            return Some(heuristic_package_result(
                target,
                "ask",
                "go_replace_local_source",
                "Go replace directive reroutes this module to a local path.",
                "medium",
            ));
        }
        if exact_version(replacement).is_none() {
            return Some(heuristic_package_result(
                target,
                "ask",
                "go_replace_mutable_source",
                "Go replace directive reroutes this module away from proxy-pinned version resolution.",
                "medium",
            ));
        }
    }
    None
}

/// `_target_requires_npm_source_review` (:3691-3693).
// supply_chain_package_eval.py:3691-3693
#[allow(dead_code)]
pub(super) fn target_requires_npm_source_review(target: &Map<String, Value>) -> bool {
    (optional_string(target.get("ecosystem"))
        .unwrap_or_default()
        .to_lowercase()
        == "npm")
        && ["git", "invalid", "local", "url"].contains(
            &optional_string(target.get("source_kind"))
                .unwrap_or_default()
                .as_str(),
        )
}
