use super::*;

/// `_local_package_manifest_path` (:3354-3372).
// supply_chain_package_eval.py:3354-3372
#[allow(dead_code)]
pub(super) fn local_package_manifest_path(
    target: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Option<PathBuf> {
    let ws = workspace_dir?;
    let mut raw_spec = optional_string(target.get("raw_spec"));
    let source_url = optional_string(target.get("source_url"));
    if let Some(url) = &source_url {
        if url.starts_with("file:") {
            raw_spec = Some(py_partition(url, "file:").2.to_string());
        }
    }
    let source_spec = npm_source_spec(raw_spec.as_deref(), "npm");
    if raw_spec.is_none()
        || (source_spec.is_some()
            && source_spec.as_ref().unwrap().source_kind
                != crate::npm_source_spec::SourceKind::Local)
    {
        return None;
    }
    let mut raw = raw_spec.unwrap();
    if raw.starts_with("file:") {
        raw = py_partition(&raw, "file:").2.to_string();
    }
    let candidate_path = PathBuf::from(&raw);
    let disk_path = if candidate_path.is_absolute() {
        candidate_path
    } else {
        ws.join(candidate_path)
    };
    if disk_path.is_dir() {
        let manifest_path = disk_path.join("package.json");
        return if manifest_path.exists() {
            Some(manifest_path)
        } else {
            None
        };
    }
    if disk_path.file_name().and_then(|n| n.to_str()) == Some("package.json") && disk_path.exists()
    {
        return Some(disk_path);
    }
    None
}

/// `_local_package_manifest_result` (:3303-3351).
// supply_chain_package_eval.py:3303-3351
#[allow(dead_code)]
pub(super) fn local_package_manifest_result(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let manifest_path = local_package_manifest_path(target, workspace_dir)?;
    let manifest_text = std::fs::read_to_string(&manifest_path).ok()?;
    let detected = match deps.risk.detect_supply_chain_risk(&manifest_text, None) {
        Ok(signals) => signals,
        Err(_) => {
            return Some(heuristic_package_result(
                target,
                "block",
                "supply_chain_risk_evaluation_failed",
                "Guard could not complete the package supply-chain risk evaluation.",
                "high",
            ));
        }
    };
    let signals: Vec<Map<String, Value>> = detected
        .into_iter()
        .filter(|s| {
            let sid = optional_string(s.get("signal_id")).unwrap_or_default();
            sid.starts_with("supply-chain.postinstall") || sid.ends_with("install-lifecycle-exec")
        })
        .collect();
    if signals.is_empty() {
        return None;
    }
    let mut manifest_target = target.clone();
    if let Some(manifest_name) = manifest_package_name(&manifest_text) {
        let eco = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
        let (namespace, name) = split_namespace_name(&manifest_name, &eco);
        manifest_target.insert(
            "namespace".to_string(),
            namespace.map(Value::String).unwrap_or(Value::Null),
        );
        manifest_target.insert("name".to_string(), Value::String(name));
    }
    if artifact_has_flag(artifact, "--ignore-scripts") {
        return Some(heuristic_package_result(
            &manifest_target,
            "allow",
            "ignore_scripts_applied",
            "`--ignore-scripts` disables lifecycle hooks for this local package install.",
            "low",
        ));
    }
    let strongest = signals
        .iter()
        .rev()
        .max_by_key(|s| {
            severity_rank_value(
                optional_string(s.get("severity"))
                    .as_deref()
                    .unwrap_or("unknown"),
            )
        })
        .expect("nonempty lifecycle risk signals");
    Some(heuristic_package_result(
        &manifest_target,
        "block",
        "install_script_risk",
        &optional_string(strongest.get("plain_reason")).unwrap_or_default(),
        &optional_string(strongest.get("severity")).unwrap_or_else(|| "medium".to_string()),
    ))
}

/// `_local_python_build_result` (:3375-3417).
// supply_chain_package_eval.py:3375-3417
#[allow(dead_code)]
pub(super) fn local_python_build_result(
    target: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Option<Map<String, Value>> {
    let ws = workspace_dir?;
    if optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string()) != "pypi" {
        return None;
    }
    let project_path = local_python_project_path(target, ws)?;
    let setup_py_path = project_path.join("setup.py");
    if setup_py_path.exists() {
        let setup_py_text = std::fs::read_to_string(&setup_py_path).unwrap_or_default();
        if python_setup_script_looks_suspicious(&setup_py_text) {
            return Some(heuristic_package_result(
                target,
                "block",
                "setup_py_exec_risk",
                "Local setup.py executes commands or network behavior during packaging.",
                "high",
            ));
        }
    }
    let pyproject_path = project_path.join("pyproject.toml");
    if pyproject_path.exists() {
        let pyproject_text = std::fs::read_to_string(&pyproject_path).unwrap_or_default();
        if pyproject_text.contains("[build-system]") && pyproject_text.contains("build-backend") {
            if python_setup_script_looks_suspicious(&pyproject_text) {
                return Some(heuristic_package_result(
                    target,
                    "block",
                    "build_backend_exec_risk",
                    "Local pyproject build backend references execution or network bootstrap behavior.",
                    "high",
                ));
            }
            return Some(heuristic_package_result(
                target,
                "ask",
                "local_build_backend_risk",
                "Editable local Python installs can invoke pyproject build backend hooks from this workspace.",
                "medium",
            ));
        }
    }
    None
}
