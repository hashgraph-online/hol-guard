use super::*;

/// `_package_from_cloud_result` (:2984-3001).
// supply_chain_package_eval.py:2984-3001
#[allow(dead_code)]
pub(super) fn package_from_cloud_result(item: &Map<String, Value>) -> Map<String, Value> {
    let dependency_path = optional_string(item.get("dependencyPath"));
    let direct = match item.get("direct").and_then(Value::as_bool) {
        Some(b) => b,
        None => dependency_path.is_none(),
    };
    let decision_raw =
        optional_string(item.get("decision")).unwrap_or_else(|| "monitor".to_string());
    let mut result = Map::new();
    result.insert(
        "decision".to_string(),
        Value::String(normalize_bundle_action(&decision_raw)),
    );
    result.insert(
        "ecosystem".to_string(),
        Value::String(optional_string(item.get("ecosystem")).unwrap_or_else(|| "npm".to_string())),
    );
    result.insert(
        "name".to_string(),
        Value::String(optional_string(item.get("name")).unwrap_or_else(|| "unknown".to_string())),
    );
    result.insert(
        "namespace".to_string(),
        optional_string(item.get("namespace"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "requestedVersion".to_string(),
        optional_string(item.get("requestedVersion"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "resolvedVersion".to_string(),
        optional_string(item.get("resolvedVersion"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "recommendedFixVersion".to_string(),
        optional_string(item.get("recommendedFixVersion"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    result.insert(
        "riskScore".to_string(),
        item.get("riskScore").cloned().unwrap_or(Value::Null),
    );
    result.insert("direct".to_string(), Value::Bool(direct));
    result.insert(
        "dependencyPath".to_string(),
        dependency_path.map(Value::String).unwrap_or(Value::Null),
    );
    result.insert(
        "reasons".to_string(),
        Value::Array(
            dict_items(item.get("reasons"))
                .into_iter()
                .map(Value::Object)
                .collect(),
        ),
    );
    result
}

/// `_ALTERNATE_PACKAGE_INDEX_FLAGS` (:3032-3043).
#[allow(dead_code)]
pub(super) static ALTERNATE_PACKAGE_INDEX_FLAGS: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| {
        [
            "--index-url",
            "--extra-index-url",
            "--index",
            "--default-index",
            "--no-index",
            "-i",
            "--find-links",
            "-f",
            "--pip-args",
        ]
        .into_iter()
        .collect()
    });

/// `_PACKAGE_SOURCE_ENV_NAMES` (:3044-3056).
#[allow(dead_code)]
pub(super) static PACKAGE_SOURCE_ENV_NAMES: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| {
        [
            "PIP_EXTRA_INDEX_URL",
            "PIP_FIND_LINKS",
            "PIP_INDEX_URL",
            "PIP_NO_INDEX",
            "UV_DEFAULT_INDEX",
            "UV_EXTRA_INDEX_URL",
            "UV_FIND_LINKS",
            "UV_INDEX",
            "UV_INDEX_URL",
            "UV_NO_INDEX",
        ]
        .into_iter()
        .collect()
    });

/// `_command_uses_alternate_package_index` (:3059-3067).
// supply_chain_package_eval.py:3059-3067
#[allow(dead_code)]
pub(super) fn command_uses_alternate_package_index(artifact: &GuardArtifact) -> bool {
    let flags: BTreeSet<String> = string_tuple(artifact.metadata.get("flags"))
        .into_iter()
        .collect();
    if flags
        .iter()
        .any(|f| ALTERNATE_PACKAGE_INDEX_FLAGS.contains(f.as_str()))
    {
        return true;
    }
    let redacted = optional_string(artifact.metadata.get("redacted_command")).unwrap_or_default();
    let tokens = match crate::command_launcher_floors::shlex_split(&redacted) {
        Ok(t) => t,
        Err(_) => return true,
    };
    if tokens.iter().any(|token| {
        PACKAGE_SOURCE_ENV_NAMES.contains(py_partition(token, "=").0.to_uppercase().as_str())
    }) {
        return true;
    }
    PACKAGE_SOURCE_ENV_NAMES.iter().any(|name| {
        std::env::var(name)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    })
}

/// `_bun_lockfile_binary_fallback_packages` (:3254-3300).
// supply_chain_package_eval.py:3254-3300
#[allow(dead_code)]
pub(super) fn bun_lockfile_binary_fallback_packages(
    targets: &[Map<String, Value>],
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    fail_closed_unidentified: bool,
) -> Vec<Map<String, Value>> {
    let Some(ws) = workspace_dir else {
        return Vec::new();
    };
    let Some(Value::Array(lockfile_paths)) = artifact.metadata.get("lockfile_paths").cloned()
    else {
        return Vec::new();
    };
    let mut bun_lock_found = false;
    for relative_path in &lockfile_paths {
        let rel = match relative_path.as_str() {
            Some(s) => s,
            None => continue,
        };
        if Path::new(rel).file_name().and_then(|n| n.to_str()) != Some("bun.lockb") {
            continue;
        }
        if let Some(resolved) = resolve_path_within_workspace(ws, rel) {
            if resolved.exists() {
                bun_lock_found = true;
                break;
            }
        }
    }
    if !bun_lock_found {
        return Vec::new();
    }
    let message = "Guard could not verify package identity from Bun's binary lockfile (bun.lockb).";
    if !targets.is_empty() {
        return targets
            .iter()
            .map(|target| {
                let eco =
                    optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
                heuristic_package_result(
                    target,
                    &unidentified_package_decision(&eco, fail_closed_unidentified, false),
                    "bun_lockfile_binary_fallback",
                    &format!("{message} Approval is required before install."),
                    if fail_closed_unidentified {
                        "high"
                    } else {
                        "medium"
                    },
                )
            })
            .collect();
    }
    let decision = unidentified_package_decision("npm", fail_closed_unidentified, false);
    let mut workspace_target = Map::new();
    workspace_target.insert("ecosystem".to_string(), Value::String("npm".to_string()));
    workspace_target.insert("name".to_string(), Value::String("workspace".to_string()));
    workspace_target.insert("namespace".to_string(), Value::Null);
    workspace_target.insert(
        "package_manager".to_string(),
        Value::String("bun".to_string()),
    );
    vec![heuristic_package_result(
        &workspace_target,
        &decision,
        "bun_lockfile_binary_fallback",
        &format!("{message} Approval is required before install."),
        if decision == "block" {
            "high"
        } else {
            "medium"
        },
    )]
}
