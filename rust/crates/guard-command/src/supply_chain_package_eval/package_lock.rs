use super::*;

/// `_package_lock_entries` (:4057-4082) — `node_modules/<path>` → `(dep_path,
/// pkg_name, version, direct)` entries from a package-lock.json text.
// supply_chain_package_eval.py:4057-4082
#[allow(dead_code)]
pub(super) fn package_lock_entries(
    text: &str,
    deadline: Option<f64>,
) -> Vec<(String, String, String, bool)> {
    let payload: Value = serde_json::from_str(text).unwrap_or_else(|_| json!({}));
    let mut entries: Vec<(String, String, String, bool)> = Vec::new();
    if let Some(Value::Object(packages)) = payload.get("packages") {
        for (package_path, value) in packages {
            if let Some(dl) = deadline {
                if monotonic_seconds() > dl {
                    break;
                }
            }
            if !package_path.starts_with("node_modules/") {
                continue;
            }
            let version = value.get("version").and_then(Value::as_str);
            let Some(version) = version else { continue };
            let dependency_path = package_path.trim_start_matches("node_modules/").to_string();
            let package_name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let direct = !dependency_path.contains("/node_modules/");
            entries.push((dependency_path, package_name, version.to_string(), direct));
        }
    }
    entries
}

/// `_walk_package_lock_entries` (:4085-4095) — alias over `package_lock_entries`.
// supply_chain_package_eval.py:4085-4095
#[allow(dead_code)]
pub(super) fn walk_package_lock_entries(
    text: &str,
    deadline: Option<f64>,
) -> Vec<(String, String, String, bool)> {
    package_lock_entries(text, deadline)
}

/// `_package_lock_candidate_names` (:4098-4106) — candidate dependency paths +
/// normalized name for matching a target against package-lock entries.
// supply_chain_package_eval.py:4098-4106
#[allow(dead_code)]
pub(super) fn package_lock_candidate_names(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> (BTreeSet<String>, String) {
    let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_default();
    let mut candidates: BTreeSet<String> = BTreeSet::new();
    for c in target_candidate_names(deps, target) {
        candidates.insert(c.clone());
        candidates.insert(format!("node_modules/{c}"));
    }
    (candidates, normalized_name)
}

/// `_package_lock_target_versions_from_entries` (:4038-4054) — resolve each
/// target's version from package-lock entries.
// supply_chain_package_eval.py:4038-4054
#[allow(dead_code)]
pub(super) fn package_lock_target_versions_from_entries(
    deps: &SupplyChainEvalDeps<'_>,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for target in targets {
        let Some(target_key) = lockfile_target_key(target) else {
            continue;
        };
        let (candidate_paths, normalized_name) = package_lock_candidate_names(deps, target);
        for entry in &parse_result.entries {
            if !entry.direct {
                continue;
            }
            if candidate_paths.contains(&entry.dependency_path)
                || entry.package_name == normalized_name
            {
                versions.insert(target_key.clone(), entry.version.clone());
                break;
            }
        }
    }
    versions
}

/// `_package_lock_target_versions` (:4019-4035) — package-lock.json target
/// versions via the parsed result.
// supply_chain_package_eval.py:4019-4035
#[allow(dead_code)]
pub(super) fn package_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    package_lock_target_versions_from_entries(deps, parse_result, targets)
}
