use super::*;

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
