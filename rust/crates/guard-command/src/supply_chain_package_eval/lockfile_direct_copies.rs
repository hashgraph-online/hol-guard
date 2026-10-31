//! Which copy of a direct dependency a lockfile resolves it to, when the
//! lockfile lists that package at several versions.

use super::manifest_dependencies::{
    cargo_lock_target_versions, composer_lock_target_versions, gemfile_lock_target_versions,
};
use super::package_lock::package_lock_target_versions_from_entries;
use super::pnpm_lock::pnpm_lock_target_versions;
use super::python_lock::{
    pipfile_lock_target_versions, poetry_lock_target_versions, uv_lock_target_versions,
};
use super::yarn_bun_lock::{bun_lock_target_versions, yarn_lock_target_versions};
use super::*;

/// The version one lockfile resolves each target to, keyed by
/// `lockfile_target_key`.
pub(super) fn lockfile_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    name: &str,
    text: &str,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
    python_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    match name {
        "package-lock.json" => {
            package_lock_target_versions_from_entries(deps, parse_result, targets)
        }
        "pnpm-lock.yaml" => pnpm_lock_target_versions(deps, text, targets),
        "yarn.lock" => yarn_lock_target_versions(text, targets),
        "bun.lock" => bun_lock_target_versions(deps, parse_result, targets),
        "Cargo.lock" => cargo_lock_target_versions(deps, text, targets),
        "composer.lock" => composer_lock_target_versions(deps, text, targets),
        "Gemfile.lock" => gemfile_lock_target_versions(deps, text, targets),
        "poetry.lock" => poetry_lock_target_versions(deps, text, targets, python_names),
        "uv.lock" => uv_lock_target_versions(deps, text, targets, python_names),
        "Pipfile.lock" => pipfile_lock_target_versions(deps, text, targets, python_names),
        _ => BTreeMap::new(),
    }
}

/// The versions of each direct target's names that are the direct copies in
/// one lockfile: the version the target names, or the one the lockfile
/// resolves it to. A name the lockfile lists at none of them is absent.
pub(super) fn direct_copy_versions(
    deps: &SupplyChainEvalDeps<'_>,
    targets: &[Map<String, Value>],
    resolved: &BTreeMap<String, String>,
    listed: &HashMap<&str, HashSet<&str>>,
) -> HashMap<String, HashSet<String>> {
    let mut direct: HashMap<String, HashSet<String>> = HashMap::new();
    for target in targets {
        let versions: Vec<String> = [
            optional_string(target.get("version")),
            optional_string(target.get("range")).and_then(|range| exact_version(&range)),
            lockfile_target_key(target).and_then(|key| resolved.get(&key).cloned()),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut names = target_candidate_names(deps, target);
        names.push(optional_string(target.get("normalized_name")).unwrap_or_default());
        for name in names {
            let Some(copies) = listed.get(name.as_str()) else {
                continue;
            };
            for version in &versions {
                if copies.contains(version.as_str()) {
                    direct
                        .entry(name.clone())
                        .or_default()
                        .insert(version.clone());
                }
            }
        }
    }
    direct
}
